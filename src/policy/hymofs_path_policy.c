/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - path redirect, hide-policy, and allowlist decision logic.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "hymofs_runtime.h"
#include "hymofs_store.h"
#include "hymofs_path_policy.h"
/* ======================================================================
 * Part 11: Core Logic - Privileged Check / Allowlist
 * ====================================================================== */

bool hymo_is_privileged_process(void)
{
	pid_t pid = task_tgid_vnr(current);

	if (unlikely(uid_eq(current_uid(), GLOBAL_ROOT_UID)))
		return true;
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return true;
	return false;
}

static bool hymo_uid_in_allowlist(uid_t uid)
{
	void *p;

	if (!READ_ONCE(hymo_allowlist_loaded))
		return false;
	rcu_read_lock();
	p = xa_load(&hymo_allow_uids_xa, uid);
	rcu_read_unlock();
	return p != NULL;
}

/*
 * Mirror KernelSU's isolated-process uid bucket so HymoFS hide/spoof rules
 * stay aligned with kernel_umount. Otherwise an app's isolated/app-zygote
 * helper process can end up in the "modules already detached, but fake view
 * not applied" gap that detectors look for during startup preload.
 */
#define HYMO_KSU_PER_USER_RANGE      100000
#define HYMO_KSU_FIRST_ISOLATED_UID   99000
#define HYMO_KSU_LAST_ISOLATED_UID    99999

static inline bool hymo_uid_is_isolated(uid_t uid)
{
	uid_t appid = uid % HYMO_KSU_PER_USER_RANGE;

	return appid >= HYMO_KSU_FIRST_ISOLATED_UID &&
	       appid <= HYMO_KSU_LAST_ISOLATED_UID;
}

bool hymo_should_apply_hide_rules(void)
{
	uid_t uid = __kuid_val(current_uid());

	/* uid 0 (root) never sees spoofed view */
	if (unlikely(uid == 0))
		return false;

	/*
	 * Primary: semantically-correct kernel symbol "should this uid be
	 * module-unmounted", which matches our hide intent exactly.
	 */
	if (hymo_ksu_uid_should_umount_ptr)
		return hymo_ksu_uid_should_umount_ptr(uid) ||
		       hymo_uid_is_isolated(uid);

	/*
	 * Fallback: cached allowlist (populated from ksu_get_allow_list(allow=false)
	 * or from parsing /data/adb/ksu/.allowlist). Presence in this set means
	 * the uid is explicitly marked non-su in the KSU allowlist — treated as
	 * "should apply hide". If we never loaded the list, conservatively do
	 * NOT hide (avoid wrongly hiding root flow).
	 */
	if (hymo_uid_is_isolated(uid))
		return true;
	if (!hymo_allowlist_loaded)
		return false;
	return hymo_uid_in_allowlist(uid);
}

static void hymo_add_allow_uid(uid_t uid)
{
	xa_store(&hymo_allow_uids_xa, uid, HYMO_UID_ALLOW_MARKER, GFP_KERNEL);
}

/*
 * GKI kernels protect many VFS symbols behind namespaces or don't export
 * them at all. We resolve ALL problematic VFS symbols via kprobe at init
 * time, so the module has zero direct VFS symbol dependencies.
 */
/*
 * Reload the KSU allowlist cache. Tries three paths in order:
 *   1. ksu_uid_should_umount symbol — authoritative, no caching needed.
 *   2. ksu_get_allow_list(allow=false) — explicitly non-su allowlist entries
 *      (= apps marked for module unmount), cached into xarray.
 *   3. Parse /data/adb/ksu/.allowlist on disk with strict version gates.
 * Path 1 shortcuts: hymo_should_apply_hide_rules will call the symbol directly.
 */
HYMO_NOCFI bool hymo_reload_ksu_allowlist(void)
{
	struct file *fp;
	loff_t off = 0;
	u32 magic = 0, version = 0;
	ssize_t ret;
	struct hymo_app_profile profile;
	int count = 0;

	if (!mutex_trylock(&hymo_config_mutex))
		return false;

	/* Resolve symbols lazily (KSU may load after us). */
	if (!hymo_ksu_uid_should_umount_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("ksu_uid_should_umount");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_uid_should_umount_ptr = (hymo_ksu_uid_should_umount_fn)addr;
	}
	if (!hymo_ksu_is_allow_uid_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("__ksu_is_allow_uid_for_current");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
	}
	if (!hymo_ksu_is_allow_uid_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("__ksu_is_allow_uid");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
	}
	if (!hymo_ksu_get_allow_list_ptr && hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name("ksu_get_allow_list");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_get_allow_list_ptr = (hymo_ksu_get_allow_list_fn)addr;
	}

	/* Path 1: primary symbol resolved — no cache needed, gate is real-time. */
	if (hymo_ksu_uid_should_umount_ptr) {
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = true;
		mutex_unlock(&hymo_config_mutex);
		return true;
	}

	/* Path 2: bulk API — cache "non-su allowlist entries" (= umount-marked apps). */
	if (hymo_ksu_get_allow_list_ptr) {
		int *arr = kmalloc(HYMO_ALLOWLIST_UID_MAX * sizeof(int), GFP_KERNEL);

		if (arr) {
			u16 out_len = 0, out_total = 0;
			bool ok = hymo_ksu_get_allow_list_ptr(arr,
							     (u16)HYMO_ALLOWLIST_UID_MAX,
							     &out_len, &out_total, false);

			if (ok) {
				xa_destroy(&hymo_allow_uids_xa);
				hymo_allowlist_loaded = true;
				for (count = 0; count < out_len && count < HYMO_ALLOWLIST_UID_MAX; count++)
					if (arr[count] > 0)
						hymo_add_allow_uid((uid_t)arr[count]);
				if (out_len < out_total)
					hymo_log("allowlist truncated at %u (total %u)\n",
						 out_len, out_total);
				kfree(arr);
				mutex_unlock(&hymo_config_mutex);
				return true;
			}
			kfree(arr);
		}
	}

	/* Path 3: parse /data/adb/ksu/.allowlist directly. */
	if (!hymo_filp_open || !hymo_kernel_read) {
		mutex_unlock(&hymo_config_mutex);
		return false;
	}

	fp = hymo_filp_open(HYMO_KSU_ALLOWLIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		xa_destroy(&hymo_allow_uids_xa);
		hymo_allowlist_loaded = false;
		mutex_unlock(&hymo_config_mutex);
		return false;
	}

	ret = hymo_kernel_read(fp, &magic, sizeof(magic), &off);
	if (ret != sizeof(magic) || magic != HYMO_KSU_ALLOWLIST_MAGIC)
		goto bad;
	ret = hymo_kernel_read(fp, &version, sizeof(version), &off);
	if (ret != sizeof(version) || version != HYMO_KSU_FILE_FORMAT_VERSION) {
		pr_warn("HymoFS: allowlist file version mismatch (got %u, expect %u)\n",
			version, HYMO_KSU_FILE_FORMAT_VERSION);
		goto bad;
	}

	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = true;

	while (hymo_kernel_read(fp, &profile, sizeof(profile), &off) == sizeof(profile)) {
		/* Skip mismatched per-profile versions: layout may differ. */
		if (profile.version != HYMO_KSU_APP_PROFILE_VER)
			continue;
		/* Match upstream ksu_uid_should_umount semantic: marked non-su and
		 * either use_default (assumed true — user explicit add) or umount_modules. */
		if (!profile.allow_su && profile.curr_uid > 0 &&
		    (profile.nrp_config.use_default ||
		     profile.nrp_config.profile.umount_modules)) {
			hymo_add_allow_uid((uid_t)profile.curr_uid);
			if (++count >= HYMO_ALLOWLIST_UID_MAX) {
				hymo_log("allowlist truncated at %d\n", count);
				break;
			}
		}
	}

	if (hymo_filp_close)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	mutex_unlock(&hymo_config_mutex);
	return true;

bad:
	pr_warn("HymoFS: allowlist load failed (magic/version or read error)\n");
	if (hymo_filp_close)
		hymo_filp_close(fp, NULL);
	else
		fput(fp);
	xa_destroy(&hymo_allow_uids_xa);
	hymo_allowlist_loaded = false;
	mutex_unlock(&hymo_config_mutex);
	return false;
}

/* ======================================================================
 * Part 12: Forward Redirect (resolve_target)
 * ====================================================================== */

char *hymofs_resolve_target(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	char *target = NULL;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return NULL;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return NULL;

	path_len = strlen(pathname);
	hash = full_name_hash(NULL, pathname, path_len);

	/* Fast path: atomic + bloom before rcu_read_lock */
	if (atomic_read(&hymo_rule_count) == 0)
		return NULL;
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);
		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return NULL;
	}

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash &&
		    strcmp(entry->src, pathname) == 0) {
			target = kstrdup(entry->target, GFP_ATOMIC);
			rcu_read_unlock();
			return target;
		}
	}
	/*
	 * Merge trie is NOT consulted here for path redirect. Merge rules
	 * only affect directory listing (inject via iterate_dir). Individual
	 * file redirects are materialized into hymo_paths at ADD_MERGE_RULE
	 * time, so the bloom+hash exact match above handles them.
	 *
	 * The KPM version validated merge targets with kern_path() before
	 * redirecting. In LKM kprobe context we cannot sleep, so blind
	 * merge-trie redirect would send EVERY path under the merge prefix
	 * to the module dir — including original system files that don't
	 * exist there — breaking PMS and causing bootloop.
	 */

	rcu_read_unlock();
	return target;
}

struct hymo_entry *hymofs_reverse_lookup_target(const char *path_str)
{
	struct hymo_entry *entry;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;

	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(entry,
		&hymo_targets[hash_min(hash, HYMO_HASH_BITS)], target_node) {
		if (strcmp(entry->target, path_str) == 0)
			return entry;
	}
	return NULL;
}

/* ======================================================================
 * Part 14: Hide Logic
 * ====================================================================== */

bool hymofs_should_hide(const char *pathname)
{
	struct hymo_hide_entry *he;
	u32 hash;
	size_t len;

	if (unlikely(!hymofs_enabled || !pathname || !*pathname))
		return false;
	if (unlikely(hymo_is_privileged_process()))
		return false;

	len = strlen(pathname);

	/* Stealth: always hide the mirror device */
	if (likely(hymo_stealth_enabled)) {
		size_t name_len = strlen(hymo_current_mirror_name);
		size_t path_len = strlen(hymo_current_mirror_path);

		if ((len == name_len && strcmp(pathname, hymo_current_mirror_name) == 0) ||
		    (len == path_len && strcmp(pathname, hymo_current_mirror_path) == 0))
			return true;
	}

	if (!hymo_should_apply_hide_rules())
		return false;

	/* Bloom fast-path */
	if (atomic_read(&hymo_hide_count) == 0)
		return false;

	{
		unsigned long bh1 = jhash(pathname, (u32)len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_hide_bloom) || !test_bit(bh2, hymo_hide_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(he,
		&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (he->path_hash == hash && strcmp(he->path, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool __maybe_unused hymofs_should_replace(const char *pathname)
{
	struct hymo_entry *entry;
	u32 hash;
	size_t path_len;
	pid_t pid;

	if (unlikely(!hymofs_enabled || !pathname))
		return false;

	pid = task_tgid_vnr(current);
	if (READ_ONCE(hymo_daemon_pid) > 0 && pid == READ_ONCE(hymo_daemon_pid))
		return false;
	if (atomic_read(&hymo_rule_count) == 0)
		return false;

	path_len = strlen(pathname);
	{
		unsigned long bh1 = jhash(pathname, (u32)path_len, 0) & (HYMO_BLOOM_SIZE - 1);
		unsigned long bh2 = jhash(pathname, (u32)path_len, 1) & (HYMO_BLOOM_SIZE - 1);

		if (!test_bit(bh1, hymo_path_bloom) || !test_bit(bh2, hymo_path_bloom))
			return false;
	}

	hash = full_name_hash(NULL, pathname, path_len);
	rcu_read_lock();
	hlist_for_each_entry_rcu(entry,
		&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (entry->src_hash == hash && strcmp(entry->src, pathname) == 0) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}
