/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - shared runtime state, rule stores, and common cleanup helpers.
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

#include "hymofs_runtime.h"
#include "hymofs_store.h"

bool hymofs_enabled;
atomic_t hymo_rule_count = ATOMIC_INIT(0);
atomic_t hymo_hide_count = ATOMIC_INIT(0);

struct hymo_percpu *hymo_percpu_base;
char *hymo_getname_buf_base;
char *hymo_iterate_buf_base;

atomic_long_t hymo_ioctl_tgid = ATOMIC_LONG_INIT(0);
atomic_long_t hymo_xattr_source_tgid = ATOMIC_LONG_INIT(0);

struct kmem_cache *hymo_filldir_cache;

unsigned long (*hymofs_kallsyms_lookup_name)(const char *name);

DEFINE_HASHTABLE(hymo_paths, HYMO_HASH_BITS);
DEFINE_HASHTABLE(hymo_targets, HYMO_HASH_BITS);
DEFINE_HASHTABLE(hymo_hide_paths, HYMO_HASH_BITS);
DEFINE_XARRAY(hymo_allow_uids_xa);
DEFINE_HASHTABLE(hymo_inject_dirs, HYMO_HASH_BITS);
DEFINE_HASHTABLE(hymo_xattr_sbs, HYMO_HASH_BITS);
DEFINE_HASHTABLE(hymo_merge_dirs, HYMO_HASH_BITS);

DEFINE_HASHTABLE(hymo_spoof_kstat_path, HYMO_HASH_BITS);
DEFINE_HASHTABLE(hymo_spoof_kstat_ino, HYMO_HASH_BITS);
atomic_t hymo_spoof_kstat_count = ATOMIC_INIT(0);

DEFINE_MUTEX(hymo_config_mutex);
LIST_HEAD(hymo_maps_rules);
DEFINE_MUTEX(hymo_maps_mutex);

bool hymo_allowlist_loaded;
hymo_ksu_is_allow_uid_fn hymo_ksu_is_allow_uid_ptr;
hymo_ksu_uid_should_umount_fn hymo_ksu_uid_should_umount_ptr;

bool hymo_debug_enabled;
bool hymo_stealth_enabled = true;

char hymo_mirror_path_buf[PATH_MAX] = HYMO_DEFAULT_MIRROR_PATH;
char hymo_mirror_name_buf[NAME_MAX] = HYMO_DEFAULT_MIRROR_NAME;
char *hymo_current_mirror_path = hymo_mirror_path_buf;
char *hymo_current_mirror_name = hymo_mirror_name_buf;

struct hymo_cmdline_rcu __rcu *hymo_spoof_cmdline_ptr;
bool hymo_cmdline_spoof_active;

pid_t hymo_daemon_pid;

int hymo_cmdline_kprobe_registered;
int hymo_cmdline_kretprobe_registered;
int hymo_getxattr_kprobe_registered;
int hymo_mount_hide_vfsmnt_registered;
int hymo_mount_hide_mountinfo_registered;
int hymo_mount_hide_vfs_read_registered;
int hymo_mount_hide_read_fallback_registered;
int hymo_mount_hide_pread_fallback_registered;
int hymo_maps_seq_read_registered;
int hymo_feature_enabled_mask = 0xFFFFFFFF;
int hymo_statfs_kretprobe_registered;
int hymo_ni_kprobe_registered;
int hymo_reboot_kprobe_registered;
int hymo_syscall_nr_param = 142;
bool hymo_getname_kprobe_registered;
bool hymo_vfs_use_ftrace;

DECLARE_BITMAP(hymo_path_bloom, HYMO_BLOOM_SIZE);
DECLARE_BITMAP(hymo_hide_bloom, HYMO_BLOOM_SIZE);

dev_t hymo_system_dev;

int (*hymo_kern_path)(const char *, unsigned int, struct path *);
int (*hymo_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
struct file *(*hymo_dentry_open)(const struct path *, int, const struct cred *);
char *(*hymo_d_absolute_path)(const struct path *, char *, int);
char *(*hymo_dentry_path_raw)(const struct dentry *, char *, int);
char *(*hymo_d_path)(const struct path *, char *, int);
struct dentry *(*hymo_d_hash_and_lookup)(struct dentry *, const struct qstr *);
void *hymo_vfs_getxattr_addr;
struct file *(*hymo_filp_open)(const char *, int, umode_t);
int (*hymo_filp_close)(struct file *, fl_owner_t);
ssize_t (*hymo_kernel_read)(struct file *, void *, size_t, loff_t *);
char *(*hymo_strndup_user)(const char __user *, long);
struct filename *(*hymo_getname_kernel)(const char *);
void (*hymo_ihold)(struct inode *);
long (*hymo_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);
hymo_ksu_get_allow_list_fn hymo_ksu_get_allow_list_ptr;

bool hymofs_valid_kernel_addr(unsigned long addr)
{
	if (!addr)
		return false;
	if (IS_ERR_VALUE(addr))
		return false;
#if defined(CONFIG_64BIT)
	return (addr & (1UL << 63)) != 0;
#else
	return addr >= PAGE_OFFSET;
#endif
}

HYMO_NOCFI unsigned long hymofs_lookup_name(const char *name)
{
	if (hymofs_kallsyms_lookup_name) {
		unsigned long addr = hymofs_kallsyms_lookup_name(name);

		if (addr && !IS_ERR_VALUE(addr))
			return addr;
	}

	{
		struct kprobe kp = { .symbol_name = name };
		unsigned long addr;
		int ret;

		ret = register_kprobe(&kp);
		if (ret < 0) {
			pr_alert("HymoFS: kprobe %s failed: %d\n", name, ret);
			return 0;
		}
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
		if (!addr || IS_ERR_VALUE(addr)) {
			pr_alert("HymoFS: symbol %s returned invalid addr 0x%lx\n", name, addr);
			return 0;
		}
		return addr;
	}
}

void hymofs_resolve_kallsyms_lookup(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	pr_alert("HymoFS: resolving kallsyms_lookup_name...\n");
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_alert("HymoFS: kprobe kallsyms_lookup_name failed: %d, using per-symbol kprobe\n",
			 ret);
		return;
	}
	if (!hymofs_valid_kernel_addr((unsigned long)kp.addr)) {
		pr_alert("HymoFS: kallsyms_lookup_name returned invalid address: 0x%lx\n",
			 (unsigned long)kp.addr);
		unregister_kprobe(&kp);
		return;
	}
	hymofs_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	pr_alert("HymoFS: kallsyms_lookup_name resolved @ 0x%lx\n",
		 (unsigned long)hymofs_kallsyms_lookup_name);
}

void hymo_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_entry *e = container_of(head, struct hymo_entry, rcu);

	kfree(e->src);
	kfree(e->target);
	kfree(e);
}

void hymo_hide_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_hide_entry *e = container_of(head, struct hymo_hide_entry, rcu);

	kfree(e->path);
	kfree(e);
}

void hymo_inject_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_inject_entry *e = container_of(head, struct hymo_inject_entry, rcu);

	kfree(e->dir);
	kfree(e);
}

void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_xattr_sb_entry *e = container_of(head, struct hymo_xattr_sb_entry, rcu);

	kfree(e);
}

void hymo_merge_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_merge_entry *e = container_of(head, struct hymo_merge_entry, rcu);

	if (e->target_dentry)
		dput(e->target_dentry);
	kfree(e->src);
	kfree(e->target);
	kfree(e->resolved_src);
	kfree(e);
}

void hymo_spoof_kstat_entry_free_rcu(struct rcu_head *head)
{
	struct hymo_spoof_kstat_entry *e =
		container_of(head, struct hymo_spoof_kstat_entry, rcu);

	kfree(e->target_pathname);
	kfree(e);
}

struct hymo_spoof_kstat_entry *hymofs_spoof_kstat_lookup_by_path(const char *path_str)
{
	struct hymo_spoof_kstat_entry *e;
	u32 hash;

	if (!path_str || !*path_str)
		return NULL;
	hash = full_name_hash(NULL, path_str, strlen(path_str));
	hlist_for_each_entry_rcu(e,
		&hymo_spoof_kstat_path[hash_min(hash, HYMO_HASH_BITS)], path_node) {
		if (e->path_hash == hash && e->target_pathname &&
		    strcmp(e->target_pathname, path_str) == 0)
			return e;
	}
	return NULL;
}

struct hymo_spoof_kstat_entry *hymofs_spoof_kstat_lookup_by_ino(unsigned long ino,
								unsigned long dev)
{
	struct hymo_spoof_kstat_entry *e;

	if (!ino)
		return NULL;
	hlist_for_each_entry_rcu(e,
		&hymo_spoof_kstat_ino[hash_min(ino, HYMO_HASH_BITS)], ino_node) {
		if (e->target_ino == ino &&
		    (e->target_dev == 0 || dev == 0 || e->target_dev == dev))
			return e;
	}
	return NULL;
}

void hymofs_mark_inode_hidden(struct inode *inode)
{
	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

bool hymofs_is_inode_hidden_bit(struct inode *inode)
{
	if (!inode || !inode->i_mapping)
		return false;
	return test_bit(AS_FLAGS_HYMO_HIDE, &inode->i_mapping->flags);
}

void hymofs_mark_dir_has_inject(const char *path_str)
{
	struct path p;

	if (!path_str || !hymo_kern_path)
		return;
	if (hymo_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		set_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT, &d_inode(p.dentry)->i_mapping->flags);
	path_put(&p);
}

void hymo_clear_inode_flags_for_path(const char *path_str, unsigned int bit)
{
	struct path p;

	if (!path_str || !hymo_kern_path)
		return;
	if (hymo_kern_path(path_str, LOOKUP_FOLLOW, &p) != 0)
		return;
	if (p.dentry && d_inode(p.dentry) && d_inode(p.dentry)->i_mapping)
		clear_bit(bit, &d_inode(p.dentry)->i_mapping->flags);
	path_put(&p);
}

void hymo_cleanup_locked(void)
{
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_xattr_sb_entry *sb_entry;
	struct hymo_merge_entry *merge_entry;
	struct hlist_node *tmp;
	int bkt;

	hymofs_enabled = false;

	hash_for_each_safe(hymo_paths, bkt, tmp, entry, node) {
		hymo_clear_inode_flags_for_path(entry->src, AS_FLAGS_HYMO_HIDE);
		hlist_del_rcu(&entry->node);
		hlist_del_rcu(&entry->target_node);
		call_rcu(&entry->rcu, hymo_entry_free_rcu);
	}
	hash_for_each_safe(hymo_hide_paths, bkt, tmp, hide_entry, node) {
		hymo_clear_inode_flags_for_path(hide_entry->path, AS_FLAGS_HYMO_HIDE);
		hlist_del_rcu(&hide_entry->node);
		call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
	}
	xa_destroy(&hymo_allow_uids_xa);
	hash_for_each_safe(hymo_inject_dirs, bkt, tmp, inject_entry, node) {
		hymo_clear_inode_flags_for_path(inject_entry->dir, AS_FLAGS_HYMO_DIR_HAS_INJECT);
		hlist_del_rcu(&inject_entry->node);
		call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
	}
	hash_for_each_safe(hymo_xattr_sbs, bkt, tmp, sb_entry, node) {
		hlist_del_rcu(&sb_entry->node);
		call_rcu(&sb_entry->rcu, hymo_xattr_sb_entry_free_rcu);
	}
	hash_for_each_safe(hymo_merge_dirs, bkt, tmp, merge_entry, node) {
		hlist_del_rcu(&merge_entry->node);
		call_rcu(&merge_entry->rcu, hymo_merge_entry_free_rcu);
	}
	{
		struct hymo_spoof_kstat_entry *sk_entry;

		hash_for_each_safe(hymo_spoof_kstat_path, bkt, tmp, sk_entry, path_node) {
			hlist_del_rcu(&sk_entry->path_node);
			if (sk_entry->target_ino)
				hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, hymo_spoof_kstat_entry_free_rcu);
		}
		hash_for_each_safe(hymo_spoof_kstat_ino, bkt, tmp, sk_entry, ino_node) {
			hlist_del_rcu(&sk_entry->ino_node);
			call_rcu(&sk_entry->rcu, hymo_spoof_kstat_entry_free_rcu);
		}
		atomic_set(&hymo_spoof_kstat_count, 0);
	}

	bitmap_zero(hymo_path_bloom, HYMO_BLOOM_SIZE);
	bitmap_zero(hymo_hide_bloom, HYMO_BLOOM_SIZE);
	atomic_set(&hymo_rule_count, 0);
	atomic_set(&hymo_hide_count, 0);
	hymo_allowlist_loaded = false;
}
