/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - module bootstrap, symbol resolution, and top-level lifecycle orchestration.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "hymofs_bootstrap.h"
#include "hymofs_runtime.h"
#include "hymofs_store.h"
#include "hymofs_entrypoints.h"
#include "hymofs_proc_hooks.h"
#include "hymofs_vfs_hooks.h"
#include "hymofs_uname.h"
#include "hymofs_sop_override.h"
#include "hymofs_dop_override.h"
#include "hymofs_xattr_sid_override.h"
#include "hymofs_iop_override.h"
#include "hymofs_fop_override.h"
#include "hymofs_fake_mountinfo.h"

#ifndef HYMOFS_VERSION
#define HYMOFS_VERSION "0.1.0-dev"
#endif

static int hymo_no_tracepoint_param;
module_param_named(hymo_no_tracepoint, hymo_no_tracepoint_param, int, 0600);
MODULE_PARM_DESC(hymo_no_tracepoint, "1=skip sys_enter tracepoint, use kprobe. 0=try tracepoint first (default).");

static int hymo_skip_vfs_param;
module_param_named(hymo_skip_vfs, hymo_skip_vfs_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_vfs, "1=skip VFS hooks (ftrace+kprobes). For debugging crash.");

static int hymo_skip_extra_kprobes_param;
module_param_named(hymo_skip_extra_kprobes, hymo_skip_extra_kprobes_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_extra_kprobes, "1=skip extra kprobes (reboot,prctl,uname,cmdline). For debugging.");

static int hymo_skip_getfd_param;
module_param_named(hymo_skip_getfd, hymo_skip_getfd_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_getfd, "1=skip GET_FD kprobe/tracepoint. For debugging crash.");

static int hymo_skip_kallsyms_param;
module_param_named(hymo_skip_kallsyms, hymo_skip_kallsyms_param, int, 0600);
MODULE_PARM_DESC(hymo_skip_kallsyms, "1=skip kallsyms resolution, use per-symbol kprobe. For GKI compatibility.");

static int hymo_dummy_mode_param;
module_param_named(hymo_dummy_mode, hymo_dummy_mode_param, int, 0600);
MODULE_PARM_DESC(hymo_dummy_mode, "1=exit immediately after init starts (for testing).");

static void hymofs_resolve_system_dev(void)
{
	struct path sys_path = {};
	struct dentry *dentry;
	struct vfsmount *mnt;
	struct super_block *sb;
	int ret;

	if (!hymo_kern_path)
		return;

	ret = hymo_kern_path("/system", LOOKUP_FOLLOW, &sys_path);
	if (ret) {
		pr_warn("HymoFS: could not resolve /system for stat spoofing: %d\n", ret);
		return;
	}

	dentry = READ_ONCE(sys_path.dentry);
	mnt = READ_ONCE(sys_path.mnt);
	sb = dentry ? READ_ONCE(dentry->d_sb) : NULL;
	if (!dentry || !mnt || !sb) {
		pr_warn("HymoFS: /system resolved to incomplete path (mnt=%p dentry=%p sb=%p), stat spoofing dev disabled\n",
			mnt, dentry, sb);
		if (dentry && mnt)
			path_put(&sys_path);
		return;
	}

	hymo_system_dev = sb->s_dev;
	pr_info("HymoFS: /system dev=%u:%u\n",
		MAJOR(hymo_system_dev), MINOR(hymo_system_dev));
	path_put(&sys_path);
}

static int hymofs_resolve_runtime_symbols(void)
{
	hymo_kern_path = (void *)hymofs_lookup_name("kern_path");
	if (!hymo_kern_path) {
		pr_err("HymoFS: FATAL - kern_path not found\n");
		return -ENOENT;
	}

	hymo_strndup_user = (void *)hymofs_lookup_name("strndup_user");
	if (!hymo_strndup_user) {
		pr_err("HymoFS: FATAL - strndup_user not found\n");
		return -ENOENT;
	}

	hymo_ihold = (void *)hymofs_lookup_name("ihold");
	if (!hymo_ihold) {
		pr_err("HymoFS: FATAL - ihold not found\n");
		return -ENOENT;
	}

	hymo_getname_kernel = (void *)hymofs_lookup_name("getname_kernel");
	if (!hymo_getname_kernel)
		pr_warn("HymoFS: getname_kernel not found, path redirect may fail\n");

	hymo_filp_open = (void *)hymofs_lookup_name("filp_open");
	hymo_filp_close = (void *)hymofs_lookup_name("filp_close");
	hymo_kernel_read = (void *)hymofs_lookup_name("kernel_read");
	hymo_vfs_getattr = (void *)hymofs_lookup_name("vfs_getattr");
	hymo_dentry_open = (void *)hymofs_lookup_name("dentry_open");
	hymo_d_absolute_path = (void *)hymofs_lookup_name("d_absolute_path");
	hymo_dentry_path_raw = (void *)hymofs_lookup_name("dentry_path_raw");
	hymo_strncpy_from_user_nofault = (void *)hymofs_lookup_name("strncpy_from_user_nofault");
	if (!hymo_strncpy_from_user_nofault)
		pr_warn("HymoFS: strncpy_from_user_nofault not found, falling back to copy_from_user\n");
	hymo_d_path = (void *)hymofs_lookup_name("d_path");
	hymo_d_hash_and_lookup = (void *)hymofs_lookup_name("d_hash_and_lookup");
	if (!hymo_d_path)
		pr_warn("HymoFS: d_path not found, path resolution in populate/merge/hide may fail\n");
	if (!hymo_d_hash_and_lookup)
		pr_warn("HymoFS: d_hash_and_lookup not found, merge dedup and hide filter disabled\n");
	if (!hymo_filp_open || !hymo_kernel_read)
		pr_warn("HymoFS: filp_open/kernel_read not found, allowlist disabled\n");

	{
		unsigned long addr = hymofs_lookup_name("ksu_uid_should_umount");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_uid_should_umount_ptr = (hymo_ksu_uid_should_umount_fn)addr;
	}
	{
		unsigned long addr = hymofs_lookup_name("__ksu_is_allow_uid_for_current");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
	}
	if (!hymo_ksu_is_allow_uid_ptr) {
		unsigned long addr = hymofs_lookup_name("__ksu_is_allow_uid");
		if (addr && hymofs_valid_kernel_addr(addr))
			hymo_ksu_is_allow_uid_ptr = (hymo_ksu_is_allow_uid_fn)addr;
	}

	if (!hymo_vfs_getattr || !hymo_dentry_open)
		pr_warn("HymoFS: vfs_getattr/dentry_open not found, merge whiteout/iterate disabled\n");
	if (!hymo_d_absolute_path && !hymo_dentry_path_raw)
		pr_warn("HymoFS: neither d_absolute_path nor dentry_path_raw found, inject/merge listing disabled\n");

	return 0;
}

int hymofs_bootstrap_init(void)
{
	int ret;

	pr_alert("HymoFS: === INIT START v%s ===\n", HYMOFS_VERSION);
	if (hymo_dummy_mode_param) {
		pr_alert("HymoFS: DUMMY MODE - exiting immediately\n");
		return 0;
	}

	hymo_filldir_cache = kmem_cache_create("hymofs_filldir",
		sizeof(struct hymofs_filldir_wrapper), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!hymo_filldir_cache) {
		pr_alert("HymoFS: failed to create filldir slab cache\n");
		return -ENOMEM;
	}

	pr_alert("HymoFS: skip_kallsyms=%d skip_vfs=%d skip_extra=%d skip_getfd=%d\n",
		hymo_skip_kallsyms_param, hymo_skip_vfs_param,
		hymo_skip_extra_kprobes_param, hymo_skip_getfd_param);

	if (!hymo_skip_kallsyms_param)
		hymofs_resolve_kallsyms_lookup();
	else
		pr_alert("HymoFS: skipping kallsyms (using per-symbol kprobe)\n");

	ret = hymofs_resolve_runtime_symbols();
	if (ret)
		goto err_cache;

	hash_init(hymo_paths);
	hash_init(hymo_targets);
	hash_init(hymo_hide_paths);
	hash_init(hymo_inject_dirs);
	hash_init(hymo_xattr_sbs);
	hash_init(hymo_merge_dirs);

	hymo_percpu_base = vmalloc(nr_cpu_ids * sizeof(struct hymo_percpu));
	hymo_getname_buf_base = vmalloc(nr_cpu_ids * HYMO_PATH_BUF);
	hymo_iterate_buf_base = vmalloc(nr_cpu_ids * HYMO_ITERATE_PATH_BUF);
	if (!hymo_percpu_base || !hymo_getname_buf_base || !hymo_iterate_buf_base) {
		ret = -ENOMEM;
		pr_err("HymoFS: failed to allocate per-CPU buffers\n");
		goto err_buffers;
	}
	memset(hymo_percpu_base, 0, nr_cpu_ids * sizeof(struct hymo_percpu));

	hymofs_resolve_system_dev();

	ret = hymofs_proc_hooks_init(hymo_skip_getfd_param, hymo_no_tracepoint_param,
				     hymo_skip_extra_kprobes_param);
	if (ret)
		goto err_buffers;

	ret = hymofs_vfs_hooks_init(hymo_skip_vfs_param);
	if (ret)
		goto err_proc;

	(void)hymofs_sop_override_init();
	(void)hymofs_dop_override_init();
	(void)hymofs_xattr_sid_override_init();
	(void)hymofs_iop_override_init();
	(void)hymofs_fop_override_init();
	(void)hymo_fake_mi_init();
	return 0;

err_proc:
	hymofs_proc_hooks_exit();
err_buffers:
	vfree(hymo_percpu_base);
	vfree(hymo_getname_buf_base);
	vfree(hymo_iterate_buf_base);
	hymo_percpu_base = NULL;
	hymo_getname_buf_base = NULL;
	hymo_iterate_buf_base = NULL;
err_cache:
	if (hymo_filldir_cache) {
		kmem_cache_destroy(hymo_filldir_cache);
		hymo_filldir_cache = NULL;
	}
	return ret;
}

void hymofs_bootstrap_exit(void)
{
	struct hymo_cmdline_rcu *old_cmdline;

	pr_info("HymoFS: shutting down\n");

	hymo_fake_mi_exit();
	hymofs_fop_override_exit();
	hymofs_iop_override_exit();
	hymofs_xattr_sid_override_exit();
	hymofs_dop_override_exit();
	hymofs_sop_override_exit();
	hymofs_vfs_hooks_exit(hymo_skip_vfs_param);
	hymofs_proc_hooks_exit();
	hymofs_uname_exit();

	mutex_lock(&hymo_config_mutex);
	hymo_cleanup_locked();
	old_cmdline = rcu_dereference_protected(hymo_spoof_cmdline_ptr,
						lockdep_is_held(&hymo_config_mutex));
	rcu_assign_pointer(hymo_spoof_cmdline_ptr, NULL);
	mutex_unlock(&hymo_config_mutex);

	rcu_barrier();
	kfree(old_cmdline);
	if (hymo_filldir_cache)
		kmem_cache_destroy(hymo_filldir_cache);
	vfree(hymo_percpu_base);
	vfree(hymo_getname_buf_base);
	vfree(hymo_iterate_buf_base);
	hymo_percpu_base = NULL;
	hymo_getname_buf_base = NULL;
	hymo_iterate_buf_base = NULL;
	pr_info("HymoFS: unloaded\n");
}
