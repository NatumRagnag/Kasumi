/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - runtime globals, resolved kernel symbols, and feature flags.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_RUNTIME_H
#define _HYMOFS_RUNTIME_H

#include <linux/anon_inodes.h>
#include <linux/bitmap.h>
#include <linux/fcntl.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/stat.h>
#include <linux/vmalloc.h>

#include "hymofs_base.h"
#include "hymofs_types.h"

extern bool hymofs_enabled;
extern atomic_t hymo_rule_count;
extern atomic_t hymo_hide_count;
extern atomic_t hymo_spoof_kstat_count;

struct hymo_percpu {
	unsigned int kprobe_reent;
	int iterate_did_swap;
	int in_populate_inject;
	int override_fd;
	int override_active;
#if defined(__aarch64__) || defined(__x86_64__)
	struct {
		char __user *buf;
		size_t count;
		int active;
	} cmdline_ctx;
	struct {
		struct statx __user *buf;
		char path[HYMO_MAX_LEN_PATHNAME];
		int active;
	} statx_ctx;
#endif
	int mount_proxy_pending;
};

extern struct hymo_percpu *hymo_percpu_base;

static inline struct hymo_percpu *hymo_this_cpu(void)
{
	return hymo_percpu_base + smp_processor_id();
}

extern char *hymo_getname_buf_base;
extern char *hymo_iterate_buf_base;
extern atomic_long_t hymo_ioctl_tgid;
extern atomic_long_t hymo_xattr_source_tgid;
extern struct kmem_cache *hymo_filldir_cache;
extern unsigned long (*hymofs_kallsyms_lookup_name)(const char *name);

bool hymofs_valid_kernel_addr(unsigned long addr);
void hymofs_resolve_kallsyms_lookup(void);

typedef bool (*hymo_ksu_is_allow_uid_fn)(uid_t uid);
typedef bool (*hymo_ksu_uid_should_umount_fn)(uid_t uid);
typedef bool (*hymo_ksu_get_allow_list_fn)(int *array, u16 length, u16 *out_length,
					   u16 *out_total, bool allow);

extern hymo_ksu_is_allow_uid_fn hymo_ksu_is_allow_uid_ptr;
extern hymo_ksu_uid_should_umount_fn hymo_ksu_uid_should_umount_ptr;
extern hymo_ksu_get_allow_list_fn hymo_ksu_get_allow_list_ptr;

extern bool hymo_stealth_enabled;
extern char hymo_mirror_path_buf[PATH_MAX];
extern char hymo_mirror_name_buf[NAME_MAX];
extern char *hymo_current_mirror_path;
extern char *hymo_current_mirror_name;

struct hymo_cmdline_rcu {
	struct rcu_head rcu;
	char cmdline[HYMO_FAKE_CMDLINE_SIZE];
};

extern struct hymo_cmdline_rcu __rcu *hymo_spoof_cmdline_ptr;
extern bool hymo_cmdline_spoof_active;
extern pid_t hymo_daemon_pid;

extern int hymo_cmdline_kprobe_registered;
extern int hymo_cmdline_kretprobe_registered;
extern int hymo_getxattr_kprobe_registered;
extern int hymo_mount_hide_vfsmnt_registered;
extern int hymo_mount_hide_mountinfo_registered;
extern int hymo_mount_hide_vfs_read_registered;
extern int hymo_mount_hide_read_fallback_registered;
extern int hymo_mount_hide_pread_fallback_registered;
extern int hymo_maps_seq_read_registered;
extern int hymo_feature_enabled_mask;
extern int hymo_statfs_kretprobe_registered;
extern int hymo_ni_kprobe_registered;
extern int hymo_reboot_kprobe_registered;
extern int hymo_syscall_nr_param;
extern bool hymo_getname_kprobe_registered;
extern bool hymo_vfs_use_ftrace;
extern dev_t hymo_system_dev;

extern int (*hymo_kern_path)(const char *, unsigned int, struct path *);
extern int (*hymo_vfs_getattr)(const struct path *, struct kstat *, u32, unsigned int);
extern struct file *(*hymo_dentry_open)(const struct path *, int, const struct cred *);
extern char *(*hymo_d_absolute_path)(const struct path *, char *, int);
extern char *(*hymo_dentry_path_raw)(const struct dentry *, char *, int);
extern char *(*hymo_d_path)(const struct path *, char *, int);
extern struct dentry *(*hymo_d_hash_and_lookup)(struct dentry *, const struct qstr *);
extern void *hymo_vfs_getxattr_addr;
extern struct file *(*hymo_filp_open)(const char *, int, umode_t);
extern int (*hymo_filp_close)(struct file *, fl_owner_t);
extern ssize_t (*hymo_kernel_read)(struct file *, void *, size_t, loff_t *);
extern char *(*hymo_strndup_user)(const char __user *, long);
extern struct filename *(*hymo_getname_kernel)(const char *);
extern void (*hymo_ihold)(struct inode *);
extern long (*hymo_strncpy_from_user_nofault)(char *dst, const void __user *src, long count);

#endif /* _HYMOFS_RUNTIME_H */
