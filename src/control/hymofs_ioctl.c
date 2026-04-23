/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - userspace control plane, ioctl dispatch, and daemon-facing anon-fd setup.
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
#include "hymofs_overlay.h"
#include "hymofs_tracepoint_hooks.h"
#include "hymofs_uname.h"
#include "hymofs_fake_mountinfo.h"
/* ======================================================================
 * Part 15: Dispatch Handler (ioctl only; all commands use HYMO_IOC_* from hymofs_uapi.h)
 * GET_FD is syscall-only -> hymofs_get_anon_fd()
 * ====================================================================== */

static int hymo_dispatch_cmd(unsigned int cmd, void __user *arg)
{
	struct hymo_syscall_arg req;
	struct hymo_entry *entry;
	struct hymo_hide_entry *hide_entry;
	struct hymo_inject_entry *inject_entry;
	char *src = NULL, *target = NULL;
	u32 hash;
	bool found = false;
	int ret = 0;

	if (cmd == HYMO_IOC_CLEAR_ALL) {
		mutex_lock(&hymo_config_mutex);
		hymo_cleanup_locked();
		strscpy(hymo_mirror_path_buf, HYMO_DEFAULT_MIRROR_PATH, PATH_MAX);
		strscpy(hymo_mirror_name_buf, HYMO_DEFAULT_MIRROR_NAME, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		mutex_unlock(&hymo_config_mutex);
		rcu_barrier();
		return 0;
	}

	if (cmd == HYMO_IOC_GET_VERSION) {
		int ver = HYMO_PROTOCOL_VERSION;
		if (copy_to_user(arg, &ver, sizeof(ver)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_SET_DEBUG) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_debug_enabled = !!val;
		hymo_log("debug mode %s\n", hymo_debug_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == HYMO_IOC_SET_STEALTH) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		hymo_stealth_enabled = !!val;
		hymo_log("stealth mode %s\n", hymo_stealth_enabled ? "enabled" : "disabled");
		return 0;
	}

	if (cmd == HYMO_IOC_SET_ENABLED) {
		int val;
		if (copy_from_user(&val, arg, sizeof(val)))
			return -EFAULT;
		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = !!val;
		mutex_unlock(&hymo_config_mutex);
		hymo_log("HymoFS %s\n", hymofs_enabled ? "enabled" : "disabled");
		if (hymofs_enabled)
			hymo_reload_ksu_allowlist();
		return 0;
	}

	if (cmd == HYMO_IOC_REORDER_MNT_ID) {
		/* struct mnt_namespace/mount not exposed to LKM; only KPM (built-in) supports this */
		return -EOPNOTSUPP;
	}

	if (cmd == HYMO_IOC_LIST_RULES) {
		struct hymo_syscall_list_arg list_arg;
		struct hymo_xattr_sb_entry *sb_entry;
		struct hymo_merge_entry *merge_entry;
		char *kbuf;
		size_t buf_size, written = 0;
		int bkt;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 64 * 1024)
			buf_size = 64 * 1024;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		rcu_read_lock();
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Protocol: %d\n", HYMO_PROTOCOL_VERSION);
		written += scnprintf(kbuf + written, buf_size - written,
				     "HymoFS Enabled: %d\n", hymofs_enabled ? 1 : 0);
		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "add %s %s %d\n", entry->src,
					     entry->target, entry->type);
		}
		hash_for_each_rcu(hymo_hide_paths, bkt, hide_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide %s\n", hide_entry->path);
		}
		hash_for_each_rcu(hymo_inject_dirs, bkt, inject_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "inject %s\n", inject_entry->dir);
		}
		hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "merge %s %s\n", merge_entry->src,
					     merge_entry->target);
		}
		hash_for_each_rcu(hymo_xattr_sbs, bkt, sb_entry, node) {
			if (written >= buf_size) break;
			written += scnprintf(kbuf + written, buf_size - written,
					     "hide_xattr_sb %p\n", sb_entry->sb);
		}
		/* Feature rules: mount_hide, maps_spoof, statfs_spoof, stealth */
		if (hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "mount_hide enabled\n");
		}
		if (hymo_feature_enabled_mask & HYMO_FEATURE_MAPS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "maps_spoof enabled\n");
		}
		if (hymo_feature_enabled_mask & HYMO_FEATURE_STATFS_SPOOF) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "statfs_spoof enabled\n");
		}
		if (hymo_stealth_enabled) {
			if (written < buf_size)
				written += scnprintf(kbuf + written, buf_size - written,
						     "stealth enabled\n");
		}
		rcu_read_unlock();

		if (copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MIRROR_PATH) {
		char *new_path, *new_name, *slash;
		size_t len;

		if (copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		if (!req.src)
			return -EINVAL;
		new_path = hymo_strndup_user(req.src, PATH_MAX);
		if (IS_ERR(new_path))
			return PTR_ERR(new_path);

		len = strlen(new_path);
		if (len > 1 && new_path[len - 1] == '/')
			new_path[len - 1] = '\0';

		slash = strrchr(new_path, '/');
		new_name = kstrdup(slash ? slash + 1 : new_path, GFP_KERNEL);
		if (!new_name) {
			kfree(new_path);
			return -ENOMEM;
		}

		mutex_lock(&hymo_config_mutex);
		strscpy(hymo_mirror_path_buf, new_path, PATH_MAX);
		strscpy(hymo_mirror_name_buf, new_name, NAME_MAX);
		hymo_current_mirror_path = hymo_mirror_path_buf;
		hymo_current_mirror_name = hymo_mirror_name_buf;
		mutex_unlock(&hymo_config_mutex);

		hymo_log("setting mirror path to: %s\n", hymo_mirror_path_buf);
		kfree(new_path);
		kfree(new_name);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_UNAME) {
		/* Scoped mode: stored config is applied per-task on first syscall
		 * from a hidden-uid process by unsharing CLONE_NEWUTS and writing
		 * the fake fields into the task's private uts_ns. */
		struct hymo_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		return hymofs_uname_set_scoped_config(&u);
	}

	if (cmd == HYMO_IOC_SET_UNAME_GLOBAL) {
		/* Global mode: rewrite init_uts_ns in place. All-empty struct
		 * restores originals. */
		struct hymo_spoof_uname u;

		if (copy_from_user(&u, arg, sizeof(u)))
			return -EFAULT;
		if (u.sysname[0] || u.nodename[0] || u.release[0] ||
		    u.version[0] || u.machine[0] || u.domainname[0])
			return hymofs_uname_apply_global(&u);
		return hymofs_uname_restore_global();
	}

	if (cmd == HYMO_IOC_SET_CMDLINE) {
		struct hymo_spoof_cmdline *c = kmalloc(sizeof(*c), GFP_KERNEL);
		struct hymo_cmdline_rcu *new_cmdline, *old_cmdline;

		if (!c)
			return -ENOMEM;
		if (copy_from_user(c, arg, sizeof(*c))) {
			kfree(c);
			return -EFAULT;
		}
		new_cmdline = kmalloc(sizeof(*new_cmdline), GFP_KERNEL);
		if (!new_cmdline) {
			kfree(c);
			return -ENOMEM;
		}
		strscpy(new_cmdline->cmdline, c->cmdline, sizeof(new_cmdline->cmdline));
		mutex_lock(&hymo_config_mutex);
		old_cmdline = rcu_dereference_protected(hymo_spoof_cmdline_ptr,
							lockdep_is_held(&hymo_config_mutex));
		rcu_assign_pointer(hymo_spoof_cmdline_ptr, new_cmdline);
		mutex_unlock(&hymo_config_mutex);
		if (old_cmdline)
			kfree_rcu(old_cmdline, rcu);
		hymo_cmdline_spoof_active = (c->cmdline[0] != '\0');
		kfree(c);
		if (hymo_cmdline_spoof_active)
			hymo_log("cmdline: spoofed\n");
		return 0;
	}

	if (cmd == HYMO_IOC_ADD_SPOOF_KSTAT || cmd == HYMO_IOC_UPDATE_SPOOF_KSTAT) {
		struct hymo_spoof_kstat __user *u = (struct hymo_spoof_kstat __user *)arg;
		struct hymo_spoof_kstat *k;
		struct hymo_spoof_kstat_entry *e, *existing = NULL;
		size_t plen;
		u32 phash = 0;
		bool have_path;
		struct path resolved;
		unsigned long auto_ino = 0;

		k = kmalloc(sizeof(*k), GFP_KERNEL);
		if (!k)
			return -ENOMEM;
		if (copy_from_user(k, u, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		k->target_pathname[HYMO_MAX_LEN_PATHNAME - 1] = '\0';
		have_path = (k->target_pathname[0] != '\0');

		/* Auto-resolve target_ino from path if userspace did not supply one. */
		if (have_path && k->target_ino == 0 && hymo_kern_path) {
			if (hymo_kern_path(k->target_pathname, LOOKUP_FOLLOW, &resolved) == 0) {
				if (resolved.dentry && d_inode(resolved.dentry))
					auto_ino = (unsigned long)d_inode(resolved.dentry)->i_ino;
				path_put(&resolved);
			}
			if (auto_ino)
				k->target_ino = auto_ino;
		}

		if (!have_path && !k->target_ino) {
			k->err = -EINVAL;
			(void)copy_to_user(u, k, sizeof(*k));
			kfree(k);
			return -EINVAL;
		}

		if (have_path) {
			plen = strlen(k->target_pathname);
			phash = full_name_hash(NULL, k->target_pathname, plen);
		}

		mutex_lock(&hymo_config_mutex);

		/* Look for existing entry by path, then by ino. */
		if (have_path) {
			hlist_for_each_entry(e,
				&hymo_spoof_kstat_path[hash_min(phash, HYMO_HASH_BITS)], path_node) {
				if (e->path_hash == phash && e->target_pathname &&
				    strcmp(e->target_pathname, k->target_pathname) == 0) {
					existing = e;
					break;
				}
			}
		}
		if (!existing && k->target_ino) {
			hlist_for_each_entry(e,
				&hymo_spoof_kstat_ino[hash_min(k->target_ino, HYMO_HASH_BITS)],
				ino_node) {
				if (e->target_ino == k->target_ino &&
				    e->target_dev == 0) {
					existing = e;
					break;
				}
			}
		}

		if (existing && cmd == HYMO_IOC_ADD_SPOOF_KSTAT) {
			/* Idempotent ADD: treat as UPDATE. */
		}

		if (!existing) {
			e = kzalloc(sizeof(*e), GFP_KERNEL);
			if (!e) {
				mutex_unlock(&hymo_config_mutex);
				k->err = -ENOMEM;
				(void)copy_to_user(u, k, sizeof(*k));
				kfree(k);
				return -ENOMEM;
			}
			if (have_path) {
				e->target_pathname = kstrdup(k->target_pathname, GFP_KERNEL);
				if (!e->target_pathname) {
					kfree(e);
					mutex_unlock(&hymo_config_mutex);
					k->err = -ENOMEM;
					(void)copy_to_user(u, k, sizeof(*k));
					kfree(k);
					return -ENOMEM;
				}
				e->path_hash = phash;
			}
			e->target_ino = k->target_ino;
			e->target_dev = 0;
			e->spoofed_ino     = k->spoofed_ino;
			e->spoofed_dev     = k->spoofed_dev;
			e->spoofed_nlink   = k->spoofed_nlink;
			e->spoofed_size    = k->spoofed_size;
			e->spoofed_atime_sec  = k->spoofed_atime_sec;
			e->spoofed_atime_nsec = k->spoofed_atime_nsec;
			e->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			e->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			e->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			e->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			e->spoofed_blksize = k->spoofed_blksize;
			e->spoofed_blocks  = k->spoofed_blocks;
			e->is_static       = k->is_static;

			if (have_path)
				hlist_add_head_rcu(&e->path_node,
					&hymo_spoof_kstat_path[hash_min(phash, HYMO_HASH_BITS)]);
			if (e->target_ino)
				hlist_add_head_rcu(&e->ino_node,
					&hymo_spoof_kstat_ino[hash_min(e->target_ino, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_spoof_kstat_count);
			hymo_log("spoof_kstat: add path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 e->target_ino, e->spoofed_ino);
		} else {
			/* Update fields in place; readers may see torn values
			 * briefly, acceptable for stat() spoof. */
			existing->spoofed_ino     = k->spoofed_ino;
			existing->spoofed_dev     = k->spoofed_dev;
			existing->spoofed_nlink   = k->spoofed_nlink;
			existing->spoofed_size    = k->spoofed_size;
			existing->spoofed_atime_sec  = k->spoofed_atime_sec;
			existing->spoofed_atime_nsec = k->spoofed_atime_nsec;
			existing->spoofed_mtime_sec  = k->spoofed_mtime_sec;
			existing->spoofed_mtime_nsec = k->spoofed_mtime_nsec;
			existing->spoofed_ctime_sec  = k->spoofed_ctime_sec;
			existing->spoofed_ctime_nsec = k->spoofed_ctime_nsec;
			existing->spoofed_blksize = k->spoofed_blksize;
			existing->spoofed_blocks  = k->spoofed_blocks;
			existing->is_static       = k->is_static;

			/* If newly-resolved ino became available, link into ino table. */
			if (existing->target_ino == 0 && k->target_ino) {
				existing->target_ino = k->target_ino;
				hlist_add_head_rcu(&existing->ino_node,
					&hymo_spoof_kstat_ino[hash_min(k->target_ino, HYMO_HASH_BITS)]);
			}
			hymo_log("spoof_kstat: update path=%s ino=%lu->%lu\n",
				 have_path ? k->target_pathname : "(none)",
				 existing->target_ino, existing->spoofed_ino);
		}

		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);

		k->err = 0;
		if (copy_to_user(u, k, sizeof(*k))) {
			kfree(k);
			return -EFAULT;
		}
		kfree(k);
		return 0;
	}

	if (cmd == HYMO_IOC_ADD_MAPS_RULE) {
		struct hymo_maps_rule __user *u = (struct hymo_maps_rule __user *)arg;
		struct hymo_maps_rule k;
		struct hymo_maps_rule_entry *e;

		if (copy_from_user(&k, u, sizeof(k)))
			return -EFAULT;
		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (!e) {
			k.err = -ENOMEM;
			if (copy_to_user(u, &k, sizeof(k)))
				return -EFAULT;
			return -ENOMEM;
		}
		e->target_ino = k.target_ino;
		e->target_dev = k.target_dev;
		e->spoofed_ino = k.spoofed_ino;
		e->spoofed_dev = k.spoofed_dev;
		strscpy(e->spoofed_pathname, k.spoofed_pathname, sizeof(e->spoofed_pathname));
		k.err = 0;
		if (copy_to_user(u, &k, sizeof(k))) {
			kfree(e);
			return -EFAULT;
		}
		mutex_lock(&hymo_maps_mutex);
		list_add_tail(&e->list, &hymo_maps_rules);
		mutex_unlock(&hymo_maps_mutex);
		return 0;
	}

	if (cmd == HYMO_IOC_CLEAR_MAPS_RULES) {
		struct hymo_maps_rule_entry *e, *tmp;

		mutex_lock(&hymo_maps_mutex);
		list_for_each_entry_safe(e, tmp, &hymo_maps_rules, list) {
			list_del(&e->list);
			kfree(e);
		}
		mutex_unlock(&hymo_maps_mutex);
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MOUNT_HIDE) {
		struct hymo_mount_hide_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_MOUNT_HIDE;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_MOUNT_HIDE;
		hymo_fake_mi_invalidate_all();
		/* path_pattern reserved for future custom hide rules */
		return 0;
	}

	if (cmd == HYMO_IOC_SET_MAPS_SPOOF) {
		struct hymo_maps_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_MAPS_SPOOF;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_MAPS_SPOOF;
		/* reserved for future inline rule */
		return 0;
	}

	if (cmd == HYMO_IOC_SET_STATFS_SPOOF) {
		struct hymo_statfs_spoof_arg a;
		if (copy_from_user(&a, arg, sizeof(a)))
			return -EFAULT;
		if (a.enable)
			hymo_feature_enabled_mask |= HYMO_FEATURE_STATFS_SPOOF;
		else
			hymo_feature_enabled_mask &= ~HYMO_FEATURE_STATFS_SPOOF;
		/* path/spoof_f_type reserved for future custom mappings */
		return 0;
	}

	if (cmd == HYMO_IOC_GET_FEATURES) {
		int features = 0;
		if (hymofs_uname_capable())
			features |= HYMO_FEATURE_UNAME_SPOOF;
		if (hymo_cmdline_kprobe_registered || hymo_cmdline_kretprobe_registered ||
		    (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered()))
			features |= HYMO_FEATURE_CMDLINE_SPOOF;
		features |= HYMO_FEATURE_KSTAT_SPOOF;
		features |= HYMO_FEATURE_MERGE_DIR;
		if (hymo_getxattr_kprobe_registered)
			features |= HYMO_FEATURE_SELINUX_BYPASS;
		if (hymo_mount_hide_vfsmnt_registered || hymo_mount_hide_mountinfo_registered ||
		    hymo_mount_hide_vfs_read_registered ||
		    hymo_mount_hide_read_fallback_registered ||
		    hymo_mount_hide_pread_fallback_registered)
			features |= HYMO_FEATURE_MOUNT_HIDE;
		if (hymo_mount_hide_vfs_read_registered ||
		    hymo_mount_hide_read_fallback_registered ||
		    hymo_mount_hide_pread_fallback_registered ||
		    hymo_maps_seq_read_registered)
			features |= HYMO_FEATURE_MAPS_SPOOF;
		if (hymo_statfs_kretprobe_registered)
			features |= HYMO_FEATURE_STATFS_SPOOF;
		if (copy_to_user(arg, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	}

	if (cmd == HYMO_IOC_GET_HOOKS) {
		struct hymo_syscall_list_arg list_arg;
		char *kbuf;
		size_t buf_size, written = 0;
		int n;

		if (copy_from_user(&list_arg, arg, sizeof(list_arg)))
			return -EFAULT;

		buf_size = list_arg.size;
		if (buf_size > 2048)
			buf_size = 2048;

		kbuf = kzalloc(buf_size, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		/* GET_FD */
		if (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered())
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: tracepoint (sys_enter/sys_exit)\n");
		else if (hymo_ni_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (ni_syscall nr=%d)\n", hymo_syscall_nr_param);
		else if (hymo_reboot_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "GET_FD: kprobe (reboot nr=%d)\n", hymo_syscall_nr_param);
		else
			n = scnprintf(kbuf + written, buf_size - written, "GET_FD: none\n");
		written += n;

		/* Path redirect */
		if (hymofs_tracepoint_path_registered())
			n = scnprintf(kbuf + written, buf_size - written, "path: tracepoint (sys_enter)\n");
		else if (hymo_getname_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "path: kprobe (getname_flags)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "path: none\n");
		written += n;

		/* VFS hooks */
		if (hymo_vfs_use_ftrace)
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: ftrace+kretprobe\n");
		else
			n = scnprintf(kbuf + written, buf_size - written,
				     "vfs_getattr,d_path,iterate_dir,vfs_getxattr: kprobe+kretprobe\n");
		written += n;

		/* uname */
		{
			const char *mode = "none";
			bool g = hymofs_uname_global_active();
			bool s = hymofs_uname_scoped_active();
			if (g && s)       mode = "utsname (global+scoped)";
			else if (g)        mode = "utsname (global)";
			else if (s)        mode = "utsname (scoped/uts_ns)";
			n = scnprintf(kbuf + written, buf_size - written,
				     "uname: %s\n", mode);
			written += n;
		}

		/* cmdline */
		if (hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered())
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: tracepoint (sys_enter/sys_exit)\n");
		else if (hymo_cmdline_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kretprobe (read)\n");
		else if (hymo_cmdline_kprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: kprobe (cmdline_proc_show)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "cmdline: none\n");
		written += n;

		/* mountinfo/mounts hide */
		if (hymo_mount_hide_vfsmnt_registered && hymo_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kprobe (show_mountinfo, show_vfsmnt)\n");
		else if (hymo_mount_hide_vfsmnt_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mounts: kprobe (show_vfsmnt)\n");
		else if (hymo_mount_hide_mountinfo_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo: kprobe (show_mountinfo)\n");
		else if (hymo_mount_hide_vfs_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (vfs_read buffer filter)\n");
		else if (hymo_mount_hide_read_fallback_registered &&
			 hymo_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (read/pread64 syscall buffer filter)\n");
		else if (hymo_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (read syscall buffer filter)\n");
		else if (hymo_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "mountinfo/mounts: kretprobe (pread64 syscall buffer filter)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "mountinfo/mounts: none\n");
		written += n;

		/* maps spoof (read kretprobe or seq_read fallback) */
		if (hymo_mount_hide_vfs_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (vfs_read buffer filter)\n");
		else if (hymo_mount_hide_read_fallback_registered &&
		    hymo_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (read/pread64 buffer filter)\n");
		else if (hymo_mount_hide_read_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (read buffer filter)\n");
		else if (hymo_mount_hide_pread_fallback_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (pread64 buffer filter)\n");
		else if (hymo_maps_seq_read_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "maps: kretprobe (seq_read fallback)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "maps: none\n");
		written += n;
		if (hymo_statfs_kretprobe_registered)
			n = scnprintf(kbuf + written, buf_size - written,
				     "statfs: kretprobe (f_type spoof for INCONSISTENT_MOUNT)\n");
		else
			n = scnprintf(kbuf + written, buf_size - written, "statfs: none\n");
		written += n;

		list_arg.size = written;
		if (copy_to_user(arg, &list_arg, sizeof(list_arg))) {
			kfree(kbuf);
			return -EFAULT;
		}
		if (written && copy_to_user(list_arg.buf, kbuf, written)) {
			kfree(kbuf);
			return -EFAULT;
		}
		kfree(kbuf);
		return 0;
	}

	/* Commands that use hymo_syscall_arg */
	if (copy_from_user(&req, arg, sizeof(req)))
		return -EFAULT;

	if (req.src) {
		src = hymo_strndup_user(req.src, PAGE_SIZE);
		if (IS_ERR(src))
			return PTR_ERR(src);
	}
	if (req.target) {
		target = hymo_strndup_user(req.target, PAGE_SIZE);
		if (IS_ERR(target)) {
			kfree(src);
			return PTR_ERR(target);
		}
	}

	switch (cmd) {
	case HYMO_IOC_ADD_MERGE_RULE: {
		struct hymo_merge_entry *me;
		char *mat_src = NULL, *mat_tgt = NULL;

		if (!src || !target) { ret = -EINVAL; break; }

		/* Resolve symlinks: d_absolute_path in iterate_dir returns
		 * canonical paths (e.g. /product/overlay), while userspace sends
		 * symlink paths (e.g. /system/product/overlay). Store the
		 * canonical form as resolved_src for iterate_dir matching. */
		{
			char *resolved_src = NULL;
			struct dentry *tgt_dentry = NULL;
			struct path mpath;

			if (hymo_kern_path(src, LOOKUP_FOLLOW, &mpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && hymo_d_path) {
					char *res = hymo_d_path(&mpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/' &&
					    strcmp(res, src) != 0)
						resolved_src = kstrdup(res, GFP_KERNEL);
					kfree(rbuf);
				}
				path_put(&mpath);
			}
			if (hymo_kern_path(target, LOOKUP_FOLLOW, &mpath) == 0) {
				tgt_dentry = dget(mpath.dentry);
				path_put(&mpath);
			}

			hash = full_name_hash(NULL, src, strlen(src));
			mutex_lock(&hymo_config_mutex);

			hlist_for_each_entry(me,
				&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
				if (strcmp(me->src, src) == 0 &&
				    strcmp(me->target, target) == 0) {
					found = true;
					break;
				}
			}
			if (!found) {
				me = kmalloc(sizeof(*me), GFP_KERNEL);
				if (me) {
					mat_src = kstrdup(src, GFP_KERNEL);
					mat_tgt = kstrdup(target, GFP_KERNEL);
					me->src = src;
					me->target = target;
					me->resolved_src = resolved_src;
					me->target_dentry = tgt_dentry;
					resolved_src = NULL;
					tgt_dentry = NULL;
					hlist_add_head_rcu(&me->node,
						&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
					src = NULL;
					target = NULL;
				} else {
					ret = -ENOMEM;
				}
			} else {
				ret = -EEXIST;
			}
			mutex_unlock(&hymo_config_mutex);
			if (!found && !ret) {
				hymo_log("add merge rule: src=%s, target=%s\n", me->src, me->target);
				hymofs_add_inject_rule(kstrdup(me->src, GFP_KERNEL));
				if (me->resolved_src)
					hymofs_add_inject_rule(kstrdup(me->resolved_src, GFP_KERNEL));
				hymofs_mark_dir_has_inject(me->src);
				if (me->resolved_src)
					hymofs_mark_dir_has_inject(me->resolved_src);
				if (mat_src && mat_tgt)
					hymofs_materialize_merge(mat_src, mat_tgt, 0);
			}
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			kfree(mat_src);
			kfree(mat_tgt);
		}
		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_ADD_RULE: {
		char *parent_dir = NULL;
		char *resolved_src = NULL;
		struct path path;
		struct inode *src_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src || !target) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		/* Try to resolve full path */
		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res)) {
				resolved_src = kstrdup(res, GFP_KERNEL);
				{
					char *ls = strrchr(res, '/');
					if (ls) {
						if (ls == res)
							parent_dir = kstrdup("/", GFP_KERNEL);
						else {
							size_t l = ls - res;
							parent_dir = kmalloc(l + 1, GFP_KERNEL);
							if (parent_dir) {
								memcpy(parent_dir, res, l);
								parent_dir[l] = '\0';
							}
						}
					}
				}
			}
			if (d_inode(path.dentry)) {
				src_inode = d_inode(path.dentry);
				hymo_ihold(src_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		} else {
			char *ls = strrchr(src, '/');
			if (ls && ls != src) {
				size_t l = ls - src;
				char *p_str = kmalloc(l + 1, GFP_KERNEL);
				if (p_str) {
					memcpy(p_str, src, l);
					p_str[l] = '\0';
					if (hymo_kern_path(p_str, LOOKUP_FOLLOW, &path) == 0) {
						char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
						if (!IS_ERR(res)) {
							size_t rl = strlen(res);
							size_t nl = strlen(ls);
							resolved_src = kmalloc(rl + nl + 1, GFP_KERNEL);
							if (resolved_src) {
								strcpy(resolved_src, res);
								strcat(resolved_src, ls);
							}
							parent_dir = kstrdup(res, GFP_KERNEL);
						}
						path_put(&path);
					}
					kfree(p_str);
				}
			}
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				char *old_t = entry->target;
				char *new_t = kstrdup(target, GFP_KERNEL);
				if (new_t) {
					hlist_del_rcu(&entry->target_node);
					rcu_assign_pointer(entry->target, new_t);
					entry->type = req.type;
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, new_t, strlen(new_t)),
							HYMO_HASH_BITS)]);
					kfree(old_t);
				}
				found = true;
				break;
			}
		}
		if (!found) {
			entry = kmalloc(sizeof(*entry), GFP_KERNEL);
			if (entry) {
				entry->src = kstrdup(src, GFP_KERNEL);
				entry->target = kstrdup(target, GFP_KERNEL);
				entry->type = req.type;
				entry->src_hash = hash;
				if (entry->src && entry->target) {
					unsigned long h1, h2;
					hlist_add_head_rcu(&entry->node,
						&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hlist_add_head_rcu(&entry->target_node,
						&hymo_targets[hash_min(
							full_name_hash(NULL, entry->target,
								strlen(entry->target)),
							HYMO_HASH_BITS)]);
					h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_path_bloom);
					set_bit(h2, hymo_path_bloom);
					atomic_inc(&hymo_rule_count);
					hymo_log("add rule: src=%s, target=%s, type=%d\n", src, target, req.type);
				} else {
					kfree(entry->src);
					kfree(entry->target);
					kfree(entry);
				}
			}
		}
		mutex_unlock(&hymo_config_mutex);

		if (parent_dir) {
			hymofs_add_inject_rule(parent_dir);
			hymofs_mark_dir_has_inject(parent_dir);
		}

		/* Do not mark redirect source as hidden: we do not inject a virtual
		 * entry for simple ADD_RULE, so hiding would make the file disappear
		 * from the listing. Open of the path is still redirected via getname. */
		if (src_inode)
			iput(src_inode);
		if (parent_inode)
			iput(parent_inode);

		mutex_lock(&hymo_config_mutex);
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_HIDE_RULE: {
		char *resolved_src = NULL;
		struct path path;
		struct inode *target_inode = NULL;
		struct inode *parent_inode = NULL;
		char *tmp_buf;

		if (!src) { ret = -EINVAL; break; }

		tmp_buf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (!tmp_buf) { ret = -ENOMEM; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			char *res = hymo_d_path ? hymo_d_path(&path, tmp_buf, PATH_MAX) : ERR_PTR(-ENOENT);
			if (!IS_ERR(res))
				resolved_src = kstrdup(res, GFP_KERNEL);
			if (d_inode(path.dentry)) {
				target_inode = d_inode(path.dentry);
				hymo_ihold(target_inode);
			}
			if (path.dentry->d_parent && d_inode(path.dentry->d_parent)) {
				parent_inode = d_inode(path.dentry->d_parent);
				hymo_ihold(parent_inode);
			}
			path_put(&path);
		}
		kfree(tmp_buf);

		if (resolved_src) {
			kfree(src);
			src = resolved_src;
		}

		if (target_inode) {
			hymofs_mark_inode_hidden(target_inode);
			iput(target_inode);
		}
		if (parent_inode) {
			if (parent_inode->i_mapping)
				set_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
					&parent_inode->i_mapping->flags);
			iput(parent_inode);
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			hide_entry = kmalloc(sizeof(*hide_entry), GFP_KERNEL);
			if (hide_entry) {
				hide_entry->path = kstrdup(src, GFP_KERNEL);
				hide_entry->path_hash = hash;
				if (hide_entry->path) {
					unsigned long h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
					unsigned long h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
					set_bit(h1, hymo_hide_bloom);
					set_bit(h2, hymo_hide_bloom);
					atomic_inc(&hymo_hide_count);
					hlist_add_head_rcu(&hide_entry->node,
						&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)]);
					hymo_log("hide rule: src=%s\n", src);
				} else {
					kfree(hide_entry);
				}
			}
		}
		hymofs_enabled = true;
		mutex_unlock(&hymo_config_mutex);
		break;
	}

	case HYMO_IOC_HIDE_OVERLAY_XATTRS: {
		struct path path;
		struct hymo_xattr_sb_entry *sb_entry;
		bool xfound = false;

		if (!src) { ret = -EINVAL; break; }

		if (hymo_kern_path(src, LOOKUP_FOLLOW, &path) == 0) {
			struct super_block *sb = path.dentry->d_sb;

			mutex_lock(&hymo_config_mutex);
			hlist_for_each_entry(sb_entry,
				&hymo_xattr_sbs[hash_min((unsigned long)sb, HYMO_HASH_BITS)], node) {
				if (sb_entry->sb == sb) {
					xfound = true;
					break;
				}
			}
			if (!xfound) {
				sb_entry = kmalloc(sizeof(*sb_entry), GFP_KERNEL);
				if (sb_entry) {
					sb_entry->sb = sb;
					hlist_add_head_rcu(&sb_entry->node,
						&hymo_xattr_sbs[hash_min((unsigned long)sb,
							HYMO_HASH_BITS)]);
					hymo_log("hide xattrs for sb %p (path: %s)\n", sb, src);
				}
			}
			hymofs_enabled = true;
			mutex_unlock(&hymo_config_mutex);
			path_put(&path);
		} else {
			ret = -ENOENT;
		}
		break;
	}

	case HYMO_IOC_DEL_RULE: {
		struct inode *del_inode = NULL;
		struct inode *del_parent_inode = NULL;

		if (!src) { ret = -EINVAL; break; }

		/* Resolve symlinks so the path matches what ADD_RULE stored */
		if (hymo_kern_path) {
			struct path dpath;
			if (hymo_kern_path(src, LOOKUP_FOLLOW, &dpath) == 0) {
				char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (rbuf && hymo_d_path) {
					char *res = hymo_d_path(&dpath, rbuf, PATH_MAX);
					if (!IS_ERR(res) && res[0] == '/') {
						char *resolved = kstrdup(res, GFP_KERNEL);
						if (resolved) {
							kfree(src);
							src = resolved;
						}
					}
				}
				if (d_inode(dpath.dentry)) {
					del_inode = d_inode(dpath.dentry);
					hymo_ihold(del_inode);
				}
				if (dpath.dentry->d_parent &&
				    d_inode(dpath.dentry->d_parent)) {
					del_parent_inode = d_inode(dpath.dentry->d_parent);
					hymo_ihold(del_parent_inode);
				}
				kfree(rbuf);
				path_put(&dpath);
			}
		}

		hash = full_name_hash(NULL, src, strlen(src));
		mutex_lock(&hymo_config_mutex);

		hlist_for_each_entry(entry,
			&hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (entry->src_hash == hash && strcmp(entry->src, src) == 0) {
				hlist_del_rcu(&entry->node);
				hlist_del_rcu(&entry->target_node);
				atomic_dec(&hymo_rule_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&entry->rcu, hymo_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(hide_entry,
			&hymo_hide_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (hide_entry->path_hash == hash &&
			    strcmp(hide_entry->path, src) == 0) {
				hlist_del_rcu(&hide_entry->node);
				atomic_dec(&hymo_hide_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&hide_entry->rcu, hymo_hide_entry_free_rcu);
				goto del_done;
			}
		}
		hlist_for_each_entry(inject_entry,
			&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, src) == 0) {
				hlist_del_rcu(&inject_entry->node);
				atomic_dec(&hymo_rule_count);
				hymo_log("del rule: src=%s\n", src);
				call_rcu(&inject_entry->rcu, hymo_inject_entry_free_rcu);
				goto del_done;
			}
		}
del_done:
		mutex_unlock(&hymo_config_mutex);
		if (del_inode) {
			if (del_inode->i_mapping)
				clear_bit(AS_FLAGS_HYMO_HIDE,
					  &del_inode->i_mapping->flags);
			iput(del_inode);
		}
		if (del_parent_inode) {
			iput(del_parent_inode);
		}
		break;
	}

	default:
		ret = -EINVAL;
		break;
	}

	kfree(src);
	kfree(target);
	return ret;
}

/* ======================================================================
 * Part 16: Ioctl Handler
 * ====================================================================== */

static HYMO_NOCFI long hymofs_dev_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	long ret;

	atomic_long_set(&hymo_ioctl_tgid, (long)task_tgid_vnr(current));
	switch (cmd) {
	case HYMO_IOC_GET_VERSION:
	case HYMO_IOC_SET_ENABLED:
	case HYMO_IOC_ADD_RULE:
	case HYMO_IOC_DEL_RULE:
	case HYMO_IOC_HIDE_RULE:
	case HYMO_IOC_CLEAR_ALL:
	case HYMO_IOC_LIST_RULES:
	case HYMO_IOC_SET_DEBUG:
	case HYMO_IOC_REORDER_MNT_ID:
	case HYMO_IOC_SET_STEALTH:
	case HYMO_IOC_HIDE_OVERLAY_XATTRS:
	case HYMO_IOC_ADD_MERGE_RULE:
	case HYMO_IOC_SET_MIRROR_PATH:
	case HYMO_IOC_GET_HOOKS:
	case HYMO_IOC_SET_UNAME:
	case HYMO_IOC_SET_UNAME_GLOBAL:
	case HYMO_IOC_ADD_MAPS_RULE:
	case HYMO_IOC_CLEAR_MAPS_RULES:
	case HYMO_IOC_GET_FEATURES:
	case HYMO_IOC_SET_MOUNT_HIDE:
	case HYMO_IOC_SET_MAPS_SPOOF:
	case HYMO_IOC_SET_STATFS_SPOOF:
	case HYMO_IOC_ADD_SPOOF_KSTAT:
	case HYMO_IOC_UPDATE_SPOOF_KSTAT:
		ret = hymo_dispatch_cmd(cmd, (void __user *)arg);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	atomic_long_set(&hymo_ioctl_tgid, 0);
	return ret;
}

/* ======================================================================
 * Part 17: Anonymous fd (no device node; syscall returns this fd)
 * ====================================================================== */

static const struct file_operations hymo_anon_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = hymofs_dev_ioctl,
	.compat_ioctl   = hymofs_dev_ioctl,
	.llseek         = noop_llseek,
};

/**
 * hymofs_get_anon_fd - Create and return anonymous fd for HymoFS.
 * Returns fd on success, negative errno on failure.
 */
int hymofs_get_anon_fd(void)
{
	int fd;
	pid_t pid;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -EPERM;
	fd = anon_inode_getfd("hymo", &hymo_anon_fops, NULL, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fd;
	pid = task_tgid_vnr(current);
	WRITE_ONCE(hymo_daemon_pid, pid);
	hymo_log("Daemon PID auto-registered: %d\n", pid);
	return fd;
}
EXPORT_SYMBOL_GPL(hymofs_get_anon_fd);
