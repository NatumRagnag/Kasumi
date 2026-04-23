/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - VFS-facing path, stat, xattr, and iterate_dir hook implementations.
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
#include "hymofs_entrypoints.h"
#include "hymofs_path_policy.h"
#include "hymofs_overlay.h"
#include "hymofs_vfs_hooks.h"
#include "hymofs_proc_hooks.h"
#include "hymofs_tracepoint_hooks.h"
#include "hymofs_ftrace_hooks.h"
#include "hymofs_fake_mountinfo.h"
#include "hymofs_iop_override.h"

#ifndef HYMOFS_VFS_KPROBES
#define HYMOFS_VFS_KPROBES 1
#endif

#define HYMO_MAGIC_POS 0x1000000000000000ULL
/* ======================================================================
 * iterate_dir: filldir filter (runs in fs callback context, not kprobe)
 * ====================================================================== */

HYMO_NOCFI HYMO_FILLDIR_RET_TYPE
hymofs_filldir_filter(struct dir_context *ctx, const char *name,
		      int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymofs_filldir_wrapper *w =
		container_of(ctx, struct hymofs_filldir_wrapper, wrap_ctx);
	HYMO_FILLDIR_RET_TYPE ret;

	/* Inject phase: before first real entry, emit entries from merge targets
	 * and hymo_paths into the directory listing. */
	if (w->dir_has_inject && !w->inject_done && w->dir_path && w->parent_dentry) {
		struct list_head head;
		struct hymo_name_list *item, *tmp;
		loff_t inj_pos = HYMO_MAGIC_POS;

		w->inject_done = true;
		INIT_LIST_HEAD(&head);
		hymofs_populate_injected_list(w->dir_path, w->parent_dentry, &head);

		list_for_each_entry_safe(item, tmp, &head, list) {
			int nlen = strlen(item->name);
			if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
				break;
			ret = w->orig_ctx->actor(w->orig_ctx, item->name, nlen,
						 inj_pos, 1, item->type);
			list_del(&item->list);
			kfree(item->name);
			kfree(item);
			if (ret != HYMO_FILLDIR_CONTINUE) {
				list_for_each_entry_safe(item, tmp, &head, list) {
					list_del(&item->list);
					kfree(item->name);
					kfree(item);
				}
				return ret;
			}
			inj_pos++;
		}
	}

	if (unlikely(namlen <= 2 && name[0] == '.')) {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			goto passthrough;
	}

	if (hymo_stealth_enabled && w->dir_path_len == 4) {
		size_t mlen = strlen(hymo_current_mirror_name);
		if ((unsigned int)namlen == mlen &&
		    memcmp(name, hymo_current_mirror_name, namlen) == 0)
			return HYMO_FILLDIR_CONTINUE;
	}

	/* Hide real entries that also exist in merge targets. This prevents
	 * duplicates: the injected version (from populate_injected_list)
	 * replaces the original, just like original hymofs.c does.
	 * Skip when merge target IS the dir we're listing (e.g. target path
	 * resolved to same inode via symlink) - otherwise we'd hide everything.
	 * Must respect allowlist: privileged/allowlist processes see real files. */
	if (hymo_d_hash_and_lookup && w->merge_target_count > 0 && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		int i;
		for (i = 0; i < w->merge_target_count; i++) {
			struct dentry *tgt = w->merge_target_dentries[i];
			if (!tgt || tgt == w->parent_dentry)
				continue;
			if (d_inode(tgt) && d_inode(tgt) == d_inode(w->parent_dentry))
				continue;
			{
				struct dentry *child = hymo_d_hash_and_lookup(tgt,
					&(struct qstr)QSTR_INIT(name, namlen));
				if (child) {
					dput(child);
					return HYMO_FILLDIR_CONTINUE;
				}
			}
		}
	}

	if (hymo_d_hash_and_lookup && w->dir_has_hidden && w->parent_dentry &&
	    !hymo_is_privileged_process() && hymo_should_apply_hide_rules()) {
		struct dentry *child;

		child = hymo_d_hash_and_lookup(w->parent_dentry,
				&(struct qstr)QSTR_INIT(name, namlen));
		if (child) {
			struct inode *cinode = d_inode(child);
			if (cinode && cinode->i_mapping &&
			    test_bit(AS_FLAGS_HYMO_HIDE,
				     &cinode->i_mapping->flags)) {
				dput(child);
				return HYMO_FILLDIR_CONTINUE;
			}
			dput(child);
		}
	}

passthrough:
	if (unlikely(!w->orig_ctx || !w->orig_ctx->actor))
		return HYMO_FILLDIR_CONTINUE;
	return w->orig_ctx->actor(w->orig_ctx, name, namlen, offset, ino, d_type);
}

/* ======================================================================
 * Kprobe pre_handlers (modify regs / user path only; return 0 to run original)
 * ====================================================================== */

#if defined(__aarch64__)
#define HYMO_REG0(regs)		((regs)->regs[0])
#define HYMO_REG1(regs)		((regs)->regs[1])
#define HYMO_REG2(regs)		((regs)->regs[2])
#define HYMO_REG3(regs)		((regs)->regs[3])
#define HYMO_REG4(regs)		((regs)->regs[4])
#define HYMO_LR(regs)		((regs)->regs[30])
#define HYMO_POP_STACK(regs)	do { } while (0)
#elif defined(__x86_64__)
#define HYMO_REG0(regs)		((regs)->di)
#define HYMO_REG1(regs)		((regs)->si)
#define HYMO_REG2(regs)		((regs)->dx)
#define HYMO_REG3(regs)		((regs)->cx)
#define HYMO_REG4(regs)		((regs)->r8)
#define HYMO_LR(regs)		(*(unsigned long *)(regs)->sp)
#define HYMO_POP_STACK(regs)	do { (regs)->sp += 8; } while (0)
#elif defined(__arm__)
/* ARM32: pt_regs uses uregs[] (r0=0, r1=1, ..., lr=14, pc=15) */
#define HYMO_REG0(regs)		((regs)->uregs[0])
#define HYMO_REG1(regs)		((regs)->uregs[1])
#define HYMO_REG2(regs)		((regs)->uregs[2])
#define HYMO_REG3(regs)		((regs)->uregs[3])
#define HYMO_REG4(regs)		((regs)->uregs[4])
#define HYMO_LR(regs)		((regs)->uregs[14])
#define HYMO_POP_STACK(regs)	do { } while (0)
#else
#define HYMO_REG0(regs)		(0)
#define HYMO_REG1(regs)		(0)
#define HYMO_REG2(regs)		(0)
#define HYMO_REG3(regs)		(0)
#define HYMO_REG4(regs)		(0)
#define HYMO_LR(regs)		(0)
#define HYMO_POP_STACK(regs)	do { } while (0)
#endif

/* Path register pointer for syscall tracepoint (avoids u64* vs unsigned long* across archs) */
#if defined(__aarch64__) || defined(__x86_64__)
#define HYMO_PATH_REG_PTR(regs, id)  ((u64 *)((id) == __NR_execve ? &HYMO_REG0(regs) : &HYMO_REG1(regs)))
#define HYMO_PATH_REG_VAL(p)         ((u64)(uintptr_t)(p))
#else
#define HYMO_PATH_REG_PTR(regs, id)  ((unsigned long *)((id) == __NR_execve ? &HYMO_REG0(regs) : &HYMO_REG1(regs)))
#define HYMO_PATH_REG_VAL(p)         ((unsigned long)(uintptr_t)(p))
#endif

/*
 * vfs_getattr / vfs_getxattr argument positions.
 *
 * Upstream Linux added an idmap arg to vfs_getattr in 5.12, but Android GKI
 * kernels (verified across 5.10/5.15/6.1/6.6/6.12) keep the original 4-arg
 * signature `vfs_getattr(path, stat, mask, flags)`. So the upstream version
 * gate was wrong for every Android target — always shifted args by one and
 * silently early-exited on `!p->dentry`. Hardcode the 4-arg layout instead.
 */
#define HYMO_GETATTR_PATH_REG(regs) HYMO_REG0(regs)
#define HYMO_GETATTR_STAT_REG(regs) HYMO_REG1(regs)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0))
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG1(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG2(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG3(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG4(regs)
#else
#define HYMO_GETXATTR_DENTRY_REG(regs) HYMO_REG0(regs)
#define HYMO_GETXATTR_NAME_REG(regs)   HYMO_REG1(regs)
#define HYMO_GETXATTR_VALUE_REG(regs)  HYMO_REG2(regs)
#define HYMO_GETXATTR_SIZE_REG(regs)   HYMO_REG3(regs)
#endif

/*
 * Atomic-safe user access for kprobe pre-handler (cannot sleep).
 * copy_from_user/copy_to_user may sleep on page fault -> use nofault variants.
 * Resolved dynamically via kallsyms (not exported on GKI).
 */
#include <linux/sched/task_stack.h>

#define HYMO_HIDE_PATH "/.hymo_hidden_placeholder"

static char __user *hymo_userspace_stack_buffer(const char *data, size_t len)
{
	char __user *p;

	if (!current->mm)
		return NULL;
	p = (void __user *)current_user_stack_pointer() - len;
	return copy_to_user(p, data, len) ? NULL : p;
}

static inline bool hymo_tp_check_path_syscall(long id)
{
	switch (id) {
	case __NR_openat:
	case __NR_faccessat:
#ifdef __NR_newfstatat
	case __NR_newfstatat:
#endif
	case __NR_execve:
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_openat2
	case __NR_openat2:
#endif
		return true;
	default:
		return false;
	}
}

void hymofs_handle_sys_enter_getfd(struct pt_regs *regs, long id)
{
#if defined(__aarch64__)
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
	unsigned long a3 = regs->regs[3];
#elif defined(__x86_64__)
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
	unsigned long a3 = regs->r10;
#elif defined(__arm__)
	unsigned long a0 = regs->uregs[0];
	unsigned long a1 = regs->uregs[1];
	unsigned long a2 = regs->uregs[2];
	unsigned long a3 = regs->uregs[3];
#else
	return;
#endif
	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return;

	/* reboot: magic + put_user via 4th arg */
	if (id == __NR_reboot && a0 == HYMO_MAGIC1 && a1 == HYMO_MAGIC2 && a2 == (unsigned long)HYMO_CMD_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a3;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* prctl: option=HYMO_PRCTL_GET_FD, arg2=fd_ptr */
	if (id == __NR_prctl && a0 == (unsigned long)HYMO_PRCTL_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			int __user *fd_ptr = (int __user *)(unsigned long)a1;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
		return;
	}
	/* ni_syscall: set per-cpu for sys_exit to replace return value */
	if (id == (long)hymo_syscall_nr_param && a0 == HYMO_MAGIC1 && a1 == HYMO_MAGIC2 && a2 == (unsigned long)HYMO_CMD_GET_FD) {
		int fd = hymofs_get_anon_fd();
		if (fd >= 0) {
			hymo_this_cpu()->override_fd = fd;
			hymo_this_cpu()->override_active = 1;
		}
	}
}

void hymofs_handle_sys_exit_getfd(struct pt_regs *regs, long ret)
{
	(void)ret;
	if (!hymo_this_cpu()->override_active)
		return;
#if defined(__aarch64__)
	regs->regs[0] = hymo_this_cpu()->override_fd;
#elif defined(__x86_64__)
	regs->ax = hymo_this_cpu()->override_fd;
#elif defined(__arm__)
	regs->uregs[0] = hymo_this_cpu()->override_fd;
#endif
	hymo_this_cpu()->override_active = 0;
}

#if defined(__aarch64__) || defined(__x86_64__)
/* Cmdline spoof: check if fd refers to /proc/cmdline (tracepoint + kretprobe path) */
static bool hymo_fd_is_proc_cmdline(int fd)
{
	struct file *file;
	struct dentry *dentry, *parent;
	bool is_cmdline = false;

	file = fget(fd);
	if (!file)
		return false;
	dentry = file->f_path.dentry;
	parent = dentry ? dentry->d_parent : NULL;
	if (dentry && dentry->d_name.len == 7 &&
	    memcmp(dentry->d_name.name, "cmdline", 7) == 0 && parent) {
		/* Parent is "proc" dir or proc root (empty name) */
		if ((parent->d_name.len == 5 && memcmp(parent->d_name.name, "proc", 5) == 0) ||
		    parent->d_name.len == 0)
			is_cmdline = true;
	}
	fput(file);
	return is_cmdline;
}
#endif

void hymofs_handle_sys_enter_cmdline(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	unsigned long fd, buf, count;

	if (!hymo_cmdline_spoof_active)
		return;
	if (id != __NR_read)
		return;
	if (READ_ONCE(hymo_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(hymo_daemon_pid))
		return;

#if defined(__aarch64__)
	fd = regs->regs[0];
	buf = regs->regs[1];
	count = regs->regs[2];
#else
	fd = regs->di;
	buf = regs->si;
	count = regs->dx;
#endif

	if (!hymo_fd_is_proc_cmdline((int)fd))
		return;

	hymo_this_cpu()->cmdline_ctx.buf = (char __user *)buf;
	hymo_this_cpu()->cmdline_ctx.count = (size_t)count;
	hymo_this_cpu()->cmdline_ctx.active = 1;
#endif
}

void hymofs_handle_sys_exit_cmdline(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct hymo_percpu *pcpu = hymo_this_cpu();
	size_t spoof_len, write_len;

	if (!pcpu->cmdline_ctx.active || ret <= 0)
		goto out;
	pcpu->cmdline_ctx.active = 0;

	if (!READ_ONCE(hymo_cmdline_spoof_active))
		goto out;

	rcu_read_lock();
	{
		struct hymo_cmdline_rcu *c = rcu_dereference(hymo_spoof_cmdline_ptr);
		if (!c || !c->cmdline[0]) {
			rcu_read_unlock();
			goto out;
		}
		spoof_len = strnlen(c->cmdline, sizeof(c->cmdline) - 1);
		/* Original cmdline ends with \n; match that */
		write_len = spoof_len + 1; /* +1 for \n */
		if (write_len > pcpu->cmdline_ctx.count)
			write_len = pcpu->cmdline_ctx.count;
		if (write_len > 0) {
			size_t n = (spoof_len < write_len) ? spoof_len : write_len - 1;
			if (copy_to_user(pcpu->cmdline_ctx.buf, c->cmdline, n) == 0) {
				if (n < write_len && copy_to_user(pcpu->cmdline_ctx.buf + n, "\n", 1) == 0)
					write_len = n + 1;
				else
					write_len = n;
#if defined(__aarch64__)
				regs->regs[0] = (unsigned long)write_len;
#else
				regs->ax = (unsigned long)write_len;
#endif
			}
		}
	}
	rcu_read_unlock();
out:
	(void)0;
#endif
}

void hymofs_handle_sys_enter_statx(struct pt_regs *regs, long id)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct hymo_percpu *pcpu = hymo_this_cpu();
	const char __user *filename_user;
	unsigned long buf_ptr;
	char *path;

	pcpu->statx_ctx.active = 0;
	if (id != __NR_statx)
		return;
	if (!(hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) ||
	    !hymo_should_apply_hide_rules())
		return;

#if defined(__aarch64__)
	filename_user = (const char __user *)(uintptr_t)regs->regs[1];
	buf_ptr = regs->regs[4];
#else
	filename_user = (const char __user *)(uintptr_t)regs->si;
	buf_ptr = regs->r8;
#endif
	if (!filename_user || !buf_ptr)
		return;

	path = pcpu->statx_ctx.path;
	if (hymo_strncpy_from_user_nofault) {
		long n = hymo_strncpy_from_user_nofault(path, filename_user,
							HYMO_MAX_LEN_PATHNAME - 1);
		if (n < 0)
			return;
		path[n < (long)(HYMO_MAX_LEN_PATHNAME - 1) ? n :
		     (long)(HYMO_MAX_LEN_PATHNAME - 1)] = '\0';
	} else {
		if (copy_from_user(path, filename_user, HYMO_MAX_LEN_PATHNAME - 1))
			return;
		path[HYMO_MAX_LEN_PATHNAME - 1] = '\0';
	}

	if (path[0] != '/')
		return;

	pcpu->statx_ctx.buf = (struct statx __user *)(uintptr_t)buf_ptr;
	pcpu->statx_ctx.active = 1;
#else
	(void)regs;
	(void)id;
#endif
}

void hymofs_handle_sys_exit_statx(struct pt_regs *regs, long ret)
{
#if defined(__aarch64__) || defined(__x86_64__)
	struct hymo_percpu *pcpu = hymo_this_cpu();
	struct statx stx;
	int fake_mnt_id;

	(void)regs;
	if (!pcpu->statx_ctx.active)
		return;
	pcpu->statx_ctx.active = 0;
	if (ret != 0 || !pcpu->statx_ctx.buf)
		return;

	fake_mnt_id = hymo_fake_mi_lookup_mount_id(pcpu->statx_ctx.path);
	if (fake_mnt_id <= 0)
		return;
	if (copy_from_user(&stx, pcpu->statx_ctx.buf, sizeof(stx)) != 0)
		return;

	stx.stx_mnt_id = (u64)fake_mnt_id;
	if (copy_to_user(pcpu->statx_ctx.buf, &stx, sizeof(stx)) != 0)
		return;

	hymo_log("statx spoof: path=%s fake_mnt_id=%d pid=%d comm=%s\n",
		 pcpu->statx_ctx.path, fake_mnt_id,
		 task_pid_nr(current), current->comm);
#else
	(void)regs;
	(void)ret;
#endif
}

void hymofs_handle_sys_exit_path(struct pt_regs *regs, long ret)
{
	struct hymo_percpu *pcpu = hymo_this_cpu();

	(void)regs;
	if (!pcpu->mount_proxy_pending)
		return;

	pcpu->mount_proxy_pending = 0;
	if (ret < 0)
		return;

	(void)hymo_mount_proxy_install_fd((int)ret);
}

void hymofs_handle_sys_enter_path(struct pt_regs *regs, long id)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	char __user *new_path;
	bool check_mount_proxy = false;
	bool have_path_filters;

	if (!hymo_tp_check_path_syscall(id))
		return;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return;
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return;
	hymo_this_cpu()->mount_proxy_pending = 0;
	check_mount_proxy = (hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) &&
			    (id == __NR_openat
#ifdef __NR_openat2
			     || id == __NR_openat2
#endif
			    );
	have_path_filters = atomic_read(&hymo_rule_count) != 0 ||
			    atomic_read(&hymo_hide_count) != 0;
	/* Fast path: no path filters and no mount view fd wrapping need. */
	if (likely(!have_path_filters && !check_mount_proxy))
		return;

	filename_user = (const char __user *)(uintptr_t)*HYMO_PATH_REG_PTR(regs, id);
	if (!filename_user)
		return;

	buf = hymo_getname_buf_base + (smp_processor_id() * HYMO_PATH_BUF);
	if (hymo_strncpy_from_user_nofault) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (long)(HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	if (check_mount_proxy && buf[0] == '/' &&
	    hymo_path_is_proc_mountinfo(buf) &&
	    hymo_should_apply_hide_rules()) {
		int prep_rc;
		hymo_log("mount_proxy: arm pid=%d comm=%s path=%s\n",
			 task_pid_nr(current), current->comm, buf);
		hymo_this_cpu()->mount_proxy_pending = 1;
		prep_rc = hymo_fake_mi_prepare(false);
		hymo_log("mount_proxy: prepare pid=%d comm=%s rc=%d\n",
			 task_pid_nr(current), current->comm, prep_rc);
	}

	if (!have_path_filters)
		return;

	if (unlikely(hymofs_should_hide(buf))) {
		new_path = hymo_userspace_stack_buffer(HYMO_HIDE_PATH, sizeof(HYMO_HIDE_PATH));
		if (new_path)
			*HYMO_PATH_REG_PTR(regs, id) = HYMO_PATH_REG_VAL(new_path);
		return;
	}

	if (buf[0] != '/')
		return;
	target = hymofs_resolve_target(buf);
	if (!target)
		return;
	{
		size_t tlen = strlen(target) + 1;
		if (tlen > HYMO_PATH_BUF) {
			kfree(target);
			return;
		}
		new_path = hymo_userspace_stack_buffer(target, tlen);
		kfree(target);
		if (new_path)
			*HYMO_PATH_REG_PTR(regs, id) = HYMO_PATH_REG_VAL(new_path);
	}
}

/* getname_flags pre-handler: only modify user path and regs; return 0 to run original. */
static HYMO_NOCFI int hymo_kp_getname_flags_pre(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename_user;
	char *buf;
	char *target;
	bool check_mountinfo_prime;
	bool have_path_filters;

	(void)p;

	if (hymo_this_cpu()->kprobe_reent)
		return 0;
	/* Skip when current is in ioctl path resolution (avoids reent / deadlock with metamount+hymod). */
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	/* Skip when resolving source path for xattr spoofing (need unredirected path). */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;
	check_mountinfo_prime = (hymo_feature_enabled_mask & HYMO_FEATURE_MOUNT_HIDE) != 0;
	have_path_filters = atomic_read(&hymo_rule_count) != 0 ||
			    atomic_read(&hymo_hide_count) != 0;
	/* Fast path: no path filters and no mountinfo prewarm need. */
	if (likely(!have_path_filters && !check_mountinfo_prime))
		return 0;

	filename_user = (const char __user *)HYMO_REG0(regs);
	if (!filename_user)
		return 0;

	buf = hymo_getname_buf_base + (smp_processor_id() * HYMO_PATH_BUF);
	if (hymo_strncpy_from_user_nofault) {
		long ret = hymo_strncpy_from_user_nofault(buf, filename_user, HYMO_PATH_BUF - 1);
		if (ret < 0)
			return 0;
		buf[ret < (long)(HYMO_PATH_BUF - 1) ? ret : (HYMO_PATH_BUF - 1)] = '\0';
	} else {
		if (copy_from_user(buf, filename_user, HYMO_PATH_BUF - 1))
			return 0;
		buf[HYMO_PATH_BUF - 1] = '\0';
	}

	if (check_mountinfo_prime && buf[0] == '/' &&
	    hymo_path_is_proc_mountinfo(buf) &&
	    hymo_should_apply_hide_rules())
		(void)hymo_fake_mi_prepare(false);

	if (!have_path_filters)
		return 0;

	/* Hide: skip original and return error (no putname needed) */
	if (unlikely(hymofs_should_hide(buf))) {
		hymo_this_cpu()->kprobe_reent = 1;
		HYMO_REG0(regs) = (unsigned long)ERR_PTR(-ENOENT);
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
#if defined(__x86_64__)
		regs->ax = (unsigned long)ERR_PTR(-ENOENT);
#endif
		hymo_this_cpu()->kprobe_reent = 0;
		return 1;
	}

	/* Redirect: use getname_kernel to build a struct filename from the target
	 * path, then skip the original getname_flags entirely.  This avoids
	 * writing back to user memory (which may be read-only, too small, or
	 * cause PAN/MTE faults in atomic context). */
	if (buf[0] != '/')
		return 0;
	target = hymofs_resolve_target(buf);
	if (!target)
		return 0;
	if (hymo_getname_kernel) {
		struct filename *fname;

		hymo_this_cpu()->kprobe_reent = 1;
		fname = hymo_getname_kernel(target);
		hymo_this_cpu()->kprobe_reent = 0;
		kfree(target);
		if (IS_ERR(fname))
			return 0;
		HYMO_REG0(regs) = (unsigned long)fname;
		instruction_pointer_set(regs, HYMO_LR(regs));
		HYMO_POP_STACK(regs);
		return 1;
	}
	kfree(target);
	return 0;
}

/* vfs_getattr kprobe pre: nop (stat spoofing is done in kretprobe entry/ret). */
static int hymo_kp_vfs_getattr_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * vfs_getattr kretprobe entry: resolve path, check hymo_targets.
 * Uses ri->data (migration-safe) instead of per-CPU storage.
 */
HYMO_NOCFI int hymo_krp_vfs_getattr_entry(struct kretprobe_instance *ri,
						  struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	const struct path *p;
	char buf[256];
	char *dp;

	d->is_target = false;
	d->stat = NULL;
	d->mapping = NULL;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (hymo_this_cpu()->in_populate_inject)
		return 0;
	if (atomic_read(&hymo_rule_count) == 0 &&
	    atomic_read(&hymo_spoof_kstat_count) == 0)
		return 0;

	p = (const struct path *)HYMO_GETATTR_PATH_REG(regs);
	d->stat = (struct kstat *)HYMO_GETATTR_STAT_REG(regs);

	if (!p || !p->dentry || !d->stat)
		return 0;

	if (d_inode(p->dentry) && d_inode(p->dentry)->i_mapping)
		d->mapping = d_inode(p->dentry)->i_mapping;

	/* Fast path: inode already marked from a previous redirect match */
	if (d->mapping && test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &d->mapping->flags)) {
		/* If shadow i_op is installed, it will spoof inline — skip the
		 * ret handler entirely to avoid redundant work. */
		if (test_bit(AS_FLAGS_HYMO_IOP_INSTALLED, &d->mapping->flags))
			return -1;
		d->is_target = true;
		return 0;
	}

	dp = ERR_PTR(-ENOENT);
	if (hymo_d_absolute_path)
		dp = hymo_d_absolute_path(p, buf, sizeof(buf));
	if (IS_ERR(dp) && hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(p->dentry, buf, sizeof(buf));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	if (hymofs_reverse_lookup_target(dp) ||
	    hymofs_spoof_kstat_lookup_by_path(dp))
		d->is_target = true;
	if (!d->is_target && d_inode(p->dentry)) {
		struct inode *ino = d_inode(p->dentry);
		if (hymofs_spoof_kstat_lookup_by_ino(
			(unsigned long)ino->i_ino,
			ino->i_sb ? (unsigned long)ino->i_sb->s_dev : 0))
			d->is_target = true;
	}
	rcu_read_unlock();

	return 0;
}

/*
 * vfs_getattr kretprobe ret: spoof kstat for redirect targets.
 * Makes the file appear to belong to /system with root ownership.
 */
/*
 * Apply kstat spoofing in place. Shared by:
 *   - vfs_getattr kretprobe ret handler (legacy slow path)
 *   - hymo_shadow_getattr in hymofs_iop_override.c (fast path after install)
 *
 * Note: `inode` may be NULL for the legacy path (we still have stat / mapping
 * via the kretprobe ri data); the shadow path always provides it.
 */
void hymo_apply_kstat_spoof(struct inode *inode, struct kstat *stat)
{
	struct hymo_spoof_kstat_entry *e = NULL;

	if (!stat)
		return;

	/* Explicit per-inode spoof rule (api15) takes precedence. */
	if (inode && atomic_read(&hymo_spoof_kstat_count) > 0) {
		rcu_read_lock();
		e = hymofs_spoof_kstat_lookup_by_ino((unsigned long)inode->i_ino,
						     (unsigned long)stat->dev);
		if (e) {
			if (e->spoofed_dev)        stat->dev = e->spoofed_dev;
			if (e->spoofed_ino)        stat->ino = e->spoofed_ino;
			if (e->spoofed_nlink)      stat->nlink = e->spoofed_nlink;
			if (e->spoofed_size)       stat->size = e->spoofed_size;
			if (e->spoofed_blksize)    stat->blksize = e->spoofed_blksize;
			if (e->spoofed_blocks)     stat->blocks = e->spoofed_blocks;
			if (e->spoofed_atime_sec || e->spoofed_atime_nsec) {
				stat->atime.tv_sec  = e->spoofed_atime_sec;
				stat->atime.tv_nsec = e->spoofed_atime_nsec;
			}
			if (e->spoofed_mtime_sec || e->spoofed_mtime_nsec) {
				stat->mtime.tv_sec  = e->spoofed_mtime_sec;
				stat->mtime.tv_nsec = e->spoofed_mtime_nsec;
			}
			if (e->spoofed_ctime_sec || e->spoofed_ctime_nsec) {
				stat->ctime.tv_sec  = e->spoofed_ctime_sec;
				stat->ctime.tv_nsec = e->spoofed_ctime_nsec;
			}
		}
		rcu_read_unlock();
	}

	if (!e) {
		/* Generic fallback: piggyback on add_rule redirect targets. */
		if (hymo_system_dev)
			stat->dev = hymo_system_dev;
		stat->ino = (u64)jhash(stat, sizeof(stat->ino), 0x48594D4F) | 0x100000ULL;
		if (S_ISREG(stat->mode))
			stat->nlink = 1;
	}

	stat->uid = GLOBAL_ROOT_UID;
	stat->gid = GLOBAL_ROOT_GID;

	hymo_log("kstat: spoofed ino %lu (explicit=%d)\n",
		 (unsigned long)stat->ino, e ? 1 : 0);

	if (inode && inode->i_mapping)
		set_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags);
}

int hymo_krp_vfs_getattr_ret(struct kretprobe_instance *ri,
				    struct pt_regs *regs)
{
	struct hymo_getattr_ri_data *d = (void *)ri->data;
	int ret_val;

	if (!d->is_target || !d->stat)
		return 0;

#if defined(__aarch64__)
	ret_val = (int)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (int)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val != 0)
		return 0;

	{
		struct inode *inode = d->mapping ? d->mapping->host : NULL;
		hymo_apply_kstat_spoof(inode, d->stat);
		/*
		 * Lookup-time i_op install: after first successful spoof,
		 * install a shadow inode_operations so future stat()s go
		 * through an indirect call instead of trapping into this
		 * kprobe. Safe to call repeatedly (idempotent).
		 */
		if (inode)
			hymofs_iop_install(inode);
	}

	return 0;
}

/*
 * Get SELinux context from a path (used for source path when spoofing).
 * Bypass must be set (hymo_xattr_source_tgid) so path resolution is not redirected.
 * Returns length of context string (excl. NUL) or negative on error.
 */
static HYMO_NOCFI ssize_t hymo_get_selinux_ctx_from_path(struct path *path, char *buf, size_t buflen)
{
	if (!hymo_vfs_getxattr_addr || buflen < 2)
		return -ENOENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_idmap(path->mnt), path->dentry, "security.selinux", buf, buflen);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	return ((ssize_t (*)(void *, struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		mnt_user_ns(path->mnt), path->dentry, "security.selinux", buf, buflen);
#else
	return ((ssize_t (*)(struct dentry *, const char *, void *, size_t))hymo_vfs_getxattr_addr)(
		path->dentry, "security.selinux", buf, buflen);
#endif
}

/*
 * vfs_getxattr kretprobe entry: check if querying security.selinux on a
 * redirect target.  Resolves source path and reads its actual SELinux context
 * from the mounted directory (no hardcoding).
 */
HYMO_NOCFI int hymo_krp_vfs_getxattr_entry(struct kretprobe_instance *ri,
						   struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	struct dentry *dentry;
	const char *xattr_name;
	struct inode *inode;
	char *tmp;  /* heap to avoid arm32 frame-larger-than=1024 */
	char *dp;
	struct hymo_entry *entry;
	struct path src_path;
	ssize_t ret;

	d->spoof_selinux = false;
	d->value_buf = NULL;
	d->value_size = 0;
	d->src_ctx[0] = '\0';
	d->src_ctx_len = 0;

	/* Skip when we're in the inner call (resolving source path's context) */
	if (atomic_long_read(&hymo_xattr_source_tgid) == (long)task_tgid_vnr(current))
		return 0;

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	xattr_name = (const char *)HYMO_GETXATTR_NAME_REG(regs);
	if (!xattr_name)
		return 0;
	if (strcmp(xattr_name, "security.selinux") != 0)
		return 0;

	dentry = (struct dentry *)HYMO_GETXATTR_DENTRY_REG(regs);
	if (!dentry)
		return 0;

	inode = d_inode(dentry);
	if (!inode || !inode->i_mapping)
		return 0;
	if (!test_bit(AS_FLAGS_HYMO_SPOOF_KSTAT, &inode->i_mapping->flags))
		return 0;

	tmp = kmalloc(256 + 256 + 256 + 256 + 512, GFP_KERNEL);
	if (!tmp)
		return 0;

	/* Resolve target path for reverse lookup. dentry_path_raw gives path
	 * relative to fs root; try full path and /data + rel for common Android layout. */
	dp = ERR_PTR(-ENOENT);
	if (hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(dentry, tmp, 256);
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		goto out_free;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (!entry && dp[0] == '/' && dp[1] != '\0') {
		if (snprintf(tmp + 256, 256, "/data%s", dp) < 256)
			entry = hymofs_reverse_lookup_target(tmp + 256);
	}
	rcu_read_unlock();
	if (!entry || !entry->src)
		goto out_free;

	/* Resolve source path (bypass redirect) and get its actual SELinux context.
	 * When source file doesn't exist (e.g. overlay dir is empty), try parent
	 * directories. Use d_absolute_path on resolved parent to get symlink-resolved
	 * path (e.g. /system/product -> /product), then try resolved+remainder. */
	atomic_long_set(&hymo_xattr_source_tgid, (long)task_tgid_vnr(current));
	if (hymo_kern_path) {
		char *parent = tmp + 512;
		char *resolved = tmp + 768;
		char *alt = tmp + 1024;
		const char *try_path = entry->src;
		size_t len = strlen(entry->src);
		size_t parent_len;

		while (try_path && len > 1) {
			/* Try logical path (LOOKUP_FOLLOW resolves symlinks) */
			if (hymo_kern_path(try_path, LOOKUP_FOLLOW, &src_path) == 0) {
				ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
				path_put(&src_path);
				if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			/* Logical path failed: try parent, get resolved path via d_absolute_path,
			 * then try resolved+remainder (handles any symlink, not just /system/product). */
			if (len >= 256)
				break;
			memcpy(parent, try_path, len + 1);
			{
				char *slash = strrchr(parent, '/');
				if (!slash || slash == parent)
					break;
				*slash = '\0';
				parent_len = slash - parent;
			}
			if (hymo_kern_path(parent, LOOKUP_FOLLOW, &src_path) == 0) {
				char *res = NULL;
				bool got_ctx = false;
				if (hymo_d_absolute_path)
					res = hymo_d_absolute_path(&src_path, resolved, 256);
				if (IS_ERR_OR_NULL(res) && hymo_dentry_path_raw)
					res = hymo_dentry_path_raw(src_path.dentry, resolved, 256);
				if (res && !IS_ERR(res) && res[0] == '/' &&
				    parent_len < len && try_path[parent_len] == '/') {
					const char *remainder = try_path + parent_len;
					if (snprintf(alt, 512, "%s%s", res, remainder) < 512 &&
					    strcmp(alt, try_path) != 0) {
						struct path alt_path;
						if (hymo_kern_path(alt, LOOKUP_FOLLOW, &alt_path) == 0) {
							ret = hymo_get_selinux_ctx_from_path(&alt_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
							path_put(&alt_path);
							if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
								got_ctx = true;
						}
					}
				}
				if (!got_ctx) {
					ret = hymo_get_selinux_ctx_from_path(&src_path, d->src_ctx, HYMO_SELINUX_CTX_MAX);
					if (ret > 0 && (size_t)ret < HYMO_SELINUX_CTX_MAX)
						got_ctx = true;
				}
				path_put(&src_path);
				if (got_ctx) {
					d->src_ctx_len = (size_t)ret;
					d->src_ctx[d->src_ctx_len] = '\0';
					d->spoof_selinux = true;
					break;
				}
			}
			try_path = parent;
			len = parent_len;
		}
	}
	atomic_long_set(&hymo_xattr_source_tgid, 0);

	d->value_buf = (void *)HYMO_GETXATTR_VALUE_REG(regs);
	d->value_size = (size_t)HYMO_GETXATTR_SIZE_REG(regs);

out_free:
	kfree(tmp);
	return 0;
}

/*
 * vfs_getxattr kretprobe ret: overwrite value buffer with source path's
 * actual SELinux context (from entry handler) and fix return value.
 */
int hymo_krp_vfs_getxattr_ret(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct hymo_getxattr_ri_data *d = (void *)ri->data;
	long ret_val;
	size_t ctx_len;

	if (!d->spoof_selinux || !d->value_buf || !d->src_ctx_len)
		return 0;

#if defined(__aarch64__)
	ret_val = (long)regs->regs[0];
#elif defined(__x86_64__)
	ret_val = (long)regs->ax;
#else
	ret_val = 0;
#endif
	if (ret_val <= 0)
		return 0;

	ctx_len = d->src_ctx_len + 1; /* include NUL */
	if (d->value_size < ctx_len)
		return 0;
	memcpy(d->value_buf, d->src_ctx, ctx_len);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)d->src_ctx_len;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)d->src_ctx_len;
#endif

	return 0;
}

/* d_path: kprobe pre now a nop; entry handler below does the real work. */
static int hymo_kp_d_path_pre(struct kprobe *p, struct pt_regs *regs)
{
	(void)p; (void)regs;
	return 0;
}

/*
 * d_path kretprobe entry: save buf/buflen from regs, resolve the struct path
 * to see if it's a redirect target.  d_path signature:
 *   char *d_path(const struct path *path, char *buf, int buflen)
 */
HYMO_NOCFI int hymo_krp_d_path_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	const struct path *p;
	char tmp[256];
	char *dp;
	struct hymo_entry *entry;

	d->is_target = false;
	d->buf = (char *)HYMO_REG1(regs);
	d->buflen = (int)HYMO_REG2(regs);
	d->src_path[0] = '\0';

	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (atomic_read(&hymo_rule_count) == 0)
		return 0;

	p = (const struct path *)HYMO_REG0(regs);
	if (!p || !p->dentry)
		return 0;

	dp = ERR_PTR(-ENOENT);
	if (hymo_d_absolute_path)
		dp = hymo_d_absolute_path(p, tmp, sizeof(tmp));
	if (IS_ERR(dp) && hymo_dentry_path_raw)
		dp = hymo_dentry_path_raw(p->dentry, tmp, sizeof(tmp));
	if (IS_ERR_OR_NULL(dp) || dp[0] != '/')
		return 0;

	rcu_read_lock();
	entry = hymofs_reverse_lookup_target(dp);
	if (entry && strlen(entry->src) < HYMO_D_PATH_SRC_MAX) {
		d->is_target = true;
		strscpy(d->src_path, entry->src, HYMO_D_PATH_SRC_MAX);
	}
	rcu_read_unlock();

	return 0;
}

/*
 * d_path kretprobe ret: if the resolved path was a redirect target,
 * overwrite the result so /proc/pid/fd/N shows /system/... instead of
 * /data/adb/modules/xxx/...
 *
 * d_path() returns a pointer INSIDE the caller's buffer (buf + offset).
 * We write the source path into the buffer from the end and update the
 * return value register to point to the new start.
 */
int hymo_krp_d_path_ret(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct hymo_d_path_ri_data *d = (void *)ri->data;
	char *ret_ptr;
	size_t src_len;
	char *new_start;

	if (!d->is_target || !d->src_path[0] || !d->buf || d->buflen <= 0)
		return 0;

#if defined(__aarch64__)
	ret_ptr = (char *)regs->regs[0];
#elif defined(__x86_64__)
	ret_ptr = (char *)regs->ax;
#else
	ret_ptr = NULL;
#endif
	if (IS_ERR_OR_NULL(ret_ptr))
		return 0;

	src_len = strlen(d->src_path);
	if ((int)src_len + 1 > d->buflen)
		return 0;

	new_start = d->buf + d->buflen - src_len - 1;
	memcpy(new_start, d->src_path, src_len + 1);

#if defined(__aarch64__)
	regs->regs[0] = (unsigned long)new_start;
#elif defined(__x86_64__)
	regs->ax = (unsigned long)new_start;
#endif

	return 0;
}

/*
 * iterate_dir: pre swaps ctx to our wrapper so kernel runs filldir filter.
 * HYMO_NOCFI: indirect calls to hymo_d_absolute_path / hymo_dentry_path_raw.
 */
HYMO_NOCFI int hymo_kp_iterate_dir_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	struct hymofs_filldir_wrapper *w;
	struct dir_context *orig_ctx;
	struct inode *dir_inode;
	const char *dname;

	(void)p;
	hymo_this_cpu()->iterate_did_swap = 0;

	if (atomic_long_read(&hymo_ioctl_tgid) == (long)task_tgid_vnr(current))
		return 0;
	if (hymo_this_cpu()->in_populate_inject)
		return 0;
	if (!READ_ONCE(hymofs_enabled))
		return 0;
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return 0;
	if (READ_ONCE(hymo_daemon_pid) > 0 && task_tgid_vnr(current) == READ_ONCE(hymo_daemon_pid))
		return 0;

	file = (struct file *)HYMO_REG0(regs);
	orig_ctx = (struct dir_context *)HYMO_REG1(regs);
	if (!orig_ctx || !orig_ctx->actor)
		return 0;
	if (orig_ctx->actor == hymofs_filldir_filter)
		return 0;

	w = kmem_cache_zalloc(hymo_filldir_cache, GFP_ATOMIC);
	if (!w)
		return 0;

	w->orig_ctx = orig_ctx;
	w->wrap_ctx.actor = hymofs_filldir_filter;
	w->wrap_ctx.pos = orig_ctx->pos;
	w->parent_dentry = file && file->f_path.dentry ? file->f_path.dentry : NULL;

	if (w->parent_dentry) {
		dir_inode = d_inode(w->parent_dentry);
		if (dir_inode && dir_inode->i_mapping) {
			w->dir_has_hidden = test_bit(AS_FLAGS_HYMO_DIR_HAS_HIDDEN,
						     &dir_inode->i_mapping->flags);
			/* Fast path: if dir has no inject flag, skip rcu_read_lock + hash traversal */
			w->dir_has_inject = test_bit(AS_FLAGS_HYMO_DIR_HAS_INJECT,
						    &dir_inode->i_mapping->flags);
		}
		dname = w->parent_dentry->d_name.name;
		if (dname[0] == 'd' && dname[1] == 'e' && dname[2] == 'v' && dname[3] == '\0')
			w->dir_path_len = 4;

		/*
		 * Only when dir_has_inject (from flag) is true: build full path and
		 * traverse hash to get merge_target_dentries. Most dirs skip this.
		 */
		if (atomic_read(&hymo_rule_count) > 0 && w->dir_has_inject) {
			char *buf = hymo_iterate_buf_base + (smp_processor_id() * HYMO_ITERATE_PATH_BUF);
			char *dp = ERR_PTR(-ENOENT);

			if (hymo_d_absolute_path)
				dp = hymo_d_absolute_path(&file->f_path, buf,
							  HYMO_ITERATE_PATH_BUF);
			if (IS_ERR(dp) && hymo_dentry_path_raw)
				dp = hymo_dentry_path_raw(w->parent_dentry, buf,
							  HYMO_ITERATE_PATH_BUF);

			if (!IS_ERR_OR_NULL(dp) && *dp == '/') {
				struct hymo_inject_entry *ie;
				struct hymo_merge_entry *me;
				u32 h;
				int mbkt;
				size_t plen = strlen(dp);

				if (plen < HYMO_ITERATE_PATH_BUF) {
					memcpy(w->dir_path_buf, dp, plen + 1);
					w->dir_path = w->dir_path_buf;
				}
				h = full_name_hash(NULL, dp, strlen(dp));

				rcu_read_lock();
				hlist_for_each_entry_rcu(ie,
					&hymo_inject_dirs[hash_min(h, HYMO_HASH_BITS)],
					node) {
					if (strcmp(ie->dir, dp) == 0) {
						w->dir_has_inject = true;
						break;
					}
				}
				/* Scan all merge entries (few) to match both
				 * src and resolved_src; cache target dentries. */
				hash_for_each_rcu(hymo_merge_dirs, mbkt, me, node) {
					if (strcmp(me->src, dp) == 0 ||
					    (me->resolved_src &&
					     strcmp(me->resolved_src, dp) == 0)) {
						w->dir_has_inject = true;
						if (me->target_dentry &&
						    w->merge_target_count < HYMO_MAX_MERGE_TARGETS)
							w->merge_target_dentries[w->merge_target_count++] =
								me->target_dentry;
					}
				}
				rcu_read_unlock();
			}
		}
	}

	if (!w->dir_has_hidden && !w->dir_has_inject &&
	    (!hymo_stealth_enabled || w->dir_path_len != 4)) {
		kmem_cache_free(hymo_filldir_cache, w);
		hymo_this_cpu()->iterate_did_swap = 0;
		return 0;
	}

	hymo_this_cpu()->iterate_did_swap = 1;
	HYMO_REG1(regs) = (unsigned long)&w->wrap_ctx;
	return 0;
}

static int hymo_krp_iterate_dir_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;
	struct dir_context *ctx = (struct dir_context *)HYMO_REG1(regs);

	d->did_swap = 0;
	d->wrapper = NULL;
	if (ctx && ctx->actor == hymofs_filldir_filter) {
		d->did_swap = 1;
		d->wrapper = container_of(ctx, struct hymofs_filldir_wrapper,
					  wrap_ctx);
	}
	return 0;
}

int hymo_krp_iterate_dir_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hymo_iterate_ri_data *d = (void *)ri->data;

	(void)regs;
	if (d->did_swap && d->wrapper) {
		if (d->wrapper->orig_ctx)
			d->wrapper->orig_ctx->pos = d->wrapper->wrap_ctx.pos;
		kmem_cache_free(hymo_filldir_cache, d->wrapper);
		d->wrapper = NULL;
	}
	return 0;
}

#define HYMOFS_VFS_HOOK_COUNT 4
#define HYMOFS_VFS_IDX_GETNAME   0
#define HYMOFS_VFS_IDX_GETATTR  1
#define HYMOFS_VFS_IDX_DPATH    2
#define HYMOFS_VFS_IDX_ITERDIR  3

static const struct {
	const char *name;
	int (*pre)(struct kprobe *, struct pt_regs *);
} hymofs_vfs_hooks[] = {
	{ "getname_flags", hymo_kp_getname_flags_pre },
	{ "vfs_getattr",   hymo_kp_vfs_getattr_pre },
	{ "d_path",        hymo_kp_d_path_pre },
	{ "iterate_dir",   hymo_kp_iterate_dir_pre },
};
static struct kprobe hymofs_kprobes[HYMOFS_VFS_HOOK_COUNT];

static struct kretprobe hymo_krp_vfs_getattr;
static struct kretprobe hymo_krp_d_path;
static struct kretprobe hymo_krp_iterate_dir;
static struct kretprobe hymo_krp_vfs_getxattr;

int hymofs_vfs_hooks_init(bool skip_vfs)
{
#if HYMOFS_VFS_KPROBES
	if (!skip_vfs) {
		size_t i;
		int ret;
		size_t start_idx = hymofs_tracepoint_path_registered() ? 1 : 0;

		pr_alert("HymoFS: STAGE 7: registering VFS hooks\n");
		{
			unsigned long ft_addr[4];

			pr_info("HymoFS: trying ftrace for VFS entry (preferred over kprobes)\n");
			ret = hymofs_ftrace_try_register(ft_addr);
			if (ret == 0) {
				hymo_vfs_getxattr_addr = (void *)ft_addr[3];
				hymo_vfs_use_ftrace = true;
				pr_info("HymoFS: ftrace registered for vfs_getattr, d_path, iterate_dir, vfs_getxattr\n");
				hymo_krp_vfs_getattr.kp.addr = (kprobe_opcode_t *)ft_addr[0];
				hymo_krp_vfs_getattr.entry_handler = hymo_ftrace_krp_entry;
				hymo_krp_vfs_getattr.handler = hymo_ftrace_krp_ret;
				hymo_krp_vfs_getattr.data_size = sizeof(void *);
				hymo_krp_vfs_getattr.maxactive = 64;
				ret = register_kretprobe(&hymo_krp_vfs_getattr);
				if (ret == 0) {
					hymo_krp_d_path.kp.addr = (kprobe_opcode_t *)ft_addr[1];
					hymo_krp_d_path.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_d_path.handler = hymo_ftrace_krp_ret;
					hymo_krp_d_path.data_size = sizeof(void *);
					hymo_krp_d_path.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_d_path);
				}
				if (ret == 0) {
					hymo_krp_iterate_dir.kp.addr = (kprobe_opcode_t *)ft_addr[2];
					hymo_krp_iterate_dir.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_iterate_dir.handler = hymo_ftrace_krp_ret;
					hymo_krp_iterate_dir.data_size = sizeof(void *);
					hymo_krp_iterate_dir.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_iterate_dir);
				}
				if (ret == 0 && ft_addr[3]) {
					hymo_krp_vfs_getxattr.kp.addr = (kprobe_opcode_t *)ft_addr[3];
					hymo_krp_vfs_getxattr.entry_handler = hymo_ftrace_krp_entry;
					hymo_krp_vfs_getxattr.handler = hymo_ftrace_krp_ret;
					hymo_krp_vfs_getxattr.data_size = sizeof(void *);
					hymo_krp_vfs_getxattr.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_vfs_getxattr);
					if (ret == 0)
						hymo_getxattr_kprobe_registered = 1;
				}
				if (ret != 0) {
					hymofs_ftrace_unregister();
					hymo_vfs_use_ftrace = false;
					unregister_kretprobe(&hymo_krp_vfs_getattr);
					unregister_kretprobe(&hymo_krp_d_path);
					unregister_kretprobe(&hymo_krp_iterate_dir);
					unregister_kretprobe(&hymo_krp_vfs_getxattr);
				}
			} else {
				pr_info("HymoFS: ftrace unavailable (err=%d), using kprobes\n", ret);
			}
		}

		if (start_idx == 0) {
			unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[0].name);

			if (!addr) {
				pr_err("HymoFS: symbol not found: %s\n", hymofs_vfs_hooks[0].name);
				return -ENOENT;
			}
			hymofs_kprobes[0].addr = (kprobe_opcode_t *)addr;
			hymofs_kprobes[0].pre_handler = hymofs_vfs_hooks[0].pre;
			ret = register_kprobe(&hymofs_kprobes[0]);
			if (ret) {
				pr_err("HymoFS: register_kprobe(getname_flags) failed: %d\n", ret);
				return ret;
			}
			pr_info("HymoFS: kprobe getname_flags @0x%lx\n", addr);
			hymo_getname_kprobe_registered = true;
		}

		if (!hymo_vfs_use_ftrace) {
			for (i = 1; i < HYMOFS_VFS_HOOK_COUNT; i++) {
				unsigned long addr = hymofs_lookup_name(hymofs_vfs_hooks[i].name);

				if (!addr) {
					pr_err("HymoFS: symbol not found: %s\n", hymofs_vfs_hooks[i].name);
					for (; i > 1; i--)
						unregister_kprobe(&hymofs_kprobes[i - 1]);
					if (start_idx == 0)
						unregister_kprobe(&hymofs_kprobes[0]);
					return -ENOENT;
				}
				hymofs_kprobes[i].addr = (kprobe_opcode_t *)addr;
				hymofs_kprobes[i].pre_handler = hymofs_vfs_hooks[i].pre;
				ret = register_kprobe(&hymofs_kprobes[i]);
				if (ret) {
					pr_err("HymoFS: register_kprobe(%s) failed: %d\n",
					       hymofs_vfs_hooks[i].name, ret);
					for (; i > 1; i--)
						unregister_kprobe(&hymofs_kprobes[i - 1]);
					if (start_idx == 0)
						unregister_kprobe(&hymofs_kprobes[0]);
					return ret;
				}
				pr_info("HymoFS: kprobe %s @0x%lx\n", hymofs_vfs_hooks[i].name, addr);
			}

			hymo_krp_vfs_getattr.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_GETATTR].addr;
			hymo_krp_vfs_getattr.entry_handler = hymo_krp_vfs_getattr_entry;
			hymo_krp_vfs_getattr.handler = hymo_krp_vfs_getattr_ret;
			hymo_krp_vfs_getattr.data_size = sizeof(struct hymo_getattr_ri_data);
			hymo_krp_vfs_getattr.maxactive = 64;
			ret = register_kretprobe(&hymo_krp_vfs_getattr);
			if (ret) {
				pr_err("HymoFS: register_kretprobe(vfs_getattr) failed: %d\n", ret);
				for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
				if (start_idx == 0)
					unregister_kprobe(&hymofs_kprobes[0]);
				return ret;
			}
			hymo_krp_d_path.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_DPATH].addr;
			hymo_krp_d_path.entry_handler = hymo_krp_d_path_entry;
			hymo_krp_d_path.handler = hymo_krp_d_path_ret;
			hymo_krp_d_path.data_size = sizeof(struct hymo_d_path_ri_data);
			hymo_krp_d_path.maxactive = 64;
			ret = register_kretprobe(&hymo_krp_d_path);
			if (ret) {
				pr_err("HymoFS: register_kretprobe(d_path) failed: %d\n", ret);
				unregister_kretprobe(&hymo_krp_vfs_getattr);
				for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
				if (start_idx == 0)
					unregister_kprobe(&hymofs_kprobes[0]);
				return ret;
			}
			hymo_krp_iterate_dir.kp.addr = hymofs_kprobes[HYMOFS_VFS_IDX_ITERDIR].addr;
			hymo_krp_iterate_dir.entry_handler = hymo_krp_iterate_dir_entry;
			hymo_krp_iterate_dir.handler = hymo_krp_iterate_dir_ret;
			hymo_krp_iterate_dir.data_size = sizeof(struct hymo_iterate_ri_data);
			hymo_krp_iterate_dir.maxactive = 64;
			ret = register_kretprobe(&hymo_krp_iterate_dir);
			if (ret) {
				pr_err("HymoFS: register_kretprobe(iterate_dir) failed: %d\n", ret);
				unregister_kretprobe(&hymo_krp_d_path);
				unregister_kretprobe(&hymo_krp_vfs_getattr);
				for (i = HYMOFS_VFS_HOOK_COUNT; i > 1; i--)
					unregister_kprobe(&hymofs_kprobes[i - 1]);
				if (start_idx == 0)
					unregister_kprobe(&hymofs_kprobes[0]);
				return ret;
			}
			pr_info("HymoFS: kretprobes vfs_getattr, d_path, iterate_dir registered\n");

			{
				unsigned long xattr_addr = hymofs_lookup_name("vfs_getxattr");

				if (xattr_addr) {
					hymo_vfs_getxattr_addr = (void *)xattr_addr;
					hymo_krp_vfs_getxattr.kp.addr = (kprobe_opcode_t *)xattr_addr;
					hymo_krp_vfs_getxattr.entry_handler = hymo_krp_vfs_getxattr_entry;
					hymo_krp_vfs_getxattr.handler = hymo_krp_vfs_getxattr_ret;
					hymo_krp_vfs_getxattr.data_size = sizeof(struct hymo_getxattr_ri_data);
					hymo_krp_vfs_getxattr.maxactive = 64;
					ret = register_kretprobe(&hymo_krp_vfs_getxattr);
					if (ret == 0) {
						hymo_getxattr_kprobe_registered = 1;
						pr_info("HymoFS: kretprobe vfs_getxattr registered (SELinux spoof)\n");
					} else {
						pr_warn("HymoFS: register_kretprobe(vfs_getxattr) failed: %d\n", ret);
					}
				} else {
					pr_warn("HymoFS: vfs_getxattr not found, SELinux context spoofing disabled\n");
				}
			}
		}

		pr_info("HymoFS: initialized (%d VFS %s + GET_FD via %s)\n",
			(int)(HYMOFS_VFS_HOOK_COUNT - (hymofs_tracepoint_path_registered() ? 1 : 0)),
			hymo_vfs_use_ftrace ? "ftrace" : "kprobes",
			hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered() ?
				"sys_enter/sys_exit tracepoint" : "kprobes");
	} else {
		pr_alert("HymoFS: skipping VFS hooks (hymo_skip_vfs=1)\n");
		pr_info("HymoFS: initialized (VFS hooks skipped, GET_FD via %s)\n",
			hymofs_tracepoint_path_registered() && hymofs_tracepoint_getfd_registered() ?
				"sys_enter/sys_exit tracepoint" : "kprobes");
	}
#else
	pr_info("HymoFS: initialized (GET_FD only, VFS kprobes disabled)\n");
#endif
	return 0;
}

void hymofs_vfs_hooks_exit(bool skip_vfs)
{
#if HYMOFS_VFS_KPROBES
	if (!skip_vfs) {
		if (hymo_vfs_use_ftrace) {
			hymofs_ftrace_unregister();
			if (hymo_getxattr_kprobe_registered)
				unregister_kretprobe(&hymo_krp_vfs_getxattr);
			unregister_kretprobe(&hymo_krp_iterate_dir);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			if (hymo_getname_kprobe_registered)
				unregister_kprobe(&hymofs_kprobes[0]);
		} else {
			size_t i, start = hymo_getname_kprobe_registered ? 0 : 1;

			if (hymo_getxattr_kprobe_registered)
				unregister_kretprobe(&hymo_krp_vfs_getxattr);
			unregister_kretprobe(&hymo_krp_iterate_dir);
			unregister_kretprobe(&hymo_krp_d_path);
			unregister_kretprobe(&hymo_krp_vfs_getattr);
			for (i = start; i < HYMOFS_VFS_HOOK_COUNT; i++)
				unregister_kprobe(&hymofs_kprobes[i]);
		}
	}
#else
	(void)skip_vfs;
#endif
}
