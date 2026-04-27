/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Kasumi - syscall table redirect via aarch64_insn_write_literal_u64.
 *
 * Uses the kernel's own instruction-patching machinery (which internally
 * handles patch_lock, fixmap, TLB flush, and cache maintenance) to swap
 * an unused ni_syscall slot with a dispatcher.  The tracepoint handler
 * only rewrites syscallno into the dispatcher slot — a single-register
 * store.  The hook handlers run in normal process context.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/kernel.h>
#include <linux/srcu.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/cacheflush.h>

#include "kasumi_base.h"
#include "kasumi_runtime.h"
#include "kasumi_entrypoints.h"
#include "kasumi_path_policy.h"
#include "kasumi_proc_hooks.h"
#include "kasumi_vfs_hooks.h"
#include "kasumi_fake_mountinfo.h"
#include "kasumi_syscall_redirect.h"

/* ---- Runtime-resolved kernel patching functions ------------------------ */

static int (*ksm_insn_write_u64)(void *addr, u64 val);

static int ksm_resolve_patch_api(void)
{
	ksm_insn_write_u64 = (void *)kasumi_lookup_name(
		"aarch64_insn_write_literal_u64");
	if (ksm_insn_write_u64 &&
	    kasumi_valid_kernel_addr((unsigned long)ksm_insn_write_u64)) {
		pr_info("Kasumi: aarch64_insn_write_literal_u64 @ %lx\n",
			(unsigned long)ksm_insn_write_u64);
		return 0;
	}

	pr_err("Kasumi: aarch64_insn_write_literal_u64 not found\n");
	return -ENOENT;
}

/* ---- Root detection ---------------------------------------------------- */

int kasumi_root_mask;

void kasumi_root_detect(void)
{
	unsigned long a;
	kasumi_root_mask = 0;

	a = kasumi_lookup_name("ksu_syscall_table");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_KSU;
		a = kasumi_lookup_name("ksu_dispatcher_nr");
		if (a && kasumi_valid_kernel_addr(a) &&
		    READ_ONCE(*(int *)a) >= 0)
			kasumi_root_mask |= KASUMI_ROOT_KSU_RDR;
		pr_info("Kasumi: KernelSU detected%s\n",
			(kasumi_root_mask & KASUMI_ROOT_KSU_RDR) ?
			" (redirect)" : "");
	}

	a = kasumi_lookup_name("kpm_init");
	if (a && kasumi_valid_kernel_addr(a)) {
		kasumi_root_mask |= KASUMI_ROOT_APATCH;
		pr_info("Kasumi: APatch/KPM detected\n");
	}

	if (!(kasumi_root_mask & KASUMI_ROOT_KSU)) {
		struct file *f = filp_open("/sbin/magisk", O_RDONLY, 0);
		if (!IS_ERR(f)) {
			filp_close(f, NULL);
			kasumi_root_mask |= KASUMI_ROOT_MAGISK;
			pr_info("Kasumi: Magisk detected\n");
		}
	}
}

/* ---- Syscall table & redirect ------------------------------------------ */

void *kasumi_syscall_table;
int  kasumi_syscall_dispatcher_nr = -1;
static kasumi_syscall_hook_fn hooks[__NR_syscalls];
static kasumi_syscall_hook_fn saved_ni;
DEFINE_STATIC_SRCU(kasumi_redirect_srcu);
kasumi_syscall_hook_fn orig_kernel_openat, orig_kernel_openat2, orig_kernel_statfs;

static int patch_entry(int nr, kasumi_syscall_hook_fn fn)
{
	unsigned long addr = (unsigned long)kasumi_syscall_table +
			    nr * sizeof(void *);
	u64 val = (u64)fn;
	int ret;

	pr_info("Kasumi: patch syscall %d @ %lx -> %llx\n", nr, addr, val);
	ret = ksm_insn_write_u64((void *)addr, val);
	if (ret)
		pr_err("Kasumi: aarch64_insn_write_literal_u64(%lx) failed: %d\n",
		       addr, ret);
	return ret;
}

static int find_ni_slot(void)
{
	unsigned long ni = kasumi_lookup_name("__arm64_sys_ni_syscall.cfi_jt");
	int i;
	if (!ni || !kasumi_valid_kernel_addr(ni))
		ni = kasumi_lookup_name("__arm64_sys_ni_syscall");
	if (!ni || !kasumi_valid_kernel_addr(ni))
		return -ENOENT;
	for (i = 0; i < __NR_syscalls; i++)
		if ((unsigned long)((kasumi_syscall_hook_fn *)
				    kasumi_syscall_table)[i] == ni)
			return i;
	return -ENOENT;
}

static long __nocfi dispatcher(const struct pt_regs *regs)
{
	int orig = (int)((struct pt_regs *)regs)->regs[8];
	kasumi_syscall_hook_fn fn;
	long ret;
	int idx;

	if (orig < 0 || orig >= __NR_syscalls)
		return -ENOSYS;
	((struct pt_regs *)regs)->syscallno = orig;
	((struct pt_regs *)regs)->regs[8] = orig;

	idx = srcu_read_lock(&kasumi_redirect_srcu);
	fn = READ_ONCE(hooks[orig]);
	ret = likely(fn) ? fn(regs) : -ENOSYS;
	srcu_read_unlock(&kasumi_redirect_srcu, idx);
	return ret;
}

int kasumi_register_syscall_hook(int nr, kasumi_syscall_hook_fn fn)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	if (READ_ONCE(hooks[nr]))
		return -EEXIST;
	WRITE_ONCE(hooks[nr], fn);
	return 0;
}

void kasumi_unregister_syscall_hook(int nr)
{
	if (nr >= 0 && nr < __NR_syscalls)
		WRITE_ONCE(hooks[nr], NULL);
}

bool kasumi_has_syscall_hook(int nr)
{
	return nr >= 0 && nr < __NR_syscalls && READ_ONCE(hooks[nr]);
}

/* ---- Hook handlers ----------------------------------------------------- */

#ifndef KASUMI_HIDE_PATH
#define KASUMI_HIDE_PATH "/.kasumi_hidden_placeholder"
#endif

/* saved original handlers for GET_FD / cmdline */
static kasumi_syscall_hook_fn orig_kernel_reboot;
static kasumi_syscall_hook_fn orig_kernel_prctl;

/* ---- GET_FD via reboot / prctl / custom nr (TSR) ---------------------- */

static long h_getfd(const struct pt_regs *regs, int nr)
{
#if defined(__aarch64__)
	unsigned long a0 = regs->regs[0];
	unsigned long a1 = regs->regs[1];
	unsigned long a2 = regs->regs[2];
#else
	unsigned long a0 = regs->di;
	unsigned long a1 = regs->si;
	unsigned long a2 = regs->dx;
#endif
	int fd;

	if (a0 != KSM_MAGIC1 || a1 != KSM_MAGIC2 ||
	    a2 != (unsigned long)KSM_CMD_GET_FD)
		return -ENOSYS;

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return -ENOSYS;

	fd = kasumi_get_anon_fd();
	if (fd < 0)
		return -ENOSYS;

#if defined(__aarch64__)
	{
		int __user *fd_ptr = (int __user *)(unsigned long)regs->regs[3];
		if (fd_ptr)
			put_user(fd, fd_ptr);
	}
#endif
	return fd;
}

static long h_reboot(const struct pt_regs *regs)
{
	long ret = h_getfd(regs, __NR_reboot);
	return ret >= 0 ? ret : orig_kernel_reboot(regs);
}

static long h_prctl(const struct pt_regs *regs)
{
#if defined(__aarch64__)
	unsigned long option = regs->regs[0];
	unsigned long arg2 = regs->regs[1];
#else
	unsigned long option = regs->di;
	unsigned long arg2 = regs->si;
#endif

	if (option != (unsigned long)KSM_PRCTL_GET_FD)
		return orig_kernel_prctl(regs);

	if (!uid_eq(current_uid(), GLOBAL_ROOT_UID))
		return orig_kernel_prctl(regs);

	{
		int fd = kasumi_get_anon_fd();
		if (fd < 0)
			return orig_kernel_prctl(regs);
#if defined(__aarch64__)
		{
			int __user *fd_ptr = (int __user *)(unsigned long)arg2;
			if (fd_ptr)
				put_user(fd, fd_ptr);
		}
#endif
		return fd;
	}
}

/* ---- path redirect + mount proxy (TSR) --------------------------------- */

static long do_openat(const struct pt_regs *regs, kasumi_syscall_hook_fn orig)
{
	char path[KSM_MAX_LEN_PATHNAME];
	const char __user *u = (void __user *)(uintptr_t)regs->regs[1];
	char *t;
	long ret;
	bool proxy = false;
	long tgid = (long)task_tgid_vnr(current);

	if (atomic_long_read(&kasumi_ioctl_tgid) == tgid ||
	    atomic_long_read(&kasumi_xattr_source_tgid) == tgid)
		return orig(regs);
	if (!u || copy_from_user(path, u, sizeof(path) - 1))
		return orig(regs);
	path[sizeof(path) - 1] = '\0';

	if (path[0] == '/' && kasumi_path_needs_proc_proxy(path)) {
		proxy = true;
		if (kasumi_path_is_proc_mountinfo(path) &&
		    kasumi_should_apply_hide_rules())
			kasumi_fake_mi_prepare(false);
	}

	if (path[0] == '/' && atomic_read(&kasumi_rule_count) > 0) {
		t = kasumi_resolve_target(path);
		if (t) {
			size_t l = strlen(t) + 1;
			char __user *n;
			if (l <= KASUMI_PATH_BUF) {
				n = kasumi_userspace_stack_buffer(t, l);
				if (n)
					((unsigned long *)regs)[1] =
						(unsigned long)n;
			}
			kfree(t);
		}
	}

	if (unlikely(kasumi_should_hide(path))) {
		char __user *n = kasumi_userspace_stack_buffer(
			KASUMI_HIDE_PATH, sizeof(KASUMI_HIDE_PATH));
		if (n)
			((unsigned long *)regs)[1] = (unsigned long)n;
	}

	ret = orig(regs);
	if (proxy && ret >= 0)
		kasumi_mount_proxy_install_fd((int)ret);
	return ret;
}

static long h_openat(const struct pt_regs *r)  { return do_openat(r, orig_kernel_openat); }
static long h_openat2(const struct pt_regs *r) { return do_openat(r, orig_kernel_openat2); }

static long h_statfs(const struct pt_regs *regs)
{
	char path[KSM_MAX_LEN_PATHNAME];
	void __user *buf = (void __user *)(uintptr_t)regs->regs[1];
	unsigned long s;
	long ret;

	if (!(kasumi_feature_enabled_mask & KSM_FEATURE_STATFS_SPOOF))
		return orig_kernel_statfs(regs);
	if (copy_from_user(path, (void __user *)(uintptr_t)regs->regs[0],
			  sizeof(path) - 1))
		return orig_kernel_statfs(regs);
	path[sizeof(path) - 1] = 0;

	s = kasumi_statfs_resolve_spoof_magic(path);
	ret = orig_kernel_statfs(regs);
	if (ret >= 0 && s)
		kasumi_statfs_apply_spoof(buf, s);
	return ret;
}

/* ---- Init / exit ------------------------------------------------------- */

int kasumi_syscall_redirect_init(void)
{
	int slot, ret;

	ret = ksm_resolve_patch_api();
	if (ret)
		return ret;

	kasumi_root_detect();

	kasumi_syscall_table = (void *)kasumi_lookup_name("sys_call_table");
	if (!kasumi_syscall_table)
		return -ENOENT;

	orig_kernel_openat = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_openat];
	orig_kernel_openat2 = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_openat2];
	orig_kernel_statfs = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_statfs];
	orig_kernel_reboot = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_reboot];
	orig_kernel_prctl = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[__NR_prctl];

	slot = find_ni_slot();
	if (slot < 0) {
		pr_err("Kasumi: no ni_syscall slot\n");
		return slot;
	}
	kasumi_syscall_dispatcher_nr = slot;
	saved_ni = ((kasumi_syscall_hook_fn *)
		kasumi_syscall_table)[slot];

	ret = patch_entry(slot, (kasumi_syscall_hook_fn)dispatcher);
	if (ret) {
		pr_err("Kasumi: patch dispatcher failed: %d\n", ret);
		kasumi_syscall_dispatcher_nr = -1;
		return ret;
	}

	kasumi_register_syscall_hook(__NR_openat,  h_openat);
	kasumi_register_syscall_hook(__NR_openat2, h_openat2);
	kasumi_register_syscall_hook(__NR_statfs,  h_statfs);
	kasumi_register_syscall_hook(__NR_reboot,  h_reboot);
	kasumi_register_syscall_hook(__NR_prctl,   h_prctl);

	pr_info("Kasumi: redirect active @ slot %d, 5 hooks\n",
		kasumi_syscall_dispatcher_nr);
	return 0;
}

void kasumi_syscall_redirect_exit(void)
{
	int i;

	for (i = 0; i < __NR_syscalls; i++)
		WRITE_ONCE(hooks[i], NULL);
	synchronize_srcu(&kasumi_redirect_srcu);

	if (kasumi_syscall_dispatcher_nr >= 0)
		patch_entry(kasumi_syscall_dispatcher_nr, saved_ni);

	kasumi_syscall_dispatcher_nr = -1;
	orig_kernel_openat  = NULL;
	orig_kernel_openat2 = NULL;
	orig_kernel_statfs  = NULL;
	orig_kernel_reboot  = NULL;
	orig_kernel_prctl   = NULL;
	pr_info("Kasumi: redirect exited\n");
}
