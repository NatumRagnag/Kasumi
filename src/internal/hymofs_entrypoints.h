/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - shared cross-module entry points used by hook and feature code.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_ENTRYPOINTS_H
#define _HYMOFS_ENTRYPOINTS_H

#include <asm/ptrace.h>
#include <linux/fs.h>

#include "hymofs_base.h"
#include "hymofs_types.h"

extern int hymo_syscall_nr_param;

int hymofs_get_anon_fd(void);

void hymofs_handle_sys_enter_path(struct pt_regs *regs, long id);
void hymofs_handle_sys_exit_path(struct pt_regs *regs, long ret);
void hymofs_handle_sys_enter_statx(struct pt_regs *regs, long id);
void hymofs_handle_sys_exit_statx(struct pt_regs *regs, long ret);
void hymofs_handle_sys_enter_getfd(struct pt_regs *regs, long id);
void hymofs_handle_sys_exit_getfd(struct pt_regs *regs, long ret);
void hymofs_handle_sys_enter_cmdline(struct pt_regs *regs, long id);
void hymofs_handle_sys_exit_cmdline(struct pt_regs *regs, long ret);

unsigned long hymofs_lookup_name(const char *name);
bool hymo_should_apply_hide_rules(void);

HYMO_FILLDIR_RET_TYPE hymofs_filldir_filter(struct dir_context *ctx, const char *name,
					    int namlen, loff_t offset, u64 ino,
					    unsigned int d_type);

#endif /* _HYMOFS_ENTRYPOINTS_H */
