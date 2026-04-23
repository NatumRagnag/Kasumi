/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - tracepoint-based syscall monitoring header.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_TRACEPOINT_HOOKS_H
#define _HYMOFS_TRACEPOINT_HOOKS_H

#include <asm/ptrace.h>

int hymofs_tracepoint_path_init(void);
void hymofs_tracepoint_path_exit(void);
int hymofs_tracepoint_path_registered(void);
int hymofs_tracepoint_getfd_registered(void);

#endif /* _HYMOFS_TRACEPOINT_HOOKS_H */
