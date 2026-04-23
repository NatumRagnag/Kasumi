/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - policy helpers for path visibility and redirect decisions.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_PATH_POLICY_H
#define _HYMOFS_PATH_POLICY_H

#include <linux/types.h>

struct hymo_entry;

bool hymo_is_privileged_process(void);
bool hymo_reload_ksu_allowlist(void);
char *hymofs_resolve_target(const char *pathname);
bool hymofs_should_hide(const char *pathname);
struct hymo_entry *hymofs_reverse_lookup_target(const char *path_str);

#endif /* _HYMOFS_PATH_POLICY_H */
