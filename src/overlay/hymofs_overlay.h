/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - overlay merge and injection helper interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_OVERLAY_H
#define _HYMOFS_OVERLAY_H

#include <linux/fs.h>
#include <linux/list.h>

void hymofs_add_inject_rule(char *dir);
void hymofs_materialize_merge(const char *src_prefix, const char *target_dir, int depth);
void hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
				   struct list_head *head);

#endif /* _HYMOFS_OVERLAY_H */
