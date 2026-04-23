/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - interfaces for lookup-time inode_operations shadow overrides.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_IOP_OVERRIDE_H
#define _HYMOFS_IOP_OVERRIDE_H

#include <linux/fs.h>

/* Module init/exit. Returns 0 on success. */
int hymofs_iop_override_init(void);
void hymofs_iop_override_exit(void);

/*
 * Install shadow inode_operations on `inode`. Idempotent: safe to call on an
 * already-installed inode (becomes a no-op).
 *
 * After successful install, AS_FLAGS_HYMO_IOP_INSTALLED is set on
 * inode->i_mapping->flags so the slow kprobe path can short-circuit.
 *
 * Returns 0 on success or already-installed; negative errno on failure.
 */
int hymofs_iop_install(struct inode *inode);

/*
 * Apply kstat spoofing in place. Extracted from the original vfs_getattr
 * kretprobe ret handler so both the legacy kprobe and the new shadow getattr
 * share one implementation.
 *
 * Caller must have a valid inode and stat. Safe to call from atomic context.
 */
void hymo_apply_kstat_spoof(struct inode *inode, struct kstat *stat);

#endif /* _HYMOFS_IOP_OVERRIDE_H */
