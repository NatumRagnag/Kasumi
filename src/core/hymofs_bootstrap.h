/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - top-level module bootstrap and teardown interfaces.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_BOOTSTRAP_H
#define _HYMOFS_BOOTSTRAP_H

int hymofs_bootstrap_init(void);
void hymofs_bootstrap_exit(void);

#endif /* _HYMOFS_BOOTSTRAP_H */
