/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - module metadata and the thin entrypoint that forwards into bootstrap.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>

#include "hymofs_bootstrap.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anatdx");
MODULE_DESCRIPTION("HymoFS kernel module");
#ifndef HYMOFS_VERSION
#define HYMOFS_VERSION "0.1.0-dev"
#endif
MODULE_VERSION(HYMOFS_VERSION);
MODULE_SOFTDEP("pre: kernelsu");

static int __init hymofs_lkm_init(void)
{
	return hymofs_bootstrap_init();
}

static void __exit hymofs_lkm_exit(void)
{
	hymofs_bootstrap_exit();
}

module_init(hymofs_lkm_init);
module_exit(hymofs_lkm_exit);
