/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - shared compile-time constants, attributes, and logging helpers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_BASE_H
#define _HYMOFS_BASE_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>

#include "hymofs_uapi.h"

#if defined(__clang__)
#if __clang_major__ >= 17
#define HYMO_NOCFI __attribute__((no_sanitize("cfi", "kcfi")))
#else
#define HYMO_NOCFI __attribute__((no_sanitize("cfi")))
#endif
#else
#define HYMO_NOCFI
#endif

#define HYMO_HASH_BITS              12
#define HYMO_BLOOM_BITS             10
#define HYMO_BLOOM_SIZE             (1 << HYMO_BLOOM_BITS)
#define HYMO_BLOOM_MASK             (HYMO_BLOOM_SIZE - 1)
#define HYMO_MERGE_HASH_BITS        6
#define HYMO_MERGE_HASH_SIZE        (1 << HYMO_MERGE_HASH_BITS)

#define HYMO_ALLOWLIST_UID_MAX      1024
#define HYMO_KSU_ALLOWLIST_PATH     "/data/adb/ksu/.allowlist"
#define HYMO_KSU_ALLOWLIST_MAGIC    0x7f4b5355
#define HYMO_KSU_ALLOWLIST_VERSION  3
#define HYMO_KSU_FILE_FORMAT_VERSION 3
#define HYMO_KSU_APP_PROFILE_VER     2
#define HYMO_KSU_MAX_PACKAGE_NAME   256
#define HYMO_KSU_MAX_GROUPS         32
#define HYMO_KSU_SELINUX_DOMAIN     64

#define HYMO_DEFAULT_MIRROR_NAME    "hymo_mirror"
#define HYMO_DEFAULT_MIRROR_PATH    "/dev/" HYMO_DEFAULT_MIRROR_NAME

#define HYMO_PATH_BUF               512
#define HYMO_ITERATE_PATH_BUF       512

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0))
#define HYMO_FILLDIR_RET_TYPE int
#define HYMO_FILLDIR_CONTINUE 0
#define HYMO_FILLDIR_STOP     1
#else
#define HYMO_FILLDIR_RET_TYPE bool
#define HYMO_FILLDIR_CONTINUE true
#define HYMO_FILLDIR_STOP     false
#endif

#define HYMO_UID_ALLOW_MARKER ((void *)1)
#define HYMO_SELINUX_CTX_MAX 96
#define HYMO_D_PATH_SRC_MAX 256
#define HYMO_MAX_MERGE_TARGETS 4

extern bool hymo_debug_enabled;

#define hymo_log(fmt, ...) (void)(hymo_debug_enabled && pr_info("HymoFS: " fmt, ##__VA_ARGS__))

#endif /* _HYMOFS_BASE_H */
