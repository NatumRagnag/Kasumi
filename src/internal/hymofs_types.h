/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - shared in-kernel data structures for rules and hook state.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_TYPES_H
#define _HYMOFS_TYPES_H

#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>

#include "hymofs_base.h"

struct hymo_entry {
	char *src;
	char *target;
	unsigned char type;
	u32 src_hash;
	struct hlist_node node;
	struct hlist_node target_node;
	struct rcu_head rcu;
};

struct hymo_hide_entry {
	char *path;
	u32 path_hash;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_inject_entry {
	char *dir;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_xattr_sb_entry {
	struct super_block *sb;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_merge_entry {
	char *src;
	char *target;
	char *resolved_src;
	struct dentry *target_dentry;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct hymo_merge_target_node {
	struct list_head list;
	char *target;
	struct dentry *target_dentry;
};

struct hymo_name_list {
	char *name;
	unsigned char type;
	struct list_head list;
};

struct hymo_root_profile {
	s32 uid;
	s32 gid;
	s32 groups_count;
	s32 groups[HYMO_KSU_MAX_GROUPS];
	struct {
		u64 effective;
		u64 permitted;
		u64 inheritable;
	} capabilities;
	char selinux_domain[HYMO_KSU_SELINUX_DOMAIN];
	s32 namespaces;
};

struct hymo_non_root_profile {
	bool umount_modules;
};

struct hymo_app_profile {
	u32 version;
	char key[HYMO_KSU_MAX_PACKAGE_NAME];
	s32 curr_uid;
	bool allow_su;
	union {
		struct {
			bool use_default;
			char template_name[HYMO_KSU_MAX_PACKAGE_NAME];
			struct hymo_root_profile profile;
		} rp_config;
		struct {
			bool use_default;
			struct hymo_non_root_profile profile;
		} nrp_config;
	};
};

struct hymo_getattr_ri_data {
	struct kstat *stat;
	struct address_space *mapping;
	bool is_target;
};

struct hymo_getxattr_ri_data {
	void *value_buf;
	size_t value_size;
	bool spoof_selinux;
	char src_ctx[HYMO_SELINUX_CTX_MAX];
	size_t src_ctx_len;
};

struct hymo_d_path_ri_data {
	char *buf;
	int buflen;
	bool is_target;
	char src_path[HYMO_D_PATH_SRC_MAX];
};

struct hymofs_filldir_wrapper {
	struct dir_context wrap_ctx;
	struct dir_context *orig_ctx;
	struct dentry *parent_dentry;
	int dir_path_len;
	bool dir_has_hidden;
	const char *dir_path;
	bool dir_has_inject;
	bool inject_done;
	int merge_target_count;
	struct dentry *merge_target_dentries[HYMO_MAX_MERGE_TARGETS];
	char dir_path_buf[HYMO_ITERATE_PATH_BUF];
};

struct hymo_iterate_ri_data {
	int did_swap;
	struct hymofs_filldir_wrapper *wrapper;
};

#endif /* _HYMOFS_TYPES_H */
