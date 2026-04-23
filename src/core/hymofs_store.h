/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - rule store declarations and cleanup helpers for shared tables.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_STORE_H
#define _HYMOFS_STORE_H

#include <linux/bitmap.h>
#include <linux/limits.h>

#include "hymofs_runtime.h"

struct hymo_spoof_kstat_entry {
	char *target_pathname;
	u32 path_hash;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_sec;
	long spoofed_atime_nsec;
	long spoofed_mtime_sec;
	long spoofed_mtime_nsec;
	long spoofed_ctime_sec;
	long spoofed_ctime_nsec;
	unsigned long spoofed_blksize;
	unsigned long long spoofed_blocks;
	int is_static;
	struct hlist_node path_node;
	struct hlist_node ino_node;
	struct rcu_head rcu;
};

struct hymo_maps_rule_entry {
	struct list_head list;
	unsigned long target_ino;
	unsigned long target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	char spoofed_pathname[HYMO_MAX_LEN_PATHNAME];
};

extern struct hlist_head hymo_paths[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_targets[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_hide_paths[1 << HYMO_HASH_BITS];
extern struct xarray hymo_allow_uids_xa;
extern struct hlist_head hymo_inject_dirs[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_xattr_sbs[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_merge_dirs[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_spoof_kstat_path[1 << HYMO_HASH_BITS];
extern struct hlist_head hymo_spoof_kstat_ino[1 << HYMO_HASH_BITS];
extern struct list_head hymo_maps_rules;

extern struct mutex hymo_config_mutex;
extern struct mutex hymo_maps_mutex;

extern bool hymo_allowlist_loaded;
extern unsigned long hymo_path_bloom[BITS_TO_LONGS(HYMO_BLOOM_SIZE)];
extern unsigned long hymo_hide_bloom[BITS_TO_LONGS(HYMO_BLOOM_SIZE)];

struct hymo_spoof_kstat_entry *hymofs_spoof_kstat_lookup_by_path(const char *path_str);
struct hymo_spoof_kstat_entry *hymofs_spoof_kstat_lookup_by_ino(unsigned long ino,
								unsigned long dev);

void hymofs_mark_inode_hidden(struct inode *inode);
bool hymofs_is_inode_hidden_bit(struct inode *inode);
void hymofs_mark_dir_has_inject(const char *path_str);
void hymo_clear_inode_flags_for_path(const char *path_str, unsigned int bit);
void hymo_cleanup_locked(void);

void hymo_entry_free_rcu(struct rcu_head *head);
void hymo_hide_entry_free_rcu(struct rcu_head *head);
void hymo_inject_entry_free_rcu(struct rcu_head *head);
void hymo_xattr_sb_entry_free_rcu(struct rcu_head *head);
void hymo_merge_entry_free_rcu(struct rcu_head *head);
void hymo_spoof_kstat_entry_free_rcu(struct rcu_head *head);

#endif /* _HYMOFS_STORE_H */
