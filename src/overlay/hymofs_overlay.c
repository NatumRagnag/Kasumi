/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - overlay merge materialization and injected directory listing helpers.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && !defined(arch_ftrace_get_regs)
#define arch_ftrace_get_regs(fregs) (NULL)
#endif
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/sched/task.h>
#include <linux/fs_struct.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/anon_inodes.h>
#include <linux/fcntl.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/xattr.h>
#include <linux/seq_file.h>
#include <uapi/linux/magic.h>
#ifndef EROFS_SUPER_MAGIC
#define EROFS_SUPER_MAGIC 0xe0f5e1e2
#endif
#include <asm/unistd.h>
#include "hymofs_runtime.h"
#include "hymofs_store.h"
#include "hymofs_overlay.h"
/* ======================================================================
 * Part 10: Inject Rule Helper
 * ====================================================================== */

void hymofs_add_inject_rule(char *dir)
{
	struct hymo_inject_entry *ie;
	u32 hash;
	bool found = false;

	if (!dir)
		return;

	hash = full_name_hash(NULL, dir, strlen(dir));
	hlist_for_each_entry(ie, &hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(ie->dir, dir) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		ie = kmalloc(sizeof(*ie), GFP_KERNEL);
		if (ie) {
			ie->dir = dir;
			hlist_add_head_rcu(&ie->node,
				&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			atomic_inc(&hymo_rule_count);
		} else {
			kfree(dir);
		}
	} else {
		kfree(dir);
	}
}

/* ======================================================================
 * Part 10b: Inject - populate list for merge/add rule dirs
 * ====================================================================== */

struct hymo_merge_ctx {
	struct dir_context ctx;
	struct list_head *head;
	const char *dir_path;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE hymo_merge_filldir(struct dir_context *ctx, const char *name,
					int namlen, loff_t offset, u64 ino,
					unsigned int d_type)
{
	struct hymo_merge_ctx *mctx = container_of(ctx, struct hymo_merge_ctx, ctx);
	struct hymo_name_list *item;

	if (namlen == 1 && name[0] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 2 && name[0] == '.' && name[1] == '.')
		return HYMO_FILLDIR_CONTINUE;
	if (namlen == 8 && strncmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	/* Skip whiteout (char dev 0:0) */
	if (d_type == DT_CHR && mctx->dir_path && hymo_vfs_getattr) {
		char *path = kasprintf(GFP_KERNEL, "%s/%.*s", mctx->dir_path, namlen, name);
		if (path) {
			struct path p;
			if (hymo_kern_path(path, LOOKUP_FOLLOW, &p) == 0) {
				struct kstat stat;
				if (hymo_vfs_getattr(&p, &stat, STATX_TYPE, AT_STATX_SYNC_AS_STAT) == 0 &&
				    S_ISCHR(stat.mode) && stat.rdev == 0) {
					path_put(&p);
					kfree(path);
					return HYMO_FILLDIR_CONTINUE;
				}
				path_put(&p);
			}
			kfree(path);
		}
	}

	/* Skip duplicates */
	{
		struct hymo_name_list *pos;
		list_for_each_entry(pos, mctx->head, list) {
			if ((size_t)namlen == strlen(pos->name) &&
			    strncmp(pos->name, name, namlen) == 0)
				return HYMO_FILLDIR_CONTINUE;
		}
	}

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (item) {
		item->name = kstrndup(name, namlen, GFP_KERNEL);
		item->type = (unsigned char)d_type;
		if (item->name)
			list_add(&item->list, mctx->head);
		else
			kfree(item);
	}
	return HYMO_FILLDIR_CONTINUE;
}

void hymofs_populate_injected_list(const char *dir_path, struct dentry *parent,
				   struct list_head *head)
{
	struct hymo_entry *entry;
	struct hymo_inject_entry *inject_entry;
	struct hymo_merge_entry *merge_entry;
	struct hymo_name_list *item;
	struct hymo_merge_target_node *target_node, *tmp_node;
	struct list_head merge_targets;
	const char *match_src = NULL;
	size_t match_src_len = 0;
	u32 hash;
	int bkt;
	bool should_inject = false;
	size_t dir_len;
	/* d_path-resolved form of dir_path for matching rules stored via d_path.
	 * iterate_dir gives us d_absolute_path output, but ADD_RULE/ADD_MERGE_RULE
	 * store paths using d_path. These can differ (e.g. /product/overlay vs
	 * /system/product/overlay) due to bind mounts / symlinks. */
	char *dpath_buf = NULL;
	const char *dpath_dir = NULL;
	size_t dpath_dir_len = 0;
	u32 dpath_hash = 0;

	if (unlikely(!hymofs_enabled || !dir_path))
		return;
	if (atomic_read(&hymo_rule_count) == 0)
		return;

	INIT_LIST_HEAD(&merge_targets);
	dir_len = strlen(dir_path);
	hash = full_name_hash(NULL, dir_path, dir_len);

	/* Resolve the d_path form of this directory. We're in filldir callback
	 * (process context), so d_path is safe to call. Our d_path kretprobe
	 * won't interfere since this directory is not a redirect target. */
	if (parent) {
		if (hymo_kern_path) {
			struct path resolved;
			if (hymo_kern_path(dir_path, LOOKUP_FOLLOW, &resolved) == 0) {
				dpath_buf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (dpath_buf && hymo_d_path) {
					char *p = hymo_d_path(&resolved, dpath_buf, PATH_MAX);
					if (!IS_ERR(p) && p[0] == '/' &&
					    strcmp(p, dir_path) != 0) {
						dpath_dir = p;
						dpath_dir_len = strlen(p);
						dpath_hash = full_name_hash(NULL, p, dpath_dir_len);
					}
				}
				path_put(&resolved);
			}
		}
	}

	rcu_read_lock();

	/* Try both d_absolute_path form and d_path form for inject_dirs */
	hlist_for_each_entry_rcu(inject_entry,
		&hymo_inject_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(inject_entry->dir, dir_path) == 0) {
			should_inject = true;
			break;
		}
	}
	if (!should_inject && dpath_dir) {
		hlist_for_each_entry_rcu(inject_entry,
			&hymo_inject_dirs[hash_min(dpath_hash, HYMO_HASH_BITS)], node) {
			if (strcmp(inject_entry->dir, dpath_dir) == 0) {
				should_inject = true;
				break;
			}
		}
	}

	/* Scan all merge entries to match both src and resolved_src against
	 * both path forms. */
	hash_for_each_rcu(hymo_merge_dirs, bkt, merge_entry, node) {
		if (strcmp(merge_entry->src, dir_path) == 0 ||
		    (merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dir_path) == 0) ||
		    (dpath_dir && strcmp(merge_entry->src, dpath_dir) == 0) ||
		    (dpath_dir && merge_entry->resolved_src &&
		     strcmp(merge_entry->resolved_src, dpath_dir) == 0)) {
			if (!match_src) {
				match_src = merge_entry->src;
				match_src_len = strlen(match_src);
			}
			target_node = kmalloc(sizeof(*target_node), GFP_ATOMIC);
			if (target_node) {
				target_node->target = kstrdup(merge_entry->target, GFP_ATOMIC);
				target_node->target_dentry = NULL;
				if (target_node->target)
					list_add_tail(&target_node->list, &merge_targets);
				else
					kfree(target_node);
			}
			should_inject = true;
		}
	}

	if (should_inject && match_src) {
		/* Only scan hymo_paths when a merge rule matched. For simple
		 * ADD_RULE redirects the source is hidden and getname_flags
		 * handles the redirect transparently — no injection needed. */
		const char *pfx = match_src;
		size_t pfx_len = match_src_len;

		hash_for_each_rcu(hymo_paths, bkt, entry, node) {
			if (strncmp(entry->src, pfx, pfx_len) != 0)
				continue;
			{
				char *name = NULL;
				if (pfx_len == 1 && pfx[0] == '/')
					name = (char *)entry->src + 1;
				else if (entry->src[pfx_len] == '/')
					name = (char *)entry->src + pfx_len + 1;

				if (name && *name && !strchr(name, '/')) {
					struct hymo_name_list *pos;
					list_for_each_entry(pos, head, list) {
						if (strcmp(pos->name, name) == 0)
							goto next_entry;
					}
					item = kmalloc(sizeof(*item), GFP_ATOMIC);
					if (item) {
						item->name = kstrdup(name, GFP_ATOMIC);
						item->type = entry->type;
						if (item->name)
							list_add(&item->list, head);
						else
							kfree(item);
					}
				}
			}
next_entry:
			;
		}
	}
	rcu_read_unlock();

	list_for_each_entry_safe(target_node, tmp_node, &merge_targets, list) {
		if (target_node->target && hymo_kern_path && hymo_dentry_open) {
			char *replace_path = kasprintf(GFP_KERNEL, "%s/.replace", target_node->target);
			if (replace_path) {
				struct path rp;
				if (hymo_kern_path(replace_path, LOOKUP_FOLLOW, &rp) == 0) {
					hymo_log("replace mode enabled for %s (found %s)\n", dir_path, replace_path);
					path_put(&rp);
				}
				kfree(replace_path);
			}
			{
			struct path path;
			if (hymo_kern_path(target_node->target, LOOKUP_FOLLOW, &path) == 0) {
				const struct cred *cred = get_task_cred(&init_task);
				struct file *f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY,
								cred);
				if (!IS_ERR(f)) {
					struct hymo_merge_ctx mctx = {
						.ctx.actor = hymo_merge_filldir,
						.head = head,
						.dir_path = target_node->target,
					};
					hymo_this_cpu()->in_populate_inject = 1;
					iterate_dir(f, &mctx.ctx);
					hymo_this_cpu()->in_populate_inject = 0;
					fput(f);
				}
				put_cred(cred);
				path_put(&path);
			}
			}
		}
		kfree(target_node->target);
		list_del(&target_node->list);
		kfree(target_node);
	}
	kfree(dpath_buf);
}

/* ======================================================================
 * Part 10c: Materialize merge rule into individual hymo_paths entries
 *
 * Called from HYMO_IOC_ADD_MERGE_RULE ioctl (process context, can sleep).
 * Recursively scans the merge target directory and creates exact-match
 * redirect rules so getname_flags works without blind trie redirect.
 * ====================================================================== */

void hymofs_materialize_merge(const char *src_prefix,
			      const char *target_dir, int depth);

static void hymofs_add_path_entry(const char *src, const char *tgt,
				  unsigned char type)
{
	struct hymo_entry *e;
	u32 hash = full_name_hash(NULL, src, strlen(src));
	bool found = false;

	hlist_for_each_entry(e, &hymo_paths[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (e->src_hash == hash && strcmp(e->src, src) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		e = kmalloc(sizeof(*e), GFP_KERNEL);
		if (e) {
			e->src = kstrdup(src, GFP_KERNEL);
			e->target = kstrdup(tgt, GFP_KERNEL);
			e->type = type;
			e->src_hash = hash;
			if (e->src && e->target) {
				unsigned long h1, h2;

				hlist_add_head_rcu(&e->node,
					&hymo_paths[hash_min(hash, HYMO_HASH_BITS)]);
				hlist_add_head_rcu(&e->target_node,
					&hymo_targets[hash_min(
						full_name_hash(NULL, e->target,
							strlen(e->target)),
						HYMO_HASH_BITS)]);
				h1 = jhash(src, strlen(src), 0) & (HYMO_BLOOM_SIZE - 1);
				h2 = jhash(src, strlen(src), 1) & (HYMO_BLOOM_SIZE - 1);
				set_bit(h1, hymo_path_bloom);
				set_bit(h2, hymo_path_bloom);
				atomic_inc(&hymo_rule_count);
			} else {
				kfree(e->src);
				kfree(e->target);
				kfree(e);
			}
		}
	}
}

/* Register a nested merge_entry from within materialize (process context).
 * Mirrors the ADD_MERGE_RULE ioctl's entry construction. Returns true when
 * a new entry was inserted. Does not take ownership of src_str/target_str.
 *
 * Used so that DT_DIR children discovered while materializing a parent merge
 * become their own merge rules, instead of being registered as DT_DIR
 * entries in hymo_paths. The latter would cause getname_flags to
 * wholesale-redirect any lookup of that subdir to the module's (typically
 * incomplete) copy, destroying real subdir content. A nested merge rule, by
 * contrast, keeps the real subdir intact and only performs iterate_dir-time
 * injection of the module's contents on top.
 */
static bool hymofs_register_nested_merge(const char *src_str,
					 const char *target_str)
{
	struct hymo_merge_entry *me, *existing;
	char *resolved_src = NULL;
	struct dentry *tgt_dentry = NULL;
	struct path mpath;
	u32 hash;
	bool created = false;

	if (!src_str || !target_str)
		return false;
	if (!hymo_kern_path)
		return false;

	if (hymo_kern_path(src_str, LOOKUP_FOLLOW, &mpath) == 0) {
		char *rbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (rbuf && hymo_d_path) {
			char *res = hymo_d_path(&mpath, rbuf, PATH_MAX);
			if (!IS_ERR(res) && res[0] == '/' &&
			    strcmp(res, src_str) != 0)
				resolved_src = kstrdup(res, GFP_KERNEL);
		}
		kfree(rbuf);
		path_put(&mpath);
	}
	if (hymo_kern_path(target_str, LOOKUP_FOLLOW, &mpath) == 0) {
		tgt_dentry = dget(mpath.dentry);
		path_put(&mpath);
	}

	hash = full_name_hash(NULL, src_str, strlen(src_str));
	mutex_lock(&hymo_config_mutex);
	hlist_for_each_entry(existing,
		&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)], node) {
		if (strcmp(existing->src, src_str) == 0 &&
		    strcmp(existing->target, target_str) == 0) {
			mutex_unlock(&hymo_config_mutex);
			kfree(resolved_src);
			if (tgt_dentry)
				dput(tgt_dentry);
			return false;
		}
	}
	me = kmalloc(sizeof(*me), GFP_KERNEL);
	if (me) {
		me->src = kstrdup(src_str, GFP_KERNEL);
		me->target = kstrdup(target_str, GFP_KERNEL);
		me->resolved_src = resolved_src;
		me->target_dentry = tgt_dentry;
		if (me->src && me->target) {
			hlist_add_head_rcu(&me->node,
				&hymo_merge_dirs[hash_min(hash, HYMO_HASH_BITS)]);
			resolved_src = NULL;
			tgt_dentry = NULL;
			created = true;
		} else {
			kfree(me->src);
			kfree(me->target);
			kfree(me);
		}
	}
	mutex_unlock(&hymo_config_mutex);

	if (created) {
		hymofs_add_inject_rule(kstrdup(src_str, GFP_KERNEL));
		if (me->resolved_src)
			hymofs_add_inject_rule(kstrdup(me->resolved_src,
						       GFP_KERNEL));
		hymofs_mark_dir_has_inject(src_str);
		if (me->resolved_src)
			hymofs_mark_dir_has_inject(me->resolved_src);
	}

	kfree(resolved_src);
	if (tgt_dentry)
		dput(tgt_dentry);
	return created;
}

struct hymo_mat_ctx {
	struct dir_context ctx;
	const char *src_prefix;
	const char *target_dir;
	int depth;
};

static HYMO_NOCFI HYMO_FILLDIR_RET_TYPE
hymo_mat_filldir(struct dir_context *ctx, const char *name,
		 int namlen, loff_t offset, u64 ino, unsigned int d_type)
{
	struct hymo_mat_ctx *mc = container_of(ctx, struct hymo_mat_ctx, ctx);
	char *src_path, *tgt_path, *inj_dir;

	(void)offset; (void)ino;

	if (namlen <= 2 && name[0] == '.') {
		if (namlen == 1 || (namlen == 2 && name[1] == '.'))
			return HYMO_FILLDIR_CONTINUE;
	}
	if (namlen == 8 && memcmp(name, ".replace", 8) == 0)
		return HYMO_FILLDIR_CONTINUE;

	src_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->src_prefix, namlen, name);
	tgt_path = kasprintf(GFP_KERNEL, "%s/%.*s", mc->target_dir, namlen, name);
	if (!src_path || !tgt_path) {
		kfree(src_path);
		kfree(tgt_path);
		return HYMO_FILLDIR_CONTINUE;
	}

	/* For DT_DIR: register a nested merge_entry and recurse. Do NOT add a
	 * DT_DIR entry to hymo_paths — hymofs_resolve_target() matches it by
	 * exact strcmp in getname_flags, which would wholesale-redirect every
	 * lookup of this subdir (e.g. an open of /product/overlay/foo would
	 * resolve against the module's incomplete foo, hiding all real
	 * siblings). The nested merge_entry gives this subdir its own
	 * iterate_dir-time injection instead, so the real subdir contents stay
	 * visible.
	 *
	 * For non-directory children we still register an exact redirect in
	 * hymo_paths so open() of that file routes to the module backing.
	 */
	if (d_type == DT_DIR) {
		if (mc->depth < 8) {
			hymofs_register_nested_merge(src_path, tgt_path);
			hymofs_materialize_merge(src_path, tgt_path,
						 mc->depth + 1);
		}
	} else {
		hymofs_add_path_entry(src_path, tgt_path, d_type);
	}

	inj_dir = kstrdup(mc->src_prefix, GFP_KERNEL);
	if (inj_dir)
		hymofs_add_inject_rule(inj_dir);
	hymofs_mark_dir_has_inject(mc->src_prefix);

	kfree(src_path);
	kfree(tgt_path);
	return HYMO_FILLDIR_CONTINUE;
}

HYMO_NOCFI void hymofs_materialize_merge(const char *src_prefix,
					 const char *target_dir,
					 int depth)
{
	struct path path;
	struct file *f;
	struct hymo_mat_ctx mctx;

	if (!hymo_kern_path || !hymo_dentry_open || depth > 8)
		return;
	if (hymo_kern_path(target_dir, LOOKUP_FOLLOW, &path) != 0)
		return;

	f = hymo_dentry_open(&path, O_RDONLY | O_DIRECTORY, current_cred());
	if (IS_ERR(f)) {
		path_put(&path);
		return;
	}

	mctx.ctx.actor = hymo_mat_filldir;
	mctx.ctx.pos = 0;
	mctx.src_prefix = src_prefix;
	mctx.target_dir = target_dir;
	mctx.depth = depth;

	iterate_dir(f, &mctx.ctx);

	fput(f);
	path_put(&path);
}
