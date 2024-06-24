#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/printk.h>
#include <linux/namei.h>
#include <linux/list.h>
#include <linux/init_task.h>
#include <linux/limits.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/susfs.h>
#include <mount.h>

LIST_HEAD(LH_SUS_PATH);
LIST_HEAD(LH_KSTAT_SPOOFER);
LIST_HEAD(LH_SUS_MOUNT);
LIST_HEAD(LH_MAPS_SPOOFER);
LIST_HEAD(LH_SUS_PROC_FD_LINK);
LIST_HEAD(LH_TRY_UMOUNT_PATH);
LIST_HEAD(LH_MOUNT_ID_RECORDER);

struct st_susfs_uname my_uname;

spinlock_t susfs_spin_lock;
spinlock_t susfs_mnt_id_recorder_spin_lock;

bool is_log_enable = true;
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
#ifdef CONFIG_KSU_SUSFS_DEBUG
#define SUSFS_LOGD(fmt, ...) if (is_log_enable) pr_debug("susfs: " fmt, ##__VA_ARGS__)
#endif /* CONFIG_KSU_SUSFS_DEBUG */
#define SUSFS_LOGI(fmt, ...) if (is_log_enable) pr_info("susfs: " fmt, ##__VA_ARGS__)
#define SUSFS_LOGE(fmt, ...) if (is_log_enable) pr_err("susfs: " fmt, ##__VA_ARGS__)
#else
#ifdef CONFIG_KSU_SUSFS_DEBUG
#define SUSFS_LOGD(fmt, ...)
#endif /* CONFIG_KSU_SUSFS_DEBUG */
#define SUSFS_LOGI(fmt, ...)
#define SUSFS_LOGE(fmt, ...)
#endif /* CONFIG_KSU_SUSFS_ENABLE_LOG */

int susfs_add_sus_path(struct st_susfs_sus_path* __user user_info) {
	struct st_susfs_sus_path_list *cursor, *temp;
	struct st_susfs_sus_path_list *new_list = NULL;
	struct st_susfs_sus_path info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_path))) {
		SUSFS_LOGE("susfs_add_sus_path: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_SUS_PATH, list) {
		if (!strcmp(info.target_pathname, cursor->info.target_pathname)) {
			SUSFS_LOGE("susfs_add_sus_path: target_pathname: '%s' is already created in LH_SUS_PATH\n", info.target_pathname);
			return 1;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: list_for_each_entry_safe completed\n");
#endif

	new_list = kmalloc(sizeof(struct st_susfs_sus_path_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_sus_path: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_sus_path));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: memcpy completed\n");
#endif

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_SUS_PATH);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_path: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_sus_path: target_pathname: '%s' is successfully added to LH_SUS_PATH\n", info.target_pathname);
	return 0;
}

int susfs_add_sus_mount(struct st_susfs_sus_mount* __user user_info) {
	struct st_susfs_sus_mount_list *cursor, *temp;
	struct st_susfs_sus_mount_list *new_list = NULL;
	struct st_susfs_sus_mount info;
	int list_count = 0;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_mount))) {
		SUSFS_LOGE("susfs_add_sus_mount: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_SUS_MOUNT, list) {
		if (!strcmp(cursor->info.target_pathname, info.target_pathname)) {
			SUSFS_LOGE("susfs_add_sus_mount: target_pathname: '%s' is already created in LH_SUS_MOUNT\n", cursor->info.target_pathname);
			return 1;
		}
		list_count += 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: list_for_each_entry_safe completed\n");
#endif

	if (list_count == SUSFS_MAX_SUS_MNTS) {
		SUSFS_LOGE("susfs_add_sus_mount: LH_SUS_MOUNT has reached the list limit of %d\n", SUSFS_MAX_SUS_MNTS);
		return 1;
	}

	new_list = kmalloc(sizeof(struct st_susfs_sus_mount_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_sus_mount: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_sus_mount));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: memcpy completed\n");
#endif

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_SUS_MOUNT);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_mount: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_sus_mount: target_pathname: '%s', is successfully added to LH_SUS_MOUNT\n", new_list->info.target_pathname);
	return 0;
}

int susfs_add_sus_kstat(struct st_susfs_sus_kstat* __user user_info) {
	struct st_susfs_sus_kstat_list *cursor, *temp;
	struct st_susfs_sus_kstat_list *new_list = NULL;
	struct st_susfs_sus_kstat info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_kstat))) {
		SUSFS_LOGE("susfs_add_sus_kstat: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_KSTAT_SPOOFER, list) {
		if (cursor->info.target_ino == info.target_ino) {
			if (info.target_pathname[0] != '\0') {
				SUSFS_LOGE("susfs_add_sus_kstat: target_pathname: '%s' is already created in LH_KSTAT_SPOOFER\n", info.target_pathname);
			} else {
				SUSFS_LOGE("susfs_add_sus_kstat: target_ino: '%lu' is already created in LH_KSTAT_SPOOFER\n", info.target_ino);
			}
			return 1;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: list_for_each_entry_safe completed\n");
#endif

	new_list = kmalloc(sizeof(struct st_susfs_sus_kstat_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_sus_kstat: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_sus_kstat));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: memcpy completed\n");
#endif

	/* Seems the dev number issue is finally solved, the userspace stat we see is already a encoded dev
	 * which is set by new_encode_dev() / huge_encode_dev() function for 64bit system and
	 * old_encode_dev() for 32bit only system, that's why we need to decode it in kernel as well,
	 * and different kernel may have different function to encode the dev number, be cautious!
	 * Also check your encode_dev() macro in fs/stat.c to determine which one to use
	 */
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	new_list->info.spoofed_dev = new_decode_dev(new_list->info.spoofed_dev);
#else
	new_list->info.spoofed_dev = huge_decode_dev(new_list->info.spoofed_dev);
#endif /* CONFIG_MIPS */
#else
	new_list->info.spoofed_dev = old_decode_dev(new_list->info.spoofed_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */
	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_KSTAT_SPOOFER);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_kstat: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_sus_kstat: target_ino: '%lu', target_pathname: '%s', spoofed_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '%lu', spoofed_nlink: '%u', spoofed_atime_tv_sec: '%ld', spoofed_mtime_tv_sec: '%ld', spoofed_ctime_tv_sec: '%ld', spoofed_atime_tv_nsec: '%ld', spoofed_mtime_tv_nsec: '%ld', spoofed_ctime_tv_nsec: '%ld', is successfully added to LH_KSTAT_SPOOFER\n",
		new_list->info.target_ino , new_list->info.target_pathname, new_list->info.spoofed_pathname,
		new_list->info.spoofed_ino, new_list->info.spoofed_dev, new_list->info.spoofed_nlink,
		new_list->info.spoofed_atime_tv_sec, new_list->info.spoofed_mtime_tv_sec, new_list->info.spoofed_ctime_tv_sec,
		new_list->info.spoofed_atime_tv_nsec, new_list->info.spoofed_mtime_tv_nsec, new_list->info.spoofed_ctime_tv_nsec);
	return 0;
}

int susfs_update_sus_kstat(struct st_susfs_sus_kstat* __user user_info) {
	struct st_susfs_sus_kstat_list *cursor, *temp;
	struct st_susfs_sus_kstat info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_kstat: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_kstat))) {
		SUSFS_LOGE("susfs_update_sus_kstat: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_kstat: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_KSTAT_SPOOFER, list) {
		if (!strcmp(info.target_pathname, cursor->info.target_pathname)) {
			SUSFS_LOGI("susfs_update_sus_kstat: updating target_ino from '%lu' to '%lu' for pathname: '%s' in LH_KSTAT_SPOOFER\n", cursor->info.target_ino, info.target_ino, info.target_pathname);
			cursor->info.target_ino = info.target_ino;
			return 0;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_kstat: list_for_each_entry_safe completed\n");
#endif

	SUSFS_LOGE("susfs_update_sus_kstat: target_pathname: '%s' is not found in LH_KSTAT_SPOOFER\n", info.target_pathname);
	return 1;
}

int susfs_add_sus_maps(struct st_susfs_sus_maps* __user user_info) {
	struct st_susfs_sus_maps_list *cursor, *temp;
	struct st_susfs_sus_maps_list *new_list = NULL;
	struct st_susfs_sus_maps info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_maps))) {
		SUSFS_LOGE("susfs_add_sus_maps: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: copy_from_user completed\n");
#endif

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	info.target_dev = new_decode_dev(info.target_dev);
#else
	info.target_dev = huge_decode_dev(info.target_dev);
#endif /* CONFIG_MIPS */
#else
	info.target_dev = old_decode_dev(info.target_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */

	list_for_each_entry_safe(cursor, temp, &LH_MAPS_SPOOFER, list) {
		if (cursor->info.is_statically == info.is_statically && !info.is_statically) {
			if (cursor->info.target_ino == info.target_ino) {
				SUSFS_LOGE("susfs_add_sus_maps: is_statically: '%d', target_ino: '%lu', is already created in LH_MAPS_SPOOFER\n",
				info.is_statically, info.target_ino);
				return 1;
			}
		} else if (cursor->info.is_statically == info.is_statically && info.is_statically) {
			if (cursor->info.compare_mode == info.compare_mode && info.compare_mode == 1) {
				if (cursor->info.target_ino == info.target_ino) {
					SUSFS_LOGE("susfs_add_sus_maps: is_statically: '%d', compare_mode: '%d', target_ino: '%lu', is already created in LH_MAPS_SPOOFER\n",
					info.is_statically, info.compare_mode, info.target_ino);
					return 1;
				}
			} else if (cursor->info.compare_mode == info.compare_mode && info.compare_mode == 2) {
				if (cursor->info.target_ino == info.target_ino &&
					cursor->info.is_isolated_entry == info.is_isolated_entry &&
					cursor->info.target_pgoff == info.target_pgoff &&
					cursor->info.target_prot == info.target_prot) {
					SUSFS_LOGE("susfs_add_sus_maps: is_statically: '%d', compare_mode: '%d', target_ino: '%lu', is_isolated_entry: '%d', target_pgoff: '0x%x', target_prot: '0x%x', is already created in LH_MAPS_SPOOFER\n",
					info.is_statically, info.compare_mode, info.target_ino,
					info.is_isolated_entry, info.target_pgoff, info.target_prot);
					return 1;
				}
			} else if (cursor->info.compare_mode == info.compare_mode && info.compare_mode == 3) {
				if (info.target_ino == 0 &&
					cursor->info.prev_target_ino == info.prev_target_ino &&
					cursor->info.next_target_ino == info.next_target_ino) {
					SUSFS_LOGE("susfs_add_sus_maps: is_statically: '%d', compare_mode: '%d', target_ino: '%lu', prev_target_ino: '%lu', next_target_ino: '%lu', is already created in LH_MAPS_SPOOFER\n",
					info.is_statically, info.compare_mode, info.target_ino,
					info.prev_target_ino, info.next_target_ino);
					return 1;
				}
			} else if (cursor->info.compare_mode == info.compare_mode && info.compare_mode == 4) {
				if (cursor->info.is_file == info.is_file &&
					cursor->info.target_dev == info.target_dev &&
					cursor->info.target_pgoff == info.target_pgoff &&
					cursor->info.target_prot == info.target_prot &&
					cursor->info.target_addr_size == info.target_addr_size) {
					SUSFS_LOGE("susfs_add_sus_maps: is_statically: '%d', compare_mode: '%d', is_file: '%d', target_dev: '0x%x', target_pgoff: '0x%x', target_prot: '0x%x', target_addr_size: '0x%x', is already created in LH_MAPS_SPOOFER\n",
					info.is_statically, info.compare_mode, info.is_file,
					info.target_dev, info.target_pgoff, info.target_prot,
					info.target_addr_size);
					return 1;
				}
			}
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: list_for_each_entry_safe completed\n");
#endif

	new_list = kmalloc(sizeof(struct st_susfs_sus_maps_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_sus_maps: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_sus_maps));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: memcpy completed\n");
#endif

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	new_list->info.spoofed_dev = new_decode_dev(new_list->info.spoofed_dev);
#else
	new_list->info.spoofed_dev = huge_decode_dev(new_list->info.spoofed_dev);
#endif /* CONFIG_MIPS */
#else
	new_list->info.spoofed_dev = old_decode_dev(new_list->info.spoofed_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */
	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_MAPS_SPOOFER);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_maps: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_sus_maps: is_statically: '%d', compare_mode: '%d', is_isolated_entry: '%d', is_file: '%d', prev_target_ino: '%lu', next_target_ino: '%lu', target_ino: '%lu', target_dev: '0x%x', target_pgoff: '0x%x', target_prot: '0x%x', target_addr_size: '0x%x', spoofed_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '0x%x', spoofed_pgoff: '0x%x', spoofed_prot: '0x%x', is successfully added to LH_MAPS_SPOOFER\n",
	new_list->info.is_statically, new_list->info.compare_mode, new_list->info.is_isolated_entry,
	new_list->info.is_file, new_list->info.prev_target_ino, new_list->info.next_target_ino,
	new_list->info.target_ino, new_list->info.target_dev, new_list->info.target_pgoff,
	new_list->info.target_prot, new_list->info.target_addr_size, new_list->info.spoofed_pathname,
	new_list->info.spoofed_ino, new_list->info.spoofed_dev, new_list->info.spoofed_pgoff,
	new_list->info.spoofed_prot);

	return 0;
}

int susfs_update_sus_maps(struct st_susfs_sus_maps* __user user_info) {
	struct st_susfs_sus_maps_list *cursor, *temp;
	struct st_susfs_sus_maps info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_maps: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_maps))) {
		SUSFS_LOGE("susfs_update_sus_maps: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_maps: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_MAPS_SPOOFER, list) {
		if (cursor->info.is_statically == info.is_statically && !info.is_statically) {
			if (!strcmp(info.target_pathname, cursor->info.target_pathname)) {
				SUSFS_LOGI("susfs_update_sus_maps: updating target_ino from '%lu' to '%lu' for pathname: '%s' in LH_MAPS_SPOOFER\n", cursor->info.target_ino, info.target_ino, info.target_pathname);
				cursor->info.target_ino = info.target_ino;
				return 0;
			}
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_update_sus_maps: list_for_each_entry_safe completed\n");
#endif

	SUSFS_LOGE("susfs_update_sus_maps: target_pathname: '%s' is not found in LH_MAPS_SPOOFER\n", info.target_pathname);
	return 1;
}

int susfs_add_sus_proc_fd_link(struct st_susfs_sus_proc_fd_link* __user user_info) {
	struct st_susfs_sus_proc_fd_link_list *cursor, *temp;
	struct st_susfs_sus_proc_fd_link_list *new_list = NULL;
	struct st_susfs_sus_proc_fd_link info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_sus_proc_fd_link))) {
		SUSFS_LOGE("susfs_add_sus_proc_fd_link: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_SUS_PROC_FD_LINK, list) {
		if (!strcmp(info.target_link_name, cursor->info.target_link_name)) {
			SUSFS_LOGE("susfs_add_sus_proc_fd_link: target_link_name: '%s' is already created in LH_SUS_PROC_FD_LINK\n", info.target_link_name);
			return 1;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: list_for_each_entry_safe completed\n");
#endif

	new_list = kmalloc(sizeof(struct st_susfs_sus_proc_fd_link_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_sus_proc_fd_link: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_sus_proc_fd_link));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: memcpy completed\n");
#endif

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_SUS_PROC_FD_LINK);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_sus_proc_fd_link: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_sus_proc_fd_link: target_link_name: '%s', spoofed_link_name: '%s', is successfully added to LH_SUS_PROC_FD_LINK\n",
				new_list->info.target_link_name, new_list->info.spoofed_link_name);
	return 0;
}

int susfs_add_try_umount(struct st_susfs_try_umount* __user user_info) {
	struct st_susfs_try_umount_list *cursor, *temp;
	struct st_susfs_try_umount_list *new_list = NULL;
	struct st_susfs_try_umount info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_try_umount))) {
		SUSFS_LOGE("susfs_add_try_umount: failed copying from userspace\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: copy_from_user completed\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_TRY_UMOUNT_PATH, list) {
		if (!strcmp(info.target_pathname, cursor->info.target_pathname)) {
			SUSFS_LOGE("susfs_add_try_umount: target_pathname: '%s' is already created in LH_TRY_UMOUNT_PATH\n", info.target_pathname);
			return 1;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: list_for_each_entry_safe completed\n");
#endif

	new_list = kmalloc(sizeof(struct st_susfs_try_umount_list), GFP_KERNEL);
	if (!new_list) {
		SUSFS_LOGE("susfs_add_try_umount: kmalloc() failed\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: kmalloc completed\n");
#endif

	memcpy(&new_list->info, &info, sizeof(struct st_susfs_try_umount));

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: memcpy completed\n");
#endif

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_spin_lock);
	list_add_tail(&new_list->list, &LH_TRY_UMOUNT_PATH);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_try_umount: list_add_tail completed\n");
#endif

	SUSFS_LOGI("susfs_add_try_umount: target_pathname: '%s', mnt_mode: %d, is successfully added to LH_TRY_UMOUNT_PATH\n", new_list->info.target_pathname, new_list->info.mnt_mode);
	return 0;
}

int susfs_set_uname(struct st_susfs_uname* __user user_info) {
	struct st_susfs_uname info;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_set_uname: called\n");
#endif

	if (copy_from_user(&info, user_info, sizeof(struct st_susfs_uname))) {
		SUSFS_LOGE("susfs_set_uname: failed copying from userspace.\n");
		return 1;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_set_uname: copy_from_user completed\n");
#endif

	spin_lock(&susfs_spin_lock);
	strncpy(my_uname.sysname, info.sysname, __NEW_UTS_LEN);
	strncpy(my_uname.nodename, info.nodename, __NEW_UTS_LEN);
	strncpy(my_uname.release, info.release, __NEW_UTS_LEN);
	strncpy(my_uname.version, info.version, __NEW_UTS_LEN);
	strncpy(my_uname.machine, info.machine, __NEW_UTS_LEN);
	SUSFS_LOGI("susfs_set_uname: Setting sysname: '%s', nodename: '%s', release: '%s', version: '%s', machine: '%s'\n",
				my_uname.sysname, my_uname.nodename, my_uname.release, my_uname.version, my_uname.machine);
	spin_unlock(&susfs_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_set_uname: spin_unlock completed\n");
#endif

	return 0;
}

int susfs_sus_path_by_path(const struct path* file, int* errno_to_be_changed, int syscall_family) {
	int res = 0;
	int status = 0;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;
	struct st_susfs_sus_path_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_path_by_path: called\n");
#endif

	if (!uid_matches_suspicious_path() || file == NULL) {
		return status; // status == 0
	}

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (path == NULL) {
		SUSFS_LOGE("susfs_sus_path_by_path: kmalloc() failed\n");
		return status; // status == 0
	}

	ptr = d_path(file, path, PATH_MAX);
	if (IS_ERR(ptr)) {
		SUSFS_LOGE("susfs_sus_path_by_path: d_path() failed\n");
		goto out;
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		goto out; // status == 0
	}

	res = end - path;
	path[(size_t) res] = '\0';

	list_for_each_entry_safe(cursor, temp, &LH_SUS_PATH, list) {
		if (!strcmp(cursor->info.target_pathname, path)) {
			SUSFS_LOGI("susfs_sus_path_by_path: hiding target_pathname: '%s', target_ino: '%lu', for UID %i\n", cursor->info.target_pathname, cursor->info.target_ino, current_uid().val);
			if (errno_to_be_changed != NULL) {
				susfs_change_error_no_by_pathname(path, errno_to_be_changed, syscall_family);
			}
			status = 1;
			goto out;
		}
	}

out:
	kfree(path);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_path_by_path: kfree completed\n");
#endif

	return status;
}

int susfs_sus_path_by_filename(struct filename* name, int* errno_to_be_changed, int syscall_family) {
	int status = 0;
	int ret = 0;
	struct path path;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_path_by_filename: called\n");
#endif

	if (IS_ERR(name)) {
		return status; // status == 0
	}

	if (!uid_matches_suspicious_path() || name == NULL) {
		return status; // status == 0
	}

	ret = kern_path(name->name, LOOKUP_FOLLOW, &path);

	if (!ret) {
		status = susfs_sus_path_by_path(&path, errno_to_be_changed, syscall_family);
		path_put(&path);
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_path_by_filename: kern_path completed\n");
#endif

	return status;
}

int susfs_sus_ino_for_filldir64(unsigned long ino) {
	struct st_susfs_sus_path_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_ino_for_filldir64: called\n");
#endif

	if (!uid_matches_suspicious_path()) return 0;
	list_for_each_entry_safe(cursor, temp, &LH_SUS_PATH, list) {
		if (cursor->info.target_ino == ino) {
			SUSFS_LOGI("susfs_sus_ino_for_filldir64: hiding target_pathname: '%s', target_ino: '%lu', for UID %i\n", cursor->info.target_pathname, cursor->info.target_ino, current_uid().val);
			return 1;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_ino_for_filldir64: list_for_each_entry_safe completed\n");
#endif

	return 0;
}

int susfs_sus_mount(struct vfsmount* mnt, struct path* root) {
	int res = 0;
	int status = 0;
	char* path = NULL;
	char* ptr = NULL;
	char* end = NULL;
	struct path mnt_path = {
		.dentry = mnt->mnt_root,
		.mnt = mnt
	};
	struct st_susfs_sus_mount_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_mount: called\n");
#endif

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (path == NULL) {
		SUSFS_LOGE("susfs_sus_mount: kmalloc() failed\n");
		return status; // status == 0
	}

	ptr = d_path(&mnt_path, path, PATH_MAX);
	if (IS_ERR(ptr)) {
		SUSFS_LOGE("susfs_sus_mount: d_path() failed\n");
		goto out; // status == 0
	}

	end = mangle_path(path, ptr, " \t\n\\");

	if (!end) {
		goto out; // status == 0
	}

	res = end - path;
	path[(size_t) res] = '\0';

	list_for_each_entry_safe(cursor, temp, &LH_SUS_MOUNT, list) {
		if (!strcmp(path, cursor->info.target_pathname)) {
			SUSFS_LOGI("susfs_sus_mount: target_pathname '%s' won't be shown to process with UID %i\n",
						cursor->info.target_pathname, current_uid().val);
			status = 1;
			goto out;
		}
	}

out:
	kfree(path);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_mount: kfree completed\n");
#endif

	return status;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
void susfs_sus_kstat(unsigned long ino, struct stat64* out_stat) {
#else
void susfs_sus_kstat(unsigned long ino, struct stat* out_stat) {
#endif
	struct st_susfs_sus_kstat_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_kstat: called\n");
#endif

	if (!uid_matches_suspicious_kstat()) return;
	list_for_each_entry_safe(cursor, temp, &LH_KSTAT_SPOOFER, list) {
		if (cursor->info.target_ino == ino) {
			SUSFS_LOGI("susfs_sus_kstat: spoofing kstat for pathname '%s' for UID %i\n", cursor->info.target_pathname, current_uid().val);
			out_stat->st_ino = cursor->info.spoofed_ino;
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
			out_stat->st_dev = new_encode_dev(cursor->info.spoofed_dev);
#else
			out_stat->st_dev = huge_encode_dev(cursor->info.spoofed_dev);
#endif /* CONFIG_MIPS */
#else
			out_stat->st_dev = old_encode_dev(cursor->info.spoofed_dev);
#endif /* defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64) */
			out_stat->st_nlink = cursor->info.spoofed_nlink;
			out_stat->st_atime = cursor->info.spoofed_atime_tv_sec;
			out_stat->st_mtime = cursor->info.spoofed_mtime_tv_sec;
			out_stat->st_ctime = cursor->info.spoofed_ctime_tv_sec;
#ifdef _STRUCT_TIMESPEC
			out_stat->st_atime_nsec = cursor->info.spoofed_atime_tv_nsec;
			out_stat->st_mtime_nsec = cursor->info.spoofed_mtime_tv_nsec;
			out_stat->st_ctime_nsec = cursor->info.spoofed_ctime_tv_nsec;
#endif
			return;
		}
	}
}

/* for non statically, it only compare with target_ino, and spoof only the ino, dev to the matched entry
 * for staticially, it compares depending on the mode user chooses
 * compare mode:
 *  1 -> target_ino is 'non-zero', all entries match with target_ino will be spoofed with user defined entry
 *  2 -> target_ino is 'non-zero', all entries match with [target_ino,target_prot,target_pgoff,is_isolated_entry] will be spoofed with user defined entry
 *  3 -> target_ino is 'zero', which is not file, all entries match with [prev_target_ino,next_target_ino] will be spoofed with user defined entry
 *  4 -> target_ino is 'zero' or 'non-zero', all entries match with [is_file,target_addr_size,target_prot,target_pgoff,target_dev] will be spoofed with user defined entry
 */
int susfs_sus_maps(unsigned long target_ino, unsigned long target_address_size, unsigned long* orig_ino, dev_t* orig_dev, vm_flags_t* flags, unsigned long long* pgoff, struct vm_area_struct* vma, char* tmpname) {
	struct st_susfs_sus_maps_list *cursor, *temp;
	struct inode *tmp_inode, *tmp_inode_prev, *tmp_inode_next;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_maps: called\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_MAPS_SPOOFER, list) {
		// if it is NOT statically
		if (!cursor->info.is_statically) {
			if (target_ino != 0 && cursor->info.target_ino == target_ino) {
				*orig_ino = cursor->info.spoofed_ino;
				*orig_dev = cursor->info.spoofed_dev;
				SUSFS_LOGI("susfs_sus_maps: spoofing maps -> is_statically: '%d', compare_mode: '%d', is_file: '%d', is_isolated_entry: '%d', prev_target_ino: '%lu', next_target_ino: '%lu', target_ino: '%lu', target_dev: '0x%x', target_pgoff: '0x%x', target_prot: '0x%x', target_addr_size: '0x%x', spoofed_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '0x%x', spoofed_pgoff: '0x%x', spoofed_prot: '0x%x'\n",
				cursor->info.is_statically, cursor->info.compare_mode, cursor->info.is_file,
				cursor->info.is_isolated_entry, cursor->info.prev_target_ino, cursor->info.next_target_ino,
				cursor->info.target_ino, cursor->info.target_dev, cursor->info.target_pgoff,
				cursor->info.target_prot, cursor->info.target_addr_size, cursor->info.spoofed_pathname,
				cursor->info.spoofed_ino, cursor->info.spoofed_dev, cursor->info.spoofed_pgoff,
				cursor->info.spoofed_prot);
				return 1;
			}
		// if it is statically, then compare with compare_mode
		} else if (cursor->info.compare_mode > 0) {
			switch(cursor->info.compare_mode) {
				case 1:
					if (target_ino != 0 && cursor->info.target_ino == target_ino) {
						goto do_spoof;
					}
					break;
				case 2:
					if (target_ino != 0 && cursor->info.target_ino == target_ino &&
						((cursor->info.target_prot & VM_READ) == (*flags & VM_READ)) &&
						((cursor->info.target_prot & VM_WRITE) == (*flags & VM_WRITE)) &&
						((cursor->info.target_prot & VM_EXEC) == (*flags & VM_EXEC)) &&
						((cursor->info.target_prot & VM_MAYSHARE) == (*flags & VM_MAYSHARE)) &&
						cursor->info.target_pgoff == *pgoff) {
						// if is NOT isolated_entry, check for vma->vm_next and vma->vm_prev to see if they have the same inode
						if (!cursor->info.is_isolated_entry) {
							if (vma && vma->vm_next && vma->vm_next->vm_file) {
								tmp_inode = file_inode(vma->vm_next->vm_file);
								if (tmp_inode->i_ino == cursor->info.target_ino ||
									tmp_inode->i_ino == (cursor->info.target_ino+1) ||
									tmp_inode->i_ino == (cursor->info.target_ino-1)) {
									goto do_spoof;
								}
							}
							if (vma && vma->vm_prev && vma->vm_prev->vm_file) {
								tmp_inode = file_inode(vma->vm_prev->vm_file);
								if (tmp_inode->i_ino == cursor->info.target_ino ||
									tmp_inode->i_ino == (cursor->info.target_ino+1) ||
									tmp_inode->i_ino == (cursor->info.target_ino-1)) {
									goto do_spoof;
								}
							}
						// if it is isolated_entry
						} else {
							if (vma && vma->vm_next && vma->vm_next->vm_file) {
								tmp_inode = file_inode(vma->vm_next->vm_file);
								if (tmp_inode->i_ino == cursor->info.target_ino) {
									continue;
								}
							}
							if (vma && vma->vm_prev && vma->vm_prev->vm_file) {
								tmp_inode = file_inode(vma->vm_prev->vm_file);
								if (tmp_inode->i_ino == cursor->info.target_ino) {
									continue;
								}
							}
							// both prev and next don't have the same indoe as current entry, we can spoof now
							goto do_spoof;
						}
					}
					break;
				case 3:
					// if current vma is a file, it is not our target
					if (vma->vm_file) continue;
					// compare next target ino only
					if (cursor->info.prev_target_ino == 0 && cursor->info.next_target_ino > 0) {
						if (vma->vm_next && vma->vm_next->vm_file) {
							tmp_inode_next = file_inode(vma->vm_next->vm_file);
							if (tmp_inode_next->i_ino == cursor->info.next_target_ino) {
								goto do_spoof;
							}
						}
					// compare prev target ino only
					} else if (cursor->info.prev_target_ino > 0 && cursor->info.next_target_ino == 0) {
						if (vma->vm_prev && vma->vm_prev->vm_file) {
							tmp_inode_prev = file_inode(vma->vm_prev->vm_file);
							if (tmp_inode_prev->i_ino == cursor->info.prev_target_ino) {
								goto do_spoof;
							}
						}
					// compare both prev ino and next ino
					} else if (cursor->info.prev_target_ino > 0 && cursor->info.next_target_ino > 0) {
						if (vma->vm_prev && vma->vm_prev->vm_file &&
							vma->vm_next && vma->vm_next->vm_file) {
							tmp_inode_prev = file_inode(vma->vm_prev->vm_file);
							tmp_inode_next = file_inode(vma->vm_next->vm_file);
							if (tmp_inode_prev->i_ino == cursor->info.prev_target_ino &&
								tmp_inode_next->i_ino == cursor->info.next_target_ino) {
								goto do_spoof;
							}
						}
					}
					break;
				case 4:
					if ((cursor->info.is_file && vma->vm_file)||(!cursor->info.is_file && !vma->vm_file)) {
						if (cursor->info.target_dev == *orig_dev &&
							cursor->info.target_pgoff == *pgoff &&
							((cursor->info.target_prot & VM_READ) == (*flags & VM_READ) &&
							 (cursor->info.target_prot & VM_WRITE) == (*flags & VM_WRITE) &&
							 (cursor->info.target_prot & VM_EXEC) == (*flags & VM_EXEC) &&
							 (cursor->info.target_prot & VM_MAYSHARE) == (*flags & VM_MAYSHARE)) &&
							cursor->info.target_addr_size == target_address_size) {
							goto do_spoof;
						}
					}
					break;
				default:
					break;
			}
		}
		continue;
do_spoof:
		if (cursor->info.need_to_spoof_pathname) {
			strncpy(tmpname, cursor->info.spoofed_pathname, SUSFS_MAX_LEN_PATHNAME-1);
		}
		if (cursor->info.need_to_spoof_ino) {
			*orig_ino = cursor->info.spoofed_ino;
		}
		if (cursor->info.need_to_spoof_dev) {
			*orig_dev = cursor->info.spoofed_dev;
		}
		if (cursor->info.need_to_spoof_prot) {
			if (cursor->info.spoofed_prot & VM_READ) *flags |= VM_READ;
			else *flags = ((*flags | VM_READ) ^ VM_READ);
			if (cursor->info.spoofed_prot & VM_WRITE) *flags |= VM_WRITE;
			else *flags = ((*flags | VM_WRITE) ^ VM_WRITE);
			if (cursor->info.spoofed_prot & VM_EXEC) *flags |= VM_EXEC;
			else *flags = ((*flags | VM_EXEC) ^ VM_EXEC);
			if (cursor->info.spoofed_prot & VM_MAYSHARE) *flags |= VM_MAYSHARE;
			else *flags = ((*flags | VM_MAYSHARE) ^ VM_MAYSHARE);
		}
		if (cursor->info.need_to_spoof_pgoff) {
			*pgoff = cursor->info.spoofed_pgoff;
		}
		SUSFS_LOGI("susfs_sus_maps: spoofing maps -> is_statically: '%d', compare_mode: '%d', is_file: '%d', is_isolated_entry: '%d', prev_target_ino: '%lu', next_target_ino: '%lu', target_ino: '%lu', target_dev: '0x%x', target_pgoff: '0x%x', target_prot: '0x%x', target_addr_size: '0x%x', spoofed_pathname: '%s', spoofed_ino: '%lu', spoofed_dev: '0x%x', spoofed_pgoff: '0x%x', spoofed_prot: '0x%x'\n",
		cursor->info.is_statically, cursor->info.compare_mode, cursor->info.is_file,
		cursor->info.is_isolated_entry, cursor->info.prev_target_ino, cursor->info.next_target_ino,
		cursor->info.target_ino, cursor->info.target_dev, cursor->info.target_pgoff,
		cursor->info.target_prot, cursor->info.target_addr_size, cursor->info.spoofed_pathname,
		cursor->info.spoofed_ino, cursor->info.spoofed_dev, cursor->info.spoofed_pgoff,
		cursor->info.spoofed_prot);
		return 2;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_maps: list_for_each_entry_safe completed\n");
#endif

	return 0;
}

void susfs_sus_proc_fd_link(char *pathname, int len) {
	struct st_susfs_sus_proc_fd_link_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_proc_fd_link: called\n");
#endif

	if (!uid_matches_suspicious_proc_fd_link()) {
		return;
	}

	list_for_each_entry_safe(cursor, temp, &LH_SUS_PROC_FD_LINK, list) {
		if (!strcmp(pathname, cursor->info.target_link_name)) {
			if (strlen(cursor->info.spoofed_link_name) >= len) {
				SUSFS_LOGE("susfs_sus_proc_fd_link: [uid:%u] Cannot spoof fd link: '%s' -> '%s', as spoofed_link_name size is bigger than %d\n", current_uid().val, pathname, cursor->info.spoofed_link_name, len);
				return;
			}
			SUSFS_LOGI("susfs_sus_proc_fd_link: [uid:%u] spoofing fd link: '%s' -> '%s'\n", current_uid().val, pathname, cursor->info.spoofed_link_name);
			strcpy(pathname, cursor->info.spoofed_link_name);
			return;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_sus_proc_fd_link: list_for_each_entry_safe completed\n");
#endif
}

static void umount_mnt(struct path *path, int flags) {
	int err = path_umount(path, flags);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("umount_mnt: called\n");
#endif
	if (err) {
		SUSFS_LOGI("umount_mnt: umount %s failed: %d\n", path->dentry->d_iname, err);
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("umount_mnt: path_umount completed\n");
#endif
}

static bool should_umount(struct path *path)
{
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("should_umount: called\n");
#endif
	if (!path) {
		return false;
	}

	if (current->nsproxy->mnt_ns == init_nsproxy.mnt_ns) {
		SUSFS_LOGI("should_umount: ignore global mnt namespace process: %d\n",
			current_uid().val);
		return false;
	}

	if (path->mnt && path->mnt->mnt_sb && path->mnt->mnt_sb->s_type) {
		const char *fstype = path->mnt->mnt_sb->s_type->name;
		return strcmp(fstype, "overlay") == 0;
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("should_umount: return false\n");
#endif

	return false;
}

static void try_umount(const char *mnt, bool check_mnt, int flags) {
	struct path path;
	int err = kern_path(mnt, 0, &path);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("try_umount: called\n");
#endif

	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		return;
	}

	// we are only interest in some specific mounts
	if (check_mnt && !should_umount(&path)) {
		return;
	}

	umount_mnt(&path, flags);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("try_umount: umount_mnt completed\n");
#endif
}

void susfs_try_umount(uid_t target_uid) {
	struct st_susfs_try_umount_list *cursor, *temp;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_try_umount: called\n");
#endif

	list_for_each_entry_safe(cursor, temp, &LH_TRY_UMOUNT_PATH, list) {
		SUSFS_LOGI("susfs_try_umount: umounting '%s' for uid: %d\n", cursor->info.target_pathname, target_uid);
		if (cursor->info.mnt_mode == 0) {
			try_umount(cursor->info.target_pathname, false, 0);
		} else if (cursor->info.mnt_mode == 1) {
			try_umount(cursor->info.target_pathname, false, MNT_DETACH);
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_try_umount: list_for_each_entry_safe completed\n");
#endif
}

void susfs_spoof_uname(struct new_utsname* tmp) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_spoof_uname: called\n");
#endif

	if (strcmp(my_uname.sysname, "default")) {
		memset(tmp->sysname, 0, __NEW_UTS_LEN);
		strncpy(tmp->sysname, my_uname.sysname, __NEW_UTS_LEN);
	}
	if (strcmp(my_uname.nodename, "default")) {
		memset(tmp->nodename, 0, __NEW_UTS_LEN);
		strncpy(tmp->nodename, my_uname.nodename, __NEW_UTS_LEN);
	}
	if (strcmp(my_uname.release, "default")) {
		memset(tmp->release, 0, __NEW_UTS_LEN);
		strncpy(tmp->release, my_uname.release, __NEW_UTS_LEN);
	}
	if (strcmp(my_uname.version, "default")) {
		memset(tmp->version, 0, __NEW_UTS_LEN);
		strncpy(tmp->version, my_uname.version, __NEW_UTS_LEN);
	}
	if (strcmp(my_uname.machine, "default")) {
		memset(tmp->machine, 0, __NEW_UTS_LEN);
		strncpy(tmp->machine, my_uname.machine, __NEW_UTS_LEN);
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_spoof_uname: completed\n");
#endif
}

void susfs_set_log(bool enabled) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_set_log: called\n");
#endif

	spin_lock(&susfs_spin_lock);
	is_log_enable = enabled;
	spin_unlock(&susfs_spin_lock);
	if (is_log_enable) {
		pr_info("susfs: enable logging to kernel");
	} else {
		pr_info("susfs: disable logging to kernel");
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_set_log: spin_unlock completed\n");
#endif
}

/* For files/directories in /sdcard/ but not in /sdcard/Android/data/, please delete it  
 * by yourself
 */
void susfs_change_error_no_by_pathname(char* const pathname, int* const errno_to_be_changed, int const syscall_family) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_change_error_no_by_pathname: called\n");
#endif

	if (!strncmp(pathname, "/system/", 8)||
		!strncmp(pathname, "/vendor/", 8)) {
		switch(syscall_family) {
			case SYSCALL_FAMILY_ALL_ENOENT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_LINKAT_OLDNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_OLDNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			default:
				*errno_to_be_changed = -EROFS;
				return;
		}
	} else if (!strncmp(pathname, "/storage/emulated/0/Android/data/", 33)) {
		switch(syscall_family) {
			case SYSCALL_FAMILY_ALL_ENOENT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_MKNOD:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_MKDIRAT:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_RMDIR:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_UNLINKAT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_SYMLINKAT_NEWNAME:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_LINKAT_OLDNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_LINKAT_NEWNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_OLDNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_NEWNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			default:
				*errno_to_be_changed = -ENOENT;
				return;
		}
	} else if (!strncmp(pathname, "/dev/", 5)) {
		switch(syscall_family) {
			case SYSCALL_FAMILY_ALL_ENOENT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_MKNOD:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_MKDIRAT:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_RMDIR:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_UNLINKAT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_SYMLINKAT_NEWNAME:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_LINKAT_OLDNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_LINKAT_NEWNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_OLDNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_NEWNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			default:
				*errno_to_be_changed = -ENOENT;
				return;
		}
	} else if (!strncmp(pathname, "/data/", 6)) {
				switch(syscall_family) {
			case SYSCALL_FAMILY_ALL_ENOENT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_MKNOD:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_MKDIRAT:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_RMDIR:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_UNLINKAT:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_SYMLINKAT_NEWNAME:
				*errno_to_be_changed = -EACCES;
				return;
			case SYSCALL_FAMILY_LINKAT_OLDNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_LINKAT_NEWNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_OLDNAME:
				*errno_to_be_changed = -ENOENT;
				return;
			case SYSCALL_FAMILY_RENAMEAT2_NEWNAME:
				*errno_to_be_changed = -EXDEV;
				return;
			default:
				*errno_to_be_changed = -ENOENT;
				return;
		}
	}

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_change_error_no_by_pathname: completed\n");
#endif
}

/* Notes:
 * - The current mechanism cannot deal with umounted path, so to get the best outcome is not to
 *   enable umount by ksu, and put all your mounts to add_sus_mount and add_sus_path
 */
void susfs_add_mnt_id_recorder(void) {
	struct st_susfs_mnt_id_recorder_list *new_list = NULL;
	struct st_susfs_sus_mount_list *sus_mount_cursor;

	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	struct mount *mnt;

	struct path mnt_path;
	char *path = NULL;
	char *p_path = NULL;
	char *end = NULL;
	int res = 0;

	int cur_pid = current->pid;
	int count = 0;

#ifdef CONFIG_KSU_SUSFS_DEBUG
	SUSFS_LOGD("susfs_add_mnt_id_recorder: Starting for pid: %d\n", cur_pid);
#endif

	new_list = kzalloc(sizeof(struct st_susfs_mnt_id_recorder_list), GFP_KERNEL);
	if (!new_list) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
		SUSFS_LOGD("susfs_add_mnt_id_recorder: kmalloc() failed for new_list\n");
#endif
		return;
	}

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	if (path == NULL) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
		SUSFS_LOGD("susfs_add_mnt_id_recorder: kmalloc() failed for path\n");
#endif
		kfree(new_list);
		return;
	}

	new_list->info.pid = cur_pid;

	list_for_each_entry(mnt, &ns->list, mnt_list) {
		if (!mnt) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
			SUSFS_LOGD("susfs_add_mnt_id_recorder: mnt is NULL\n");
#endif
			continue;
		}

		mnt_path.dentry = mnt->mnt.mnt_root;
		mnt_path.mnt = &mnt->mnt;
		p_path = d_path(&mnt_path, path, PATH_MAX);
		if (IS_ERR(p_path)) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
			SUSFS_LOGD("susfs_add_mnt_id_recorder: d_path() failed\n");
#endif
			continue;
		}
		end = mangle_path(path, p_path, " \t\n\\");
		if (!end) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
			SUSFS_LOGD("susfs_add_mnt_id_recorder: mangle_path() failed\n");
#endif
			continue;
		}
		res = end - path;
		path[(size_t) res] = '\0';
		list_for_each_entry(sus_mount_cursor, &LH_SUS_MOUNT, list) {
			if (!strcmp(path, sus_mount_cursor->info.target_pathname)) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
				SUSFS_LOGD("susfs_add_mnt_id_recorder: found target_mnt_id: '%d', target_pathname: '%s' for pid '%d'\n", mnt->mnt_id, sus_mount_cursor->info.target_pathname, cur_pid);
#endif
				new_list->info.target_mnt_id[count++] = mnt->mnt_id;
				new_list->info.count = count;
				break;
			}
		}
	}

	kfree(path);
	if (new_list->info.count == 0) {
		kfree(new_list);
#ifdef CONFIG_KSU_SUSFS_DEBUG
		SUSFS_LOGD("susfs_add_mnt_id_recorder: No matching mounts found for pid: %d\n", cur_pid);
#endif
		return;
	}

	INIT_LIST_HEAD(&new_list->list);
	spin_lock(&susfs_mnt_id_recorder_spin_lock);
	list_add_tail(&new_list->list, &LH_MOUNT_ID_RECORDER);
	spin_unlock(&susfs_mnt_id_recorder_spin_lock);
	SUSFS_LOGI("susfs_add_mnt_id_recorder: recording pid '%u' to LH_MOUNT_ID_RECORDER\n", new_list->info.pid);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_add_mnt_id_recorder: completed\n");
#endif
}

int susfs_get_fake_mnt_id(int mnt_id) {
	struct st_susfs_mnt_id_recorder_list *cursor;
	int cur_pid = current->pid;
	int i;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_get_fake_mnt_id: called\n");
#endif

	SUSFS_LOGI("susfs_get_fake_mnt_id: Starting susfs_get_fake_mnt_id for pid: %d, mnt_id: %d\n", cur_pid, mnt_id);

	list_for_each_entry(cursor, &LH_MOUNT_ID_RECORDER, list) {
		if (cursor->info.pid == cur_pid) {
			SUSFS_LOGI("susfs_get_fake_mnt_id: Found matching pid: %d in LH_MOUNT_ID_RECORDER\n", cur_pid);
			for (i = 0; i < cursor->info.count; i++) {
				// if comparing with first target_mnt_id and mnt_id is before any target_mnt_id
				if (i == 0 && mnt_id < cursor->info.target_mnt_id[i]) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
					SUSFS_LOGD("mnt_id: %d is before first target_mnt_id: %d\n", mnt_id, cursor->info.target_mnt_id[i]);
#endif
					return mnt_id;
				}
				// if comparing with last target_mnt_id and mnt_id is after the last target_mnt_id
				if (i+1 == cursor->info.count && cursor->info.target_mnt_id[i] < mnt_id) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
					SUSFS_LOGD("mnt_id: %d is after last target_mnt_id: %d\n", mnt_id, cursor->info.target_mnt_id[i]);
#endif
					return mnt_id - cursor->info.count;
				}
				// else comparing the target_mnt_id[i] with previous one and next one
				if (cursor->info.target_mnt_id[i-1] < mnt_id && mnt_id < cursor->info.target_mnt_id[i]) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
					SUSFS_LOGD("mnt_id: %d is between target_mnt_id[%d]: %d and target_mnt_id[%d]: %d\n", mnt_id, i-1, cursor->info.target_mnt_id[i-1], i, cursor->info.target_mnt_id[i]);
#endif
					return mnt_id - i;
				}
				if (cursor->info.target_mnt_id[i] < mnt_id && mnt_id < cursor->info.target_mnt_id[i+1]) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
					SUSFS_LOGD("mnt_id: %d is between target_mnt_id[%d]: %d and target_mnt_id[%d]: %d\n", mnt_id, i, cursor->info.target_mnt_id[i], i+1, cursor->info.target_mnt_id[i+1]);
#endif
					return mnt_id - (i+1);
				}
			}
		}
	}
	SUSFS_LOGI("susfs_get_fake_mnt_id: No matching pid: %d found in LH_MOUNT_ID_RECORDER\n", cur_pid);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_get_fake_mnt_id: completed\n");
#endif

	return mnt_id;
}

void susfs_remove_mnt_id_recorder(void) {
	struct st_susfs_mnt_id_recorder_list *cursor, *temp;
	int cur_pid = current->pid;

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_remove_mnt_id_recorder: called\n");
#endif

	spin_lock(&susfs_mnt_id_recorder_spin_lock);
	list_for_each_entry_safe(cursor, temp, &LH_MOUNT_ID_RECORDER, list) {
		if (cursor->info.pid == cur_pid) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
			SUSFS_LOGD("susfs_remove_mnt_id_recorder: removing pid '%u' from LH_MOUNT_ID_RECORDER\n", cursor->info.pid);
#endif
			list_del(&cursor->list);
			kfree(cursor);
			spin_unlock(&susfs_mnt_id_recorder_spin_lock);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_remove_mnt_id_recorder: completed\n");
#endif

			return;
		}
	}
	spin_unlock(&susfs_mnt_id_recorder_spin_lock);
}

static void susfs_my_uname_init(void) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_my_uname_init: called\n");
#endif

	memset(&my_uname, 0, sizeof(struct st_susfs_uname));
	strncpy(my_uname.sysname, "default", __NEW_UTS_LEN);
	strncpy(my_uname.nodename, "default", __NEW_UTS_LEN);
	strncpy(my_uname.release, "default", __NEW_UTS_LEN);
	strncpy(my_uname.version, "default", __NEW_UTS_LEN);
	strncpy(my_uname.machine, "default", __NEW_UTS_LEN);

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_my_uname_init: completed\n");
#endif
}

void __init susfs_init(void) {
#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_init: called\n");
#endif

	spin_lock_init(&susfs_spin_lock);
	spin_lock_init(&susfs_mnt_id_recorder_spin_lock);
	susfs_my_uname_init();

#ifdef CONFIG_KSU_SUSFS_DEBUG
    SUSFS_LOGD("susfs_init: completed\n");
#endif
}
