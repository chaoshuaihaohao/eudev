/*
 * Copyright (C) 2004-2009 Kay Sievers <kay@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if 0
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <sys/sysmacros.h>
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/signalfd.h>

#include "missing.h"
#include "udev.h"
#include "udev-util.h"

#ifndef HAVE_UNSHARE
#include <sys/syscall.h>
/* Provide our own replacement with local reach*/
static inline int unshare(int x)
{
	return syscall(SYS_unshare, x);
}
#endif

#ifndef _USE_GNU
/* Make sure CLONE_NEWNS macro is available */
#include <linux/sched.h>
#endif


static void exec_list_utcs(struct udev *udev, struct udev_event *event,
		      struct udev_rules *rules,
		      struct udev_enumerate *udev_enumerate, const char *action,
		      sigset_t *sigmask_orig)
{
	_cleanup_udev_device_unref_ struct udev_device *dev = NULL;
	struct udev_list_entry *entry;
	sigset_t mask;
	const char *devpath;

	udev_list_entry_foreach(entry,
				udev_enumerate_get_list_entry(udev_enumerate)) {

		char filename[UTIL_PATH_SIZE];
		char syspath[UTIL_PATH_SIZE];
		int fd;

		bzero(filename, sizeof(filename));
		strscpyl(filename, sizeof(filename),
			 udev_list_entry_get_name(entry), NULL, NULL);
		devpath = filename;
		/* add /sys if needed */
		if (!startswith(devpath, "/sys"))
			strscpyl(syspath, sizeof(syspath), "/sys", devpath,
				 NULL);
		else
			strscpy(syspath, sizeof(syspath), devpath);
		util_remove_trailing_chars(syspath, '/');
		dev =
		    udev_device_new_from_synthetic_event(udev, syspath, action);
		if (dev == NULL) {
			log_debug("unknown device '%s'", devpath);
			return;
		}
		event = udev_event_new(dev);
		sigfillset(&mask);
		sigprocmask(SIG_SETMASK, &mask, sigmask_orig);
		event->fd_signal = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
		if (event->fd_signal < 0) {
			fprintf(stderr, "error creating signalfd\n");
			return;
		}
		/* don't read info from the db */
		udev_device_set_info_loaded(dev);

		udev_event_execute_rules(event,
					 3 * USEC_PER_SEC, USEC_PER_SEC,
					 NULL, rules, sigmask_orig);
		udev_event_execute_run(event,
				       300 * USEC_PER_SEC, USEC_PER_SEC, NULL);
	}

}

static int uutcs(struct udev *udev, int argc, char *argv[]) {
	_cleanup_udev_event_unref_ struct udev_event *event = NULL;
	_cleanup_udev_device_unref_ struct udev_device *dev = NULL;
	_cleanup_udev_rules_unref_ struct udev_rules *rules = NULL;
	_cleanup_udev_enumerate_unref_ struct udev_enumerate *udev_enumerate =
	    NULL;
	const char *action = "change";
	sigset_t mask, sigmask_orig;

	log_set_target(LOG_TARGET_CONSOLE);
	log_set_max_level(LOG_DEBUG);

	udev = udev_new();
	if (udev == NULL)
		return EXIT_FAILURE;

	log_debug("version %s", VERSION);
	mac_selinux_init("/dev");

	sigprocmask(SIG_SETMASK, NULL, &sigmask_orig);


	rules = udev_rules_new_utcs(udev, 1);
	if (rules == NULL) {
		fprintf(stderr, "new udev rules failed\n");
		return -ENOMEM;
	}

	udev_enumerate = udev_enumerate_new(udev);
	if (udev_enumerate == NULL)
		goto out;



	//scan device
	udev_enumerate_scan_devices(udev_enumerate);
	//udev_enumerate_scan_subsystems(udev_enumerate);
	exec_list_utcs(udev, event, rules, udev_enumerate, action, &sigmask_orig);

out:
	if (!udev_enumerate)
		free(udev_enumerate);
	if (!rules)
		free(rules);
	mac_selinux_finish();
	udev_builtin_exit(udev);
	return EXIT_SUCCESS;
}

const struct udevadm_cmd udevadm_utcs = {
        .name = "utcs",
        .cmd = uutcs,
        .help = "Query sysfs and exec the rules",
};
