/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2015-2020  Jolla Ltd. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>

#include <gdbus.h>

#include "../src/connman.h"
#include "vpn.h"

#include "connman/vpn-dbus.h"
#include "src/shared/util.h"

#define CONFIGMAINFILE CONFIGDIR "/connman-vpn.conf"
#define CONFIGMAINDIR CONFIGMAINFILE ".d"
#define CONFIGSUFFIX ".conf"

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			DBG("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gchar *option_config = NULL;
static gchar *option_debug = NULL;
static gchar *option_plugin = NULL;
static gchar *option_noplugin = NULL;
static bool option_detach = true;
static bool option_version = false;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value) {
		if (option_debug) {
			char *prev = option_debug;

			option_debug = g_strconcat(prev, ",", value, NULL);
			g_free(prev);
		} else {
			option_debug = g_strdup(value);
		}
	} else {
		g_free(option_debug);
		option_debug = g_strdup("*");
	}

	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_STRING, &option_config,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ "plugin", 'p', 0, G_OPTION_ARG_STRING, &option_plugin,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_STRING, &option_noplugin,
				"Specify plugins not to load", "NAME,..." },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

/*
 * This function will be called from generic src/agent.c code so we have
 * to use connman_ prefix instead of vpn_ one.
 */
unsigned int connman_timeout_input_request(void)
{
	return __vpn_settings_get_timeout_inputreq();
}

static bool vpn_access_change_user(const char *sender, const char *user,
							bool default_access)
{
	return __vpn_access_policy_check(sender,
				VPN_ACCESS_STORAGE_CHANGE_USER, user,
				default_access);
}

static struct connman_storage_callbacks storage_callbacks = {
	.unload =			vpn_provider_unload_providers,
	.load =				vpn_provider_load_providers,
	.finalize = 			__vpn_settings_set_binary_user_override,
	.vpn_access_change_user = 	vpn_access_change_user,
	.get_peer_dbus_name =		__vpn_provider_get_connman_dbus_name,
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	guint signal;
	int conf_err;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, VPN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(argv[0], option_debug, option_detach, false,
			"Connection Manager VPN daemon", VERSION);

	__connman_dbus_init(conn);

	if (!option_config)
		__vpn_settings_init(CONFIGMAINFILE, CONFIGDIR);
	else
		__vpn_settings_init(option_config, CONFIGDIR);

	conf_err = util_read_config_files_from(CONFIGMAINDIR, CONFIGSUFFIX,
			NULL, __vpn_settings_process_config);
	if (conf_err && conf_err != -ENOTDIR)
		connman_error("failed to read configs from %s: %s",
				CONFIGMAINDIR, strerror(conf_err));

	const char* fs_identity = NULL;
	if ((fs_identity = __vpn_settings_get_fs_identity()))
		__connman_set_fsid(fs_identity);

	__connman_inotify_init();
	__connman_storage_init(__vpn_settings_get_storage_root(),
			__vpn_settings_get_user_storage_dir(),
			__vpn_settings_get_storage_dir_permissions(),
			__vpn_settings_get_storage_file_permissions());

	mode_t dir_perm = __vpn_settings_get_storage_dir_permissions();
	if (__connman_storage_create_dir(VPN_STATEDIR, dir_perm))
		perror("Failed to create VPN state directory");

	if (__connman_storage_create_dir(VPN_STORAGEDIR, dir_perm)) {
		perror("Failed to create VPN storage directory");
	} else {
		if (__connman_storage_register_dbus(STORAGE_DIR_TYPE_VPN,
					&storage_callbacks))
			perror("Failed to register VPN storage D-Bus");
	}

	umask(__vpn_settings_get_umask());

	__connman_agent_init();
	__vpn_provider_init();
	__vpn_manager_init();
	__vpn_ipconfig_init();
	__vpn_rtnl_init();
	__connman_task_init();
	__connman_plugin_init(option_plugin, option_noplugin);
	__vpn_config_init();

	__vpn_rtnl_start();

	g_free(option_plugin);
	g_free(option_noplugin);

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__vpn_config_cleanup();
	__connman_plugin_cleanup();
	__connman_task_cleanup();
	__vpn_rtnl_cleanup();
	__vpn_ipconfig_cleanup();
	__vpn_manager_cleanup();
	__vpn_provider_cleanup();
	__connman_agent_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();
	__connman_dbus_cleanup();
	__connman_log_cleanup(false);
	__vpn_settings_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	g_free(option_debug);

	return 0;
}
