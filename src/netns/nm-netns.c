/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2008 Novell, Inc.
 */

#include "config.h"

#include <stdio.h>

#include <gmodule.h>
#include <nm-dbus-interface.h>

#include "nm-config.h"
#include "nm-macros-internal.h"
#include "nm-default-route-manager.h"
#include "nm-route-manager.h"
#include "nm-device.h"
#include "nm-device-generic.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-netns.h"
#include "nm-netns-controller.h"
#include "nm-connectivity.h"
#include "nm-settings.h"
#include "nm-setting-connection.h"
#include "nm-utils.h"
#include "nm-manager.h"
#include "nm-auth-utils.h"
#include "nm-auth-manager.h"
#include "nm-setting-ip6-config.h"
#include "nm-setting-vpn.h"
#include "nm-active-connection.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-manager.h"
#include "nm-audit-manager.h"
#include "nm-activation-request.h"
#include "nm-core-internal.h"
#include "nm-policy.h"
#include "nm-logging.h"

#include "nmdbus-netns.h"

static void
connection_changed (NMSettings *settings,
                    NMConnection *connection,
                    NMNetns *netns);

static void
retry_connections_for_parent_device (NMNetns *self, NMDevice *device);

static NMDevice *
find_parent_device_for_connection (NMNetns *self, NMConnection *connection);

static gboolean
autoconnect_slaves (NMNetns *self,
                    NMSettingsConnection *master_connection,
                    NMDevice *master_device,
                    NMAuthSubject *subject);

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMNetns *self);

G_DEFINE_TYPE (NMNetns, nm_netns, NM_TYPE_EXPORTED_OBJECT)

#define NM_NETNS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS, NMNetnsPrivate))

enum {
	PROP_0 = 0,
	PROP_NAME,
	PROP_DEVICES,
	PROP_ALL_DEVICES,
	PROP_ACTIVATING_CONNECTION,
	PROP_PRIMARY_CONNECTION,
	PROP_PRIMARY_CONNECTION_TYPE,
	PROP_METERED,
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	INTERNAL_DEVICE_ADDED,
	INTERNAL_DEVICE_REMOVED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	/*
	 * Index of a device that is waited for.
	 */
	int ifindex;

	/*
	 * Function that should be called when device appears in this
	 * network namespace.
	 */
	void (*callback)(gpointer user_data, gboolean timouet);

	/*
	 * Data that should be passed to the callback function
	 */
	gpointer user_data;

	/*
	 * Namespace in which device should appear
	 */
	NMNetns *netns;

	/*
	 * Timeout ID
	 */
	guint timeout_id;

} DeviceChangeData;

typedef struct {

	/*
	 * Is this root network namespace? For root network namespace
	 * behavior is special.
	 */
	gboolean isroot;

	/*
	 * file descriptor of file in directory /var/run/netns/
	 * where network namespace is mounted. It is necessary
	 * to have it because setns() system call needs it as a
	 * paramter.
	 */
	int fd;

	/*
	 * Network namespace name, as created in /var/run/netns/
	 * directory.
	 */
	char *name;

	/*
	 * Platform interaction layer
	 */
	NMPlatform *platform;

	/*
	 * List of devices in this namespace
	 */
	GSList *devices;

	/*
	 * List of callbacks for devices that are waited for in this namespace
	 * due to the network namespace switch.
	 *
	 * It is expected that each element of this list has a unique ifindex.
	 */
	GSList *devices_change_list;

	/*
	 * Default route manager instance for the namespace
	 */
	NMDefaultRouteManager *default_route_manager;

	/*
	 * Configuration singleton object
	 */
	NMConfig *config;

	/*
	 * Route manager instance for the namespace
	 */
	NMRouteManager *route_manager;

	/*
	 * ???
	 */
	NMConnectivity *connectivity;

	GSList *active_connections;
	GSList *authorizing_connections;
	guint ac_cleanup_id;

	NMActiveConnection *primary_connection;
	NMActiveConnection *activating_connection;
	NMMetered metered;

#if 0
	NMPolicy *policy;
#endif

	NMVpnManager *vpn_manager;

	/*
	 * Hostname in the given network namespace
	 */
        char *hostname;


} NMNetnsPrivate;

/************************************************************************/

#define _NMLOG_PREFIX_NAME      "netns"
#define _NMLOG(level, domain, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            const NMNetns *const __self = (self); \
            char __sbuf[32]; \
            \
            _nm_log (__level, __domain, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                         nm_sprintf_buf (__sbuf, "[%p]", __self) \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/************************************************************************/

/*
 * Functions that manipulate device change callback structure
 */

/*
 * Remove callback structure from a list.
 */
static void
_device_change_callback_remove(NMNetns *self, DeviceChangeData *dc)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	priv->devices_change_list = g_slist_remove (priv->devices_change_list, dc);

	g_object_unref(dc->netns);

	/*
	 * Cancel timeout
	 */
	if (dc->timeout_id)
		nm_clear_g_source (&dc->timeout_id);

	g_slice_free (DeviceChangeData, dc);
}

/*
 * Timeout triggered, notify caller and remove callback structure
 */
static gboolean
_device_change_timeout_cb(gpointer user_data)
{
	DeviceChangeData *dc = (DeviceChangeData *)user_data;

	nm_log_dbg (LOGD_NETNS, "Timeout while waiting for device to appear in network namespace");

	(dc->callback)(dc->user_data, TRUE);

	_device_change_callback_remove(dc->netns, dc);

	return FALSE;
}

/*
 * Add new callback structure and also add timeout for the given
 * callback structure.
 *
 * TODO: Timeout should be a configurable value! We currently wait
 * for 2000ms fixed!
 */
static DeviceChangeData *
_device_change_callback_add(NMNetns *self,
                            int ifindex,
                            void (*callback)(gpointer user_data, gboolean timeout),
                            gpointer user_data)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	DeviceChangeData *dc;

	dc = g_slice_new (DeviceChangeData);
	dc->callback = callback;
	dc->user_data = user_data;
	dc->ifindex = ifindex;
	dc->netns = g_object_ref(self);

	dc->timeout_id = g_timeout_add (5000, _device_change_timeout_cb, dc);

	priv->devices_change_list = g_slist_prepend (priv->devices_change_list, dc);

	return dc;
}

/*
 * Search list of DeviceChangeData structures by interface index
 * and return a pointer, or NULL if none.
 */
static DeviceChangeData *
_device_change_find (NMNetns *self, NMDevice *device)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	int ifindex;
	GSList *iter;

	ifindex = nm_device_get_ifindex (device);

	for (iter = priv->devices_change_list; iter; iter = iter->next) {
		if (((DeviceChangeData *) iter->data)->ifindex == ifindex)
			return iter->data;
	}

	return NULL;
}

/*
 * Remove callback structure from a list, cancel timeout and
 * call callback function.
 *
 * BUG/HACK: This is a public function because it is called by NMNetns
 * object to handle movement of devices into root network namespace.
 */
void
nm_netns_device_change_callback_activate_and_remove(NMNetns *self, NMDevice *device)
{
	DeviceChangeData *dc;

	nm_log_dbg (LOGD_NETNS, "Checking if device %s (ifindex=%d) is waited on in network namespace %s",
		    nm_device_get_iface (device), nm_device_get_ifindex (device), nm_netns_get_name(self));

	/*
	 * Check if we were waiting for this device to appear. If not, return.
	 */
	if ((dc = _device_change_find (self, device)) == NULL)
		return;

	nm_log_dbg (LOGD_NETNS, "Device %s (ifindex=%d) appeared in network namespace %s",
		    nm_device_get_iface (device), nm_device_get_ifindex (device), nm_netns_get_name(self));

	(dc->callback)(dc->user_data, FALSE);

	_device_change_callback_remove(self, dc);
}

/**************************************************************/

const char *
nm_netns_export(NMNetns *self)
{
	const char *path;

	path = nm_exported_object_export (NM_EXPORTED_OBJECT (self));

	return g_strdup(path);
}

/**************************************************************/

void
nm_netns_set_name(NMNetns *self, const char *name)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	if (priv->name)
		g_free(priv->name);

	priv->name = g_strdup(name);

	g_object_notify (G_OBJECT (self), NM_NETNS_NAME);
}

const char *
nm_netns_get_name(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->name;
}

void
nm_netns_set_id(NMNetns *self, int netns_id)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	priv->fd = netns_id;
}

int
nm_netns_get_id(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->fd;
}

void
nm_netns_set_platform(NMNetns *self, NMPlatform *platform)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	if (priv->platform)
		g_object_unref(priv->platform);

	priv->platform = platform;
	g_object_ref(priv->platform);
}

NMPlatform *
nm_netns_get_platform(NMNetns *self)
{
	NMNetnsPrivate *priv;

	if (self == NULL)
		return NM_PLATFORM_GET;

	priv = NM_NETNS_GET_PRIVATE (self);

	if (priv == NULL || priv->platform == NULL)
		return NM_PLATFORM_GET;

	return priv->platform;
}

NMDefaultRouteManager *
nm_netns_get_default_route_manager(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->default_route_manager;
}

NMRouteManager *
nm_netns_get_route_manager(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->route_manager;
}

void
nm_netns_remove_device(NMNetns *self, NMDevice *device)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	priv->devices = g_slist_remove (priv->devices, device);

	if (nm_device_is_real (device)) {
		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
		nm_device_removed (device);
		g_object_notify (G_OBJECT (self), NM_NETNS_DEVICES);
	}

	g_signal_emit (self, signals[INTERNAL_DEVICE_REMOVED], 0, device);
	nm_exported_object_clear_and_unexport (&device);

	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);
}

void
nm_netns_add_device(NMNetns *self, NMDevice *device)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GError *error;
	int ifindex;
	GSList *iter;

	/* No duplicates */
	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0 && nm_netns_get_device_by_ifindex (self, ifindex)) {
		g_set_error (&error, NM_NETNS_ERROR, NM_NETNS_ERROR_FAILED,
			     "A device with ifindex %d already exits", ifindex);
		return;
	}

	priv->devices = g_slist_append (priv->devices, g_object_ref (device));

	if (nm_device_is_real (device)) {
		g_object_notify (G_OBJECT (self), NM_NETNS_DEVICES);
		nm_device_removed (device);
	}
	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);

	nm_settings_device_added (nm_settings_get(), device);
	g_signal_emit (self, signals[INTERNAL_DEVICE_ADDED], 0, device);
	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *d = iter->data;

		if (d != device)
			nm_device_notify_new_device_added (d, device);
	}
}

gboolean
nm_netns_take_device(NMNetns *self,
                     NMDevice *device,
                     int timeout,
                     void (*callback)(gpointer user_data, gboolean timeout),
                     gpointer user_data)
{
	DeviceChangeData *dc;

	nm_log_dbg (LOGD_NETNS, "Moving device %s (%d) from network namespace %s to %s",
		    nm_device_get_iface (device),
		    nm_device_get_ifindex (device),
		    nm_netns_get_name (nm_device_get_netns (device)),
		    nm_netns_get_name (self));

	/*
	 * Add callback structure and associated timeout
	 */
	dc = _device_change_callback_add(self, nm_device_get_ifindex(device), callback, user_data);

	/*
	 * Initiate change of network namespace for device
	 */
	if (!nm_platform_link_set_netns(nm_device_get_platform(device),
	                                nm_device_get_ifindex(device),
	                                nm_netns_get_id(self))) {

		nm_log_dbg (LOGD_NETNS, "Error moving device %s (%d) from network namespace %s to %s",
			    nm_device_get_iface (device),
			    nm_device_get_ifindex (device),
			    nm_netns_get_name (nm_device_get_netns (device)),
			    nm_netns_get_name (self));

		/*
		 * Remove callback structure and associated timeout
		 */
		_device_change_callback_remove(self, dc);

		return FALSE;
	}

	return TRUE;
}

/**************************************************************/

NMDevice *
nm_netns_get_device_by_ifindex (NMNetns *self, int ifindex)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GSList *iter;

	/*
	 * Root network namespace is handled by NMManager so redirect
	 * query to it.
	 */
	if (priv->isroot)
		return nm_manager_get_device_by_ifindex (nm_manager_get(), ifindex);

	for (iter = NM_NETNS_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_ifindex (device) == ifindex)
			return device;
	}

	return NULL;
}

NMDevice *
nm_netns_get_device_by_path (NMNetns *self, const char *device_path)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GSList *iter;

	/*
	 * Root network namespace is handled by NMManager so redirect
	 * qurey to it.
	 */
	if (priv->isroot)
		return nm_manager_get_device_by_path (nm_manager_get(), device_path);

	for (iter = priv->devices; iter; iter = iter->next) {
		const char *path;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data));

		if (!strcmp(path, device_path))
			return iter->data;
        }

	return NULL;
}

/**************************************************************/

static void
remove_device (NMNetns *self,
	       NMDevice *device,
	       gboolean quitting,
	       gboolean allow_unmanage)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	nm_log_dbg (LOGD_NETNS, "(%s): removing device (allow_unmanage %d, managed %d)",
		    nm_device_get_iface (device), allow_unmanage, nm_device_get_managed (device, FALSE));

	if (allow_unmanage && nm_device_get_managed (device, FALSE)) {
		NMActRequest *req = nm_device_get_act_request (device);
		gboolean unmanage = FALSE;

                /* Leave activated interfaces up when quitting so their configuration
		 * can be taken over when NM restarts.  This ensures connectivity while
		 * NM is stopped. Devices which do not support connection assumption
		 * cannot be left up.
		 */
		if (!quitting)  /* Forced removal; device already gone */
			unmanage = TRUE;
		else if (!nm_device_can_assume_active_connection (device))
			unmanage = TRUE;
		else if (!req)
			unmanage = TRUE;

		if (unmanage) {
			if (quitting)
				nm_device_set_unmanaged_by_quitting (device);
			else
				nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_PLATFORM_INIT, TRUE, NM_DEVICE_STATE_REASON_REMOVED);
		} else if (quitting && nm_config_get_configure_and_quit (nm_config_get ())) {
			nm_device_spawn_iface_helper (device);
		}
	}

	g_signal_handlers_disconnect_matched (device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, self);

	nm_settings_device_removed (nm_settings_get(), device, quitting);
	priv->devices = g_slist_remove (priv->devices, device);

	if (nm_device_is_real (device)) {
		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
		nm_device_removed (device);
		g_object_notify (G_OBJECT (self), NM_NETNS_DEVICES);
	}

	g_signal_emit (self, signals[INTERNAL_DEVICE_REMOVED], 0, device);
	nm_exported_object_clear_and_unexport (&device);

	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);
}

static void
device_removed_cb (NMDevice *device, gpointer user_data)
{
	remove_device (NM_NETNS (user_data), device, FALSE, TRUE);
}

/**
 * add_device:
 * @self: the #NMNetns
 * @device: the #NMDevice to add
 * @error: (out): the #GError
 *
 * If successful, this function will increase the references count of @device.
 * Callers should decrease the reference count.
 */
static gboolean
add_device (NMNetns *self, NMDevice *device, GError **error)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	const char *iface, *type_desc;
#if 0
	const GSList *unmanaged_specs;
	RfKillType rtype;
#endif
	GSList *iter, *remove = NULL;
	int ifindex;
	const char *dbus_path;

	/* No duplicates */
	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0 && nm_netns_get_device_by_ifindex (self, ifindex)) {
		g_set_error (error, NM_NETNS_ERROR, NM_NETNS_ERROR_FAILED,
			     "A device with ifindex %d already exits", ifindex);
		return FALSE;
	}

        /* Remove existing devices owned by the new device; eg remove ethernet
	 * ports that are owned by a WWAN modem, since udev may announce them
	 * before the modem is fully discovered.
	 *
	 * FIXME: use parent/child device relationships instead of removing
	 * the child NMDevice entirely
	 */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		iface = nm_device_get_ip_iface (candidate);
		if (nm_device_is_real (candidate) && nm_device_owns_iface (device, iface))
			remove = g_slist_prepend (remove, candidate);
	}
	for (iter = remove; iter; iter = iter->next)
		remove_device (self, NM_DEVICE (iter->data), FALSE, FALSE);
	g_slist_free (remove);

	priv->devices = g_slist_append (priv->devices, g_object_ref (device));

#if 0
	g_signal_connect (device, NM_DEVICE_STATE_CHANGED,
			  G_CALLBACK (manager_device_state_changed),
			  self);

	g_signal_connect (device, NM_DEVICE_AUTH_REQUEST,
			  G_CALLBACK (device_auth_request_cb),
			  self);
#endif

	g_signal_connect (device, NM_DEVICE_REMOVED,
			  G_CALLBACK (device_removed_cb),
			  self);

#if 0
	g_signal_connect (device, NM_DEVICE_RECHECK_ASSUME,
			  G_CALLBACK (recheck_assume_connection_cb),
			  self);

	g_signal_connect (device, "notify::" NM_DEVICE_IP_IFACE,
			  G_CALLBACK (device_ip_iface_changed),
			  self);

	g_signal_connect (device, "notify::" NM_DEVICE_IFACE,
			  G_CALLBACK (device_iface_changed),
			  self);

	g_signal_connect (device, "notify::" NM_DEVICE_REAL,
			  G_CALLBACK (device_realized),
			  self);

	if (priv->startup) {
		g_signal_connect (device, "notify::" NM_DEVICE_HAS_PENDING_ACTION,
				  G_CALLBACK (device_has_pending_action_changed),
				  self);
	}

        /* Update global rfkill state for this device type with the device's
	 * rfkill state, and then set this device's rfkill state based on the
	 * global state.
	 */
	rtype = nm_device_get_rfkill_type (device);
	if (rtype != RFKILL_TYPE_UNKNOWN) {
		nm_manager_rfkill_update (self, rtype);
		nm_device_set_enabled (device, radio_enabled_for_type (self, rtype, TRUE));
	}
#endif

	iface = nm_device_get_iface (device);
	g_assert (iface);
	type_desc = nm_device_get_type_desc (device);
	g_assert (type_desc);

	nm_device_set_unmanaged_by_user_config (device, nm_settings_get_unmanaged_specs (nm_settings_get()));

#if 0
	nm_device_set_unmanaged_flags (device,
	                               NM_UNMANAGED_SLEEPING,
	                               manager_sleeping (self));
#endif

	dbus_path = nm_exported_object_export (NM_EXPORTED_OBJECT (device));
	nm_log_info (LOGD_NETNS, "netns (%s): new %s device (%s)", iface, type_desc, dbus_path);

	nm_settings_device_added (nm_settings_get(), device);
	g_signal_emit (self, signals[INTERNAL_DEVICE_ADDED], 0, device);
	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *d = iter->data;

		if (d != device)
			nm_device_notify_new_device_added (d, device);
	}

	/* Virtual connections may refer to the new device as
	 * parent device, retry to activate them.
	 */
	retry_connections_for_parent_device (self, device);

	/*
	 * If this device was moved from another network namespace 
	 * see if anyone is waiting for it.
	 */
	nm_netns_device_change_callback_activate_and_remove(self, device);

	return TRUE;
}

static void
platform_link_added (NMNetns *self,
		     int ifindex,
		     const NMPlatformLink *plink)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	NMDevice *device = NULL;
	GError *error = NULL;
	gboolean nm_plugin_missing = FALSE;
	GSList *iter;

	g_return_if_fail (ifindex > 0);

	if (nm_netns_get_device_by_ifindex (self, ifindex))
		return;

	/* Let unrealized devices try to realize themselves with the link */
	for (iter = NM_NETNS_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;
		gboolean compatible = TRUE;

		if (strcmp (nm_device_get_iface (candidate), plink->name))
			continue;

		if (nm_device_is_real (candidate)) {
                        /* Ignore the link added event since there's already a realized
			 * device with the link's name.
			 */
			return;
		} else if (nm_device_realize_start (candidate, plink, &compatible, &error)) {
			/* Success */
			nm_device_realize_finish (candidate, plink);
			return;
		}

		nm_log_dbg (LOGD_NETNS, "(%s): failed to realize from plink: '%s'",
			    plink->name, error->message);
		g_clear_error (&error);

                /* Try next unrealized device */
        }

	/* Try registered device factories */
	factory = nm_device_factory_manager_find_factory_for_link_type (plink->type);
	if (factory) {
		gboolean ignore = FALSE;

		nm_log_dbg (LOGD_NETNS, "Creating new device %s in network namespace %s",
			     plink->name, priv->name);
		device = nm_device_factory_create_device (factory, plink->name, plink, NULL, self, &ignore, &error);
		if (!device) {
			if (!ignore) {
				nm_log_warn (LOGD_NETNS, "%s: factory failed to create device: %s",
					     plink->name, error->message);
				g_clear_error (&error);
			}
			return;
		}
	}

	if (device == NULL) {
		switch (plink->type) {
		case NM_LINK_TYPE_WWAN_ETHERNET:
		case NM_LINK_TYPE_BNEP:
		case NM_LINK_TYPE_OLPC_MESH:
		case NM_LINK_TYPE_TEAM:
		case NM_LINK_TYPE_WIFI:
			nm_log_info (LOGD_NETNS, "(%s): '%s' plugin not available; creating generic device",
				     plink->name, nm_link_type_to_string (plink->type));
			nm_plugin_missing = TRUE;
			/* fall through */
		default:
			nm_log_dbg (LOGD_NETNS, "Creating new generic device %s in network namespace %s",
				    plink->name, priv->name);
			device = nm_device_generic_new (plink, self);
			break;
		}
	}

	if (device) {
		if (nm_plugin_missing)
			nm_device_set_nm_plugin_missing (device, TRUE);

		if (nm_device_realize_start (device, plink, NULL, &error)) {
			add_device (self, device, NULL);
			nm_device_realize_finish (device, plink);
		} else {
			nm_log_warn (LOGD_NETNS, "%s: failed to realize device: %s",
				     plink->name, error->message);
			g_clear_error (&error);
		}
		g_object_unref (device);
	}
}

static void
platform_query_devices (NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GArray *links_array;
	NMPlatformLink *links;
	int i;

	links_array = nm_platform_link_get_all (priv->platform);
	links = (NMPlatformLink *) links_array->data;
	for (i = 0; i < links_array->len; i++)
		platform_link_added (self, links[i].ifindex, &links[i]);

	g_array_unref (links_array);
}

typedef struct {
	NMNetns *self;
	int ifindex;
} PlatformLinkCbData;

static gboolean
_platform_link_cb_idle (PlatformLinkCbData *data)
{
	NMNetns *self = data->self;
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	const NMPlatformLink *l;

	if (!self)
		goto out;

	g_object_remove_weak_pointer (G_OBJECT (self), (gpointer *) &data->self);

	l = nm_platform_link_get (priv->platform, data->ifindex);
	if (l) {
		NMPlatformLink pllink;

		pllink = *l; /* make a copy of the link instance */
		platform_link_added (self, data->ifindex, &pllink);
	} else {
		NMDevice *device;
		GError *error = NULL;

		device = nm_netns_get_device_by_ifindex (self, data->ifindex);
		if (device) {
			if (nm_device_is_software (device)) {
				/* Our software devices stick around until their connection is removed */
				if (!nm_device_unrealize (device, FALSE, &error)) {
					nm_log_warn (LOGD_NETNS, "(%s): failed to unrealize: %s",
						     nm_device_get_iface (device),
						     error->message);
					g_clear_error (&error);
					remove_device (self, device, FALSE, TRUE);
				}
			} else {
				/* Hardware and external devices always get removed when their kernel link is gone */
				remove_device (self, device, FALSE, TRUE);
			}
		}
	}

out:
	g_slice_free (PlatformLinkCbData, data);
	return G_SOURCE_REMOVE;
}

static void
platform_link_cb (NMPlatform *platform,
		  NMPObjectType obj_type,
		  int ifindex,
		  NMPlatformLink *plink,
		  NMPlatformSignalChangeType change_type,
		  gpointer user_data)
{
	PlatformLinkCbData *data;

	switch (change_type) {
	case NM_PLATFORM_SIGNAL_ADDED:
	case NM_PLATFORM_SIGNAL_REMOVED:
		data = g_slice_new (PlatformLinkCbData);
		data->self = NM_NETNS (user_data);
		data->ifindex = ifindex;
		g_object_add_weak_pointer (G_OBJECT (data->self), (gpointer *) &data->self);
		g_idle_add ((GSourceFunc) _platform_link_cb_idle, data);
		break;
	default:
                break;
	}
}

gboolean
nm_netns_setup(NMNetns *self, gboolean isroot)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	/*
	 * For root network namespace NMManager enumerates devices
	 * and loopback interface is activated in main function.
	 * For all other network namespaces we have to do it by our
	 * selves!
	 *
	 * Also, monitoring of network devices in root network
	 * namespace will be done by NMManager, so we don't do
	 * anything about it.
	 */

	priv->default_route_manager = nm_default_route_manager_new();
	priv->route_manager = nm_route_manager_new();

	priv->isroot = isroot;

	if (isroot)
		return TRUE;

	g_signal_connect (priv->platform,
			  NM_PLATFORM_SIGNAL_LINK_CHANGED,
			  G_CALLBACK (platform_link_cb),
			  self);

	/*
	 * Enumerate all existing devices in the network namespace
	 *
	 * This isn't done for root namespace because NMManager object
	 * takes care of that part.
	 */
	platform_query_devices (self);

	/* Activate loopback interface in a new network namespace */
	nm_platform_link_set_up (priv->platform, 1, NULL);

#if 0
	priv->policy = nm_policy_new (self, nm_settings_get());
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP4_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP6_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP4_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP6_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), self);
#endif

	return TRUE;
}

void
nm_netns_stop(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	if (priv->isroot)
		return;

	while (priv->devices)
		remove_device (self, NM_DEVICE (priv->devices->data), TRUE, TRUE);

	nm_platform_netns_destroy(priv->platform, priv->name);

	/*
	 * TODO/BUG: Maybe this should go to dispose method?
	 */
	nm_clear_g_source (&priv->ac_cleanup_id);
	g_clear_object (&priv->activating_connection);

#if 0
	/*
	 * TODO/BUG: Maybe this should go to dispose method?
	 */
	if (priv->policy) {
		g_signal_handlers_disconnect_by_func (priv->policy, policy_default_device_changed, manager);
		g_signal_handlers_disconnect_by_func (priv->policy, policy_activating_device_changed, manager);
		g_clear_object (&priv->policy);
	}
#endif

	g_clear_object(&priv->platform);
}

NMNetns *
nm_netns_new (const char *netns_name)
{
	NMNetns *self;

	self = g_object_new (NM_TYPE_NETNS, NULL);
	nm_netns_set_name(self, netns_name);

	return self;
}

/******************************************************************/

const GSList *
nm_netns_get_devices (NMNetns *netns)
{
	g_return_val_if_fail (NM_IS_NETNS (netns), NULL);

	return NM_NETNS_GET_PRIVATE (netns)->devices;
}

static NMDevice *
nm_netns_get_connection_device (NMNetns *self,
                                NMConnection *connection)
{
	NMActiveConnection *ac = nm_manager_find_ac_for_connection (nm_manager_get (), connection);
	if (ac == NULL)
		return NULL;

	return nm_active_connection_get_device (ac);
}

static NMDevice *
nm_netns_get_best_device_for_connection (NMNetns *self,
                                         NMConnection *connection,
                                         gboolean for_user_request)
{
	const GSList *devices, *iter;
	NMDevice *act_device = nm_netns_get_connection_device (self, connection);
	NMDeviceCheckConAvailableFlags flags;

	if (act_device)
		return act_device;

	flags = for_user_request ? NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST : NM_DEVICE_CHECK_CON_AVAILABLE_NONE;

	/* Pick the first device that's compatible with the connection. */
	devices = nm_netns_get_devices (self);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_check_connection_available (device, connection, flags, NULL))
			return device;
	}

	/* No luck. :( */
	return NULL;
}

static void
_get_devices (NMNetns *self,
	      GDBusMethodInvocation *context,
	      gboolean all_devices)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	gs_free const char **paths = NULL;
	GSList *iter;
	int i;

	paths = g_new (const char *, g_slist_length (priv->devices) + 1);

	for (i = 0, iter = priv->devices; iter; iter = iter->next) {
		const char *path;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data));
		if (   path
		    && (all_devices || nm_device_is_real (iter->data)))
                        paths[i++] = path;
        }
	paths[i++] = NULL;

	g_dbus_method_invocation_return_value (context,
					       g_variant_new ("(^ao)", (char **) paths));
}

static void
impl_netns_get_devices (NMNetns *self,
                        GDBusMethodInvocation *context)
{
	_get_devices (self, context, FALSE);
}

static void
impl_netns_get_all_devices (NMNetns *self,
                            GDBusMethodInvocation *context)
{
	_get_devices (self, context, TRUE);
}

typedef struct {
	NMNetns *netns;
	GDBusMethodInvocation *context;
	int ifindex;
} _take_device_data;

static void
_take_device_cb (gpointer user_data, gboolean timeout)
{
	NMNetns *netns = ((_take_device_data *)user_data)->netns;
	GDBusMethodInvocation *context = ((_take_device_data *)user_data)->context;
	int ifindex = ((_take_device_data *)user_data)->ifindex;
	NMDevice *device;

	if (timeout) {
		nm_log_dbg (LOGD_NETNS, "Timeout while waiting for device %d to appear in network namespace %s",
		              ifindex, nm_netns_get_name(netns));

		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_FAILED,
		                                       "Timeout while waiting for device to appear in the target namespace.");
		goto out_free;
	}

	device = nm_netns_get_device_by_ifindex (netns, ifindex);

	if (!device) {
		nm_log_dbg (LOGD_NETNS, "Device %d not found in the target network namespace %s",
                              ifindex, nm_netns_get_name(netns));

		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_FAILED,
		                                       "Device didn't appear in the network namespace.");
		goto out_free;
        }

	g_dbus_method_invocation_return_value (context, NULL);

out_free:

	g_object_unref (netns);
	g_slice_free (_take_device_data, user_data);

	return;
}

static void
impl_netns_take_device (NMNetns *self,
                        GDBusMethodInvocation *context,
                        const char *device_path,
			int timeout)
{
	NMDevice *device;
	_take_device_data *td;

	device = nm_netns_controller_find_device_by_path(device_path);

	if (!device) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_UNKNOWN_DEVICE,
		                                       "Device not found.");
		return;
	}

	if (nm_device_get_netns (device) == self) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_DEVICE_ALREADY_IN_NETNS,
		                                       "Device already in target namespace.");
		return;
	}

	td = g_slice_new (_take_device_data);
	td->netns = g_object_ref (self);
	td->context = context;
	td->ifindex = nm_device_get_ifindex (device);

	if (!nm_netns_take_device(self, device, timeout, _take_device_cb, td)) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_FAILED,
		                                       "Error moving device to target namespace");
		return;
	}
}

/**
 * find_device_by_iface:
 * @self: the #NMNetns
 * @iface: the device interface to find
 * @connection: a connection to ensure the returned device is compatible with
 * @slave: a slave connection to ensure a master is compatible with
 *
 * Finds a device by interface name, preferring realized devices.  If @slave
 * is given, this function will only return master devices and will ensure
 * @slave, when activated, can be a slave of the returned master device.  If
 * @connection is given, this function will only consider devices that are
 * compatible with @connection.
 *
 * Returns: the matching #NMDevice
 */
static NMDevice *
find_device_by_iface (NMNetns *self,
                      const char *iface,
                      NMConnection *connection,
                      NMConnection *slave)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMDevice *fallback = NULL;
	GSList *iter;

	g_return_val_if_fail (iface != NULL, NULL);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		if (strcmp (nm_device_get_iface (candidate), iface))
			continue;
		if (connection && !nm_device_check_connection_compatible (candidate, connection))
			continue;
		if (slave) {
			if (!nm_device_is_master (candidate))
				continue;
			if (!nm_device_check_slave_connection_compatible (candidate, slave))
				continue;
		}

		if (nm_device_is_real (candidate))
			return candidate;
		else if (!fallback)
			fallback = candidate;
	}
	return fallback;
}

/**
 * validate_activation_request:
 * @self: the #NMNetns
 * @context: the D-Bus context of the requestor
 * @connection: the partial or complete #NMConnection to be activated
 * @device_path: the object path of the device to be activated, or "/"
 * @out_device: on successful reutrn, the #NMDevice to be activated with @connection
 * @out_vpn: on successful return, %TRUE if @connection is a VPN connection
 * @error: location to store an error on failure
 *
 * Performs basic validation on an activation request, including ensuring that
 * the requestor is a valid Unix process, is not disallowed in @connection
 * permissions, and that a device exists that can activate @connection.
 *
 * Returns: on success, the #NMAuthSubject representing the requestor, or
 *   %NULL on error
 */
static NMAuthSubject *
validate_activation_request (NMNetns *self,
                             GDBusMethodInvocation *context,
                             NMConnection *connection,
                             const char *device_path,
                             NMDevice **out_device,
                             gboolean *out_vpn,
                             GError **error)
{
	NMDevice *device = NULL;
	gboolean vpn = FALSE;
	NMAuthSubject *subject = NULL;
	char *error_desc = NULL;

	g_assert (connection);
	g_assert (out_device);
	g_assert (out_vpn);

	/* Validate the caller */
	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_PERMISSION_DENIED,
		                     "Failed to get request UID.");
		return NULL;
	}

	/* Ensure the subject has permissions for this connection */
	if (!nm_auth_is_subject_in_acl (connection,
	                                subject,
	                                &error_desc)) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_PERMISSION_DENIED,
		                     error_desc);
		g_free (error_desc);
		goto error;
	}

	/* Not implemented yet, we want to fail early */
	if (   nm_connection_get_setting_connection (connection)
	    && nm_connection_get_setting_ip6_config (connection)
	    && !strcmp (nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG),
	                NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_CONNECTION_NOT_AVAILABLE,
		                     "Sharing IPv6 connections is not supported yet.");
		return NULL;
	}

	/* Check whether it's a VPN or not */
	if (   nm_connection_get_setting_vpn (connection)
	    || nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME))
		vpn = TRUE;

	/* Normalize device path */
	if (device_path && g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

	/* And validate it */
	if (device_path) {
		device = nm_netns_get_device_by_path (self, device_path);
		if (!device) {
			g_set_error_literal (error,
			                     NM_NETNS_ERROR,
			                     NM_NETNS_ERROR_UNKNOWN_DEVICE,
			                     "Device not found");
			goto error;
		}
	} else
		device = nm_netns_get_best_device_for_connection (self, connection, TRUE);

	if (!device && !vpn) {
		gboolean is_software = nm_connection_is_virtual (connection);

		/* VPN and software-device connections don't need a device yet */
		if (!is_software) {
			g_set_error_literal (error,
			                     NM_NETNS_ERROR,
			                     NM_NETNS_ERROR_UNKNOWN_DEVICE,
			                     "No suitable device found for this connection.");
			goto error;
		}

		if (is_software) {
			char *iface;

			/* Look for an existing device with the connection's interface name */
			iface = nm_netns_get_connection_iface (self, connection, NULL, error);
			if (!iface)
				goto error;

			device = find_device_by_iface (self, iface, connection, NULL);
			g_free (iface);
		}
	}

	if ((!vpn || device_path) && !device) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_UNKNOWN_DEVICE,
		                     "Failed to find a compatible device for this connection");
		goto error;
	}

	*out_device = device;
	*out_vpn = vpn;
	return subject;

error:
	g_object_unref (subject);
	return NULL;
}

static NMActiveConnection *
_new_vpn_active_connection (NMNetns *self,
                            NMSettingsConnection *settings_connection,
                            const char *specific_object,
                            NMAuthSubject *subject,
                            GError **error)
{
	NMActiveConnection *parent = NULL;
	NMDevice *device = NULL;

	g_return_val_if_fail (!settings_connection || NM_IS_SETTINGS_CONNECTION (settings_connection), NULL);

	if (specific_object) {
		/* Find the specific connection the client requested we use */
		parent = nm_manager_active_connection_get_by_path (nm_manager_get (), specific_object);
		if (!parent) {
			g_set_error_literal (error, NM_NETNS_ERROR, NM_NETNS_ERROR_CONNECTION_NOT_ACTIVE,
			                     "Base connection for VPN connection not active.");
			return NULL;
		}
	} else
		parent = nm_manager_get_primary_connection (nm_manager_get ());

	if (!parent) {
		g_set_error_literal (error, NM_NETNS_ERROR, NM_NETNS_ERROR_UNKNOWN_CONNECTION,
		                     "Could not find source connection.");
		return NULL;
	}

	device = nm_active_connection_get_device (parent);
	if (!device) {
		g_set_error_literal (error, NM_NETNS_ERROR, NM_NETNS_ERROR_UNKNOWN_DEVICE,
		                     "Source connection had no active device.");
		return NULL;
	}

	return (NMActiveConnection *) nm_vpn_connection_new (settings_connection,
	                                                     device,
	                                                     nm_exported_object_get_path (NM_EXPORTED_OBJECT (parent)),
	                                                     subject);
}

static NMActiveConnection *
_new_active_connection (NMNetns *self,
                        NMConnection *connection,
                        const char *specific_object,
                        NMDevice *device,
                        NMAuthSubject *subject,
                        GError **error)
{
	NMSettingsConnection *settings_connection = NULL;
	NMActiveConnection *existing_ac;
	gboolean is_vpn;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);

	/* Can't create new AC for already-active connection */
	existing_ac = nm_manager_find_ac_for_connection (nm_manager_get (), connection);
	if (NM_IS_VPN_CONNECTION (existing_ac)) {
		g_set_error (error, NM_NETNS_ERROR, NM_NETNS_ERROR_CONNECTION_ALREADY_ACTIVE,
		             "Connection '%s' is already active",
		             nm_connection_get_id (connection));
		return NULL;
	}

	/* Normalize the specific object */
	if (specific_object && g_strcmp0 (specific_object, "/") == 0)
		specific_object = NULL;

	is_vpn = nm_connection_is_type (NM_CONNECTION (connection), NM_SETTING_VPN_SETTING_NAME);

	if (NM_IS_SETTINGS_CONNECTION (connection))
		settings_connection = (NMSettingsConnection *) connection;

	if (is_vpn) {
		return _new_vpn_active_connection (self,
		                                   settings_connection,
		                                   specific_object,
		                                   subject,
		                                   error);
	}

	return (NMActiveConnection *) nm_act_request_new (settings_connection,
	                                                  specific_object,
	                                                  subject,
	                                                  device);
}

static gboolean
_internal_activate_vpn (NMNetns *self, NMActiveConnection *active, GError **error)
{
	gboolean success;

	g_assert (NM_IS_VPN_CONNECTION (active));

	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	success = nm_vpn_manager_activate_connection (NM_NETNS_GET_PRIVATE (self)->vpn_manager,
	                                              NM_VPN_CONNECTION (active),
	                                              error);
	if (success)
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
	else
		nm_exported_object_unexport (NM_EXPORTED_OBJECT (active));

	return success;
}

static gboolean
is_compatible_with_slave (NMConnection *master, NMConnection *slave)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (master, FALSE);
	g_return_val_if_fail (slave, FALSE);

	s_con = nm_connection_get_setting_connection (slave);
	g_assert (s_con);

	return nm_connection_is_type (master, nm_setting_connection_get_slave_type (s_con));
}

/**
 * find_master:
 * @self: #NMNetns object
 * @connection: the #NMConnection to find the master connection and device for
 * @device: the #NMDevice, if any, which will activate @connection
 * @out_master_connection: on success, the master connection of @connection if
 *   that master connection was found
 * @out_master_device: on success, the master device of @connection if that
 *   master device was found
 * @out_master_ac: on success, the master ActiveConnection of @connection if
 *   there already is one
 * @error: the error, if an error occurred
 *
 * Given an #NMConnection, attempts to find its master. If @connection has
 * no master, this will return %TRUE and @out_master_connection and
 * @out_master_device will be untouched.
 *
 * If @connection does have a master, then the outputs depend on what is in its
 * #NMSettingConnection:master property:
 *
 * If "master" is the ifname of an existing #NMDevice, and that device has a
 * compatible master connection activated or activating on it, then
 * @out_master_device, @out_master_connection, and @out_master_ac will all be
 * set. If the device exists and is idle, only @out_master_device will be set.
 * If the device exists and has an incompatible connection on it, an error
 * will be returned.
 *
 * If "master" is the ifname of a non-existent device, then @out_master_device
 * will be %NULL, and @out_master_connection will be a connection whose
 * activation would cause the creation of that device. @out_master_ac MAY be
 * set in this case as well (if the connection has started activating, but has
 * not yet created its device).
 *
 * If "master" is the UUID of a compatible master connection, then
 * @out_master_connection will be the identified connection, and @out_master_device
 * and/or @out_master_ac will be set if the connection is currently activating.
 * (@out_master_device will not be set if the device exists but does not have
 * @out_master_connection active/activating on it.)
 *
 * Returns: %TRUE if the master device and/or connection could be found or if
 *  the connection did not require a master, %FALSE otherwise
 **/
static gboolean
find_master (NMNetns *self,
             NMConnection *connection,
             NMDevice *device,
             NMSettingsConnection **out_master_connection,
             NMDevice **out_master_device,
             NMActiveConnection **out_master_ac,
             GError **error)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *master;
	NMDevice *master_device = NULL;
	NMSettingsConnection *master_connection = NULL;
	GSList *iter;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master == NULL)
		return TRUE;  /* success, but no master */

	/* Try as an interface name first */
	master_device = find_device_by_iface (self, master, NULL, connection);
	if (master_device) {
		if (master_device == device) {
			g_set_error_literal (error, NM_NETNS_ERROR, NM_NETNS_ERROR_DEPENDENCY_FAILED,
			                     "Device cannot be its own master");
			return FALSE;
		}

		master_connection = nm_device_get_settings_connection (master_device);
		if (master_connection && !is_compatible_with_slave (NM_CONNECTION (master_connection), connection)) {
			g_set_error (error, NM_NETNS_ERROR, NM_NETNS_ERROR_DEPENDENCY_FAILED,
			             "The active connection on %s is not a valid master for '%s'",
			             nm_device_get_iface (master_device),
			             nm_connection_get_id (connection));
			return FALSE;
		}
	} else {
		/* Try master as a connection UUID */
		master_connection = nm_settings_get_connection_by_uuid (nm_settings_get(), master);
		if (master_connection) {
			/* Check if the master connection is activated on some device already */
			for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
				NMDevice *candidate = NM_DEVICE (iter->data);

				if (candidate == device)
					continue;

				if (nm_device_get_settings_connection (candidate) == master_connection) {
					master_device = candidate;
					break;
				}
			}
		}
	}

	if (out_master_connection)
		*out_master_connection = master_connection;
	if (out_master_device)
		*out_master_device = master_device;
	if (out_master_ac && master_connection)
		*out_master_ac = nm_manager_find_ac_for_connection (nm_manager_get (), NM_CONNECTION (master_connection));

	if (master_device || master_connection)
		return TRUE;
	else {
		g_set_error_literal (error, NM_NETNS_ERROR, NM_NETNS_ERROR_UNKNOWN_DEVICE,
		                     "Master connection not found or invalid");
		return FALSE;
	}
}

/* Filter out connections that are already active.
 * nm_settings_get_connections() returns sorted list. We need to preserve the
 * order so that we didn't change auto-activation order (recent timestamps
 * are first).
 * Caller is responsible for freeing the returned list with g_slist_free().
 */
GSList *
nm_netns_get_activatable_connections (NMNetns *self)
{
	GSList *all_connections = nm_settings_get_connections (nm_settings_get ());
	GSList *connections = NULL, *iter;
	NMSettingsConnection *connection;

	for (iter = all_connections; iter; iter = iter->next) {
		connection = iter->data;

		if (!nm_manager_find_ac_for_connection (nm_manager_get (), NM_CONNECTION (connection)))
			connections = g_slist_prepend (connections, connection);
	}

	g_slist_free (all_connections);
	return g_slist_reverse (connections);
}

/**
 * ensure_master_active_connection:
 * @self: the #NMNetns
 * @subject: the #NMAuthSubject representing the requestor of this activation
 * @connection: the connection that should depend on @master_connection
 * @device: the #NMDevice, if any, which will activate @connection
 * @master_connection: the master connection, or %NULL
 * @master_device: the master device, or %NULL
 * @error: the error, if an error occurred
 *
 * Determines whether a given #NMConnection depends on another connection to
 * be activated, and if so, finds that master connection or creates it.
 *
 * If @master_device and @master_connection are both set then @master_connection
 * MUST already be activated or activating on @master_device, and the function will
 * return the existing #NMActiveConnection.
 *
 * If only @master_device is set, and it has an #NMActiveConnection, then the
 * function will return it if it is a compatible master, or an error if not. If it
 * doesn't have an AC, then the function will create one if a compatible master
 * connection exists, or return an error if not.
 *
 * If only @master_connection is set, then this will try to find or create a compatible
 * #NMDevice, and either activate @master_connection on that device or return an error.
 *
 * Returns: the master #NMActiveConnection that the caller should depend on, or
 * %NULL if an error occurred
 */
static NMActiveConnection *
ensure_master_active_connection (NMNetns *self,
                                 NMAuthSubject *subject,
                                 NMConnection *connection,
                                 NMDevice *device,
                                 NMSettingsConnection *master_connection,
                                 NMDevice *master_device,
                                 GError **error)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMActiveConnection *master_ac = NULL;
	NMDeviceState master_state;
	GSList *iter;

	g_assert (connection);
	g_assert (master_connection || master_device);

	/* If the master device isn't activated then we need to activate it using
	 * compatible connection.  If it's already activating we can just proceed.
	 */
	if (master_device) {
		NMSettingsConnection *device_connection = nm_device_get_settings_connection (master_device);

		/* If we're passed a connection and a device, we require that connection
		 * be already activated on the device, eg returned from find_master().
		 */
		g_assert (!master_connection || master_connection == device_connection);
		if (device_connection && !is_compatible_with_slave (NM_CONNECTION (device_connection), connection)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The active connection on %s is not a valid master for '%s'",
			             nm_device_get_iface (master_device),
			             nm_connection_get_id (connection));
			return NULL;
		}

		master_state = nm_device_get_state (master_device);
		if (   (master_state == NM_DEVICE_STATE_ACTIVATED)
		    || nm_device_is_activating (master_device)) {
			/* Device already using master_connection */
			g_assert (device_connection);
			return NM_ACTIVE_CONNECTION (nm_device_get_act_request (master_device));
		}

		/* If the device is disconnected, find a compatible connection and
		 * activate it on the device.
		 */
		if (master_state == NM_DEVICE_STATE_DISCONNECTED || !nm_device_is_real (master_device)) {
			GSList *connections;

			g_assert (master_connection == NULL);

			/* Find a compatible connection and activate this device using it */
			connections = nm_netns_get_activatable_connections (self);
			for (iter = connections; iter; iter = g_slist_next (iter)) {
				NMSettingsConnection *candidate = NM_SETTINGS_CONNECTION (iter->data);

				/* Ensure eg bond/team slave and the candidate master is a
				 * bond/team master
				 */
				if (!is_compatible_with_slave (NM_CONNECTION (candidate), connection))
					continue;

				if (nm_device_check_connection_available (master_device, NM_CONNECTION (candidate), NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
					master_ac = nm_netns_activate_connection (self,
					                                          candidate,
					                                          NULL,
					                                          master_device,
					                                          subject,
					                                          error);
					if (!master_ac)
						g_prefix_error (error, "%s", "Master device activation failed: ");
					g_slist_free (connections);
					return master_ac;
				}
			}
			g_slist_free (connections);

			g_set_error (error,
			             NM_NETNS_ERROR,
			             NM_NETNS_ERROR_UNKNOWN_CONNECTION,
			             "No compatible connection found for master device %s.",
			             nm_device_get_iface (master_device));
			return NULL;
		}

		/* Otherwise, the device is unmanaged, unavailable, or disconnecting */
		g_set_error (error,
		             NM_NETNS_ERROR,
		             NM_NETNS_ERROR_DEPENDENCY_FAILED,
		             "Master device %s unmanaged or not available for activation",
		             nm_device_get_iface (master_device));
	} else if (master_connection) {
		gboolean found_device = FALSE;

		/* Find a compatible device and activate it using this connection */
		for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
			NMDevice *candidate = NM_DEVICE (iter->data);

			if (candidate == device) {
				/* A device obviously can't be its own master */
				continue;
			}

			if (!nm_device_check_connection_available (candidate, NM_CONNECTION (master_connection), NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL))
				continue;

			found_device = TRUE;
			if (!nm_device_is_software (candidate)) {
				master_state = nm_device_get_state (candidate);
				if (nm_device_is_real (candidate) && master_state != NM_DEVICE_STATE_DISCONNECTED)
					continue;
			}

			master_ac = nm_netns_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            candidate,
			                                            subject,
			                                            error);
			if (!master_ac)
				g_prefix_error (error, "%s", "Master device activation failed: ");
			return master_ac;
		}

		g_set_error (error,
		             NM_NETNS_ERROR,
		             NM_NETNS_ERROR_UNKNOWN_DEVICE,
		             "No compatible disconnected device found for master connection %s.",
		             nm_settings_connection_get_uuid (master_connection));
	} else
		g_assert_not_reached ();

	return NULL;
}

static gboolean
should_connect_slaves (NMConnection *connection, NMDevice *device)
{
	NMSettingConnection *s_con;
	NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
	gs_free char *value = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* Check autoconnect-slaves property */
	autoconnect_slaves = nm_setting_connection_get_autoconnect_slaves (s_con);
	if (autoconnect_slaves != NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT)
		goto out;

	/* Check configuration default for autoconnect-slaves property */
	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "connection.autoconnect-slaves", device);
	if (value)
		autoconnect_slaves = _nm_utils_ascii_str_to_int64 (value, 10, 0, 1, -1);

out:
	if (autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO)
		return FALSE;
	if (autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES)
		return TRUE;
	return FALSE;
}

/**
 * find_slaves:
 * @netns: #NMNetns object
 * @connection: the master #NMSettingsConnection to find slave connections for
 * @device: the master #NMDevice for the @connection
 *
 * Given an #NMSettingsConnection, attempts to find its slaves. If @connection is not
 * master, or has not any slaves, this will return %NULL.
 *
 * Returns: list of slave connections for given master @connection, or %NULL
 **/
static GSList *
find_slaves (NMNetns *netns,
             NMSettingsConnection *connection,
             NMDevice *device)
{
	GSList *all_connections, *iter;
	GSList *slaves = NULL;
	NMSettingConnection *s_con;
	const char *master;

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master != NULL)
		return NULL;  /* connection is not master */

	/* Search through all connections, not only inactive ones, because
	 * even if a slave was already active, it might be deactivated during
	 * master reactivation.
	 */
	all_connections = nm_settings_get_connections (nm_settings_get());
	for (iter = all_connections; iter; iter = iter->next) {
		NMSettingsConnection *master_connection = NULL;
		NMDevice *master_device = NULL;
		NMConnection *candidate = iter->data;

		find_master (netns, candidate, NULL, &master_connection, &master_device, NULL, NULL);
		if (   (master_connection && master_connection == connection)
		    || (master_device && master_device == device)) {
			slaves = g_slist_prepend (slaves, candidate);
		}
        }
	g_slist_free (all_connections);

	return g_slist_reverse (slaves);
}

static gboolean
autoconnect_slaves (NMNetns *self,
                    NMSettingsConnection *master_connection,
                    NMDevice *master_device,
                    NMAuthSubject *subject)
{
	GError *local_err = NULL;
	gboolean ret = FALSE;

	if (should_connect_slaves (NM_CONNECTION (master_connection), master_device)) {
		GSList *slaves, *iter;

		iter = slaves = find_slaves (self, master_connection, master_device);
		ret = slaves != NULL;

		while (iter) {
			NMSettingsConnection *slave_connection = iter->data;

			iter = iter->next;
			_LOGD (LOGD_CORE, "will activate slave connection '%s' (%s) as a dependency for master '%s' (%s)",
			       nm_settings_connection_get_id (slave_connection),
			       nm_settings_connection_get_uuid (slave_connection),
			       nm_settings_connection_get_id (master_connection),
			       nm_settings_connection_get_uuid (master_connection));

			/* Schedule slave activation */
			nm_netns_activate_connection (self,
			                              slave_connection,
			                              NULL,
			                              nm_netns_get_best_device_for_connection (self, NM_CONNECTION (slave_connection), FALSE),
			                              subject,
			                              &local_err);
			if (local_err) {
				_LOGW (LOGD_CORE, "Slave connection activation failed: %s", local_err->message);
				g_error_free (local_err);
			}
		}
		g_slist_free (slaves);
	}
	return ret;
}

static gboolean
_internal_activate_device (NMNetns *self, NMActiveConnection *active, GError **error)
{
	NMDevice *device, *existing, *master_device = NULL;
	NMConnection *applied;
	NMSettingsConnection *connection;
	NMSettingsConnection *master_connection = NULL;
	NMConnection *existing_connection = NULL;
	NMActiveConnection *master_ac = NULL;
	NMAuthSubject *subject;
	char *error_desc = NULL;

	g_return_val_if_fail (NM_IS_NETNS (self), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	g_assert (NM_IS_VPN_CONNECTION (active) == FALSE);

	connection = nm_active_connection_get_settings_connection (active);
	g_assert (connection);

	applied = nm_active_connection_get_applied_connection (active);

	device = nm_active_connection_get_device (active);
	g_return_val_if_fail (device != NULL, FALSE);

	/* If the device is active and its connection is not visible to the
	 * user that's requesting this new activation, fail, since other users
	 * should not be allowed to implicitly deactivate private connections
	 * by activating a connection of their own.
	 */
	existing_connection = nm_device_get_applied_connection (device);
	subject = nm_active_connection_get_subject (active);
	if (existing_connection &&
	    !nm_auth_is_subject_in_acl (existing_connection,
	                                subject,
	                                &error_desc)) {
		g_set_error (error,
		             NM_NETNS_ERROR,
		             NM_NETNS_ERROR_PERMISSION_DENIED,
		             "Private connection already active on the device: %s",
		             error_desc);
		g_free (error_desc);
		return FALSE;
	}

	/* Final connection must be available on device */
	if (!nm_device_check_connection_available (device, applied, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
		g_set_error (error, NM_NETNS_ERROR, NM_NETNS_ERROR_UNKNOWN_CONNECTION,
		             "Connection '%s' is not available on the device %s at this time.",
		             nm_settings_connection_get_id (connection), nm_device_get_iface (device));
		return FALSE;
	}

	/* Create any backing resources the device needs */
	if (!nm_device_is_real (device)) {
		NMDevice *parent;

		parent = find_parent_device_for_connection (self, (NMConnection *) connection);
		if (!nm_device_create_and_realize (device, (NMConnection *) connection, parent, error)) {
			g_prefix_error (error, "%s failed to create resources: ", nm_device_get_iface (device));
			return FALSE;
		}
	}

	/* Try to find the master connection/device if the connection has a dependency */
	if (!find_master (self, applied, device,
	                  &master_connection, &master_device, &master_ac,
	                  error))
		return FALSE;

	/* Ensure there's a master active connection the new connection we're
	 * activating can depend on.
	 */
	if (master_connection || master_device) {
		if (master_connection) {
			_LOGD (LOGD_CORE, "Activation of '%s' requires master connection '%s'",
			       nm_settings_connection_get_id (connection),
			       nm_settings_connection_get_id (master_connection));
		}
		if (master_device) {
			_LOGD (LOGD_CORE, "Activation of '%s' requires master device '%s'",
			       nm_settings_connection_get_id (connection),
			       nm_device_get_ip_iface (master_device));
		}

		/* Ensure eg bond slave and the candidate master is a bond master */
		if (master_connection && !is_compatible_with_slave (NM_CONNECTION (master_connection), applied)) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			                     "The master connection was not compatible");
			return FALSE;
		}

		if (!master_ac) {
			master_ac = ensure_master_active_connection (self,
			                                             nm_active_connection_get_subject (active),
			                                             applied,
			                                             device,
			                                             master_connection,
			                                             master_device,
			                                             error);
			if (!master_ac) {
				if (error)
					g_assert (*error);
				return FALSE;
			}
		}

		nm_active_connection_set_master (active, master_ac);
		_LOGD (LOGD_CORE, "Activation of '%s' depends on active connection %p %s",
		       nm_settings_connection_get_id (connection),
		       master_ac,
		       nm_exported_object_get_path (NM_EXPORTED_OBJECT  (master_ac)) ?: "");
	}

	/* Check slaves for master connection and possibly activate them */
	autoconnect_slaves (self, connection, device, nm_active_connection_get_subject (active));

	/* Disconnect the connection if connected or queued on another device */
	existing = nm_netns_get_connection_device (self, NM_CONNECTION (connection));
	if (existing)
		nm_device_steal_connection (existing, connection);

	/* when creating the software device, it can happen that the device is
	 * still unmanaged by NM_UNMANAGED_PLATFORM_INIT because we didn't yet
	 * get the udev event. At this point, we can no longer delay the activation
	 * and force the device to be managed. */
	nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_PLATFORM_INIT, FALSE, NM_DEVICE_STATE_REASON_USER_REQUESTED);

	nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_USER_EXPLICIT, FALSE, NM_DEVICE_STATE_REASON_USER_REQUESTED);

	g_return_val_if_fail (nm_device_get_managed (device, FALSE), FALSE);

	if (nm_device_get_state (device) == NM_DEVICE_STATE_UNMANAGED) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
	}

	if (   nm_device_is_available (device, NM_DEVICE_CHECK_DEV_AVAILABLE_FOR_USER_REQUEST)
	    && (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
	}

	/* Export the new ActiveConnection to clients and start it on the device */
	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
	nm_device_queue_activation (device, NM_ACT_REQUEST (active));
	return TRUE;
}

static void
active_connection_default_changed (NMActiveConnection *active,
                                   GParamSpec *pspec,
                                   NMNetns *self)
{
#if 0
	/*
	 * TODO/BUG: State is global for NM so NMManager should take care of it!
	 */
	nm_manager_update_state (self);
#endif
}

/* Returns: whether to notify D-Bus of the removal or not */
static gboolean
active_connection_remove (NMNetns *self, NMActiveConnection *active)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	gboolean notify = nm_exported_object_is_exported (NM_EXPORTED_OBJECT (active));
	GSList *found;

	/* FIXME: switch to a GList for faster removal */
	found = g_slist_find (priv->active_connections, active);
	if (found) {
		NMSettingsConnection *connection;

		priv->active_connections = g_slist_remove (priv->active_connections, active);
		g_signal_emit (self, signals[ACTIVE_CONNECTION_REMOVED], 0, active);
		g_signal_handlers_disconnect_by_func (active, active_connection_state_changed, self);
		g_signal_handlers_disconnect_by_func (active, active_connection_default_changed, self);

		if (   nm_active_connection_get_assumed (active)
		    && (connection = nm_active_connection_get_settings_connection (active))
		    && nm_settings_connection_get_nm_generated_assumed (connection))
			g_object_ref (connection);
		else
			connection = NULL;

		nm_exported_object_clear_and_unexport (&active);

		if (   connection
		    && nm_settings_has_connection (nm_settings_get(), connection)) {
			_LOGD (LOGD_DEVICE, "assumed connection disconnected. Deleting generated connection '%s' (%s)",
			       nm_settings_connection_get_id (connection), nm_settings_connection_get_uuid (connection));
			nm_settings_connection_delete (NM_SETTINGS_CONNECTION (connection), NULL, NULL);
			g_object_unref (connection);
		}
	}

	return found && notify;
}

static gboolean
_active_connection_cleanup (gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GSList *iter;

	priv->ac_cleanup_id = 0;

	g_object_freeze_notify (G_OBJECT (self));
	iter = priv->active_connections;
	while (iter) {
		NMActiveConnection *ac = iter->data;

		iter = iter->next;
		if (nm_active_connection_get_state (ac) == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
			if (active_connection_remove (self, ac))
				g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
		}
	}
	g_object_thaw_notify (G_OBJECT (self));

	return FALSE;
}

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMActiveConnectionState state;

	state = nm_active_connection_get_state (active);
	if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		/* Destroy active connections from an idle handler to ensure that
		 * their last property change notifications go out, which wouldn't
		 * happen if we destroyed them immediately when their state was set
		 * to DEACTIVATED.
		 */
		if (!priv->ac_cleanup_id)
			priv->ac_cleanup_id = g_idle_add (_active_connection_cleanup, self);
	}

#if 0
	/*
	 * TODO/BUG: State is global for NM so NMManager should take care of it!
	 */
	nm_manager_update_state (self);
#endif
}

/**
 * active_connection_add():
 * @self: the #NMNetns
 * @active: the #NMActiveConnection to manage
 *
 * Begins to track and manage @active.  Increases the refcount of @active.
 */
static void
active_connection_add (NMNetns *self, NMActiveConnection *active)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	g_return_if_fail (g_slist_find (priv->active_connections, active) == FALSE);

	priv->active_connections = g_slist_prepend (priv->active_connections,
	                                            g_object_ref (active));

	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  self);
	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_DEFAULT,
	                  G_CALLBACK (active_connection_default_changed),
	                  self);
	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_DEFAULT6,
	                  G_CALLBACK (active_connection_default_changed),
	                  self);

	g_signal_emit (self, signals[ACTIVE_CONNECTION_ADDED], 0, active);

	/* Only notify D-Bus if the active connection is actually exported */
	if (nm_exported_object_is_exported (NM_EXPORTED_OBJECT (active)))
		g_object_notify (G_OBJECT (self), NM_NETNS_ACTIVE_CONNECTIONS);
}

#if 0
static void
policy_activating_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMDevice *activating;
#if 0
	NMDevice *activating, *best;
#endif
	NMActiveConnection *ac;

#if 0
	/* We only look at activating-ip6-device if activating-ip4-device
	 * AND default-ip4-device are NULL; if default-ip4-device is
	 * non-NULL, then activating-ip6-device is irrelevant, since while
	 * that device might become the new default-ip6-device, it can't
	 * become primary-connection while default-ip4-device is set to
	 * something else.
	 */
	activating = nm_policy_get_activating_ip4_device (priv->policy);
	best = nm_policy_get_default_ip4_device (priv->policy);
	if (!activating && !best)
		activating = nm_policy_get_activating_ip6_device (priv->policy);
#endif

	if (activating)
		ac = NM_ACTIVE_CONNECTION (nm_device_get_act_request (activating));
	else
		ac = NULL;

	if (ac != priv->activating_connection) {
		g_clear_object (&priv->activating_connection);
		priv->activating_connection = ac ? g_object_ref (ac) : NULL;
		_LOGD (LOGD_CORE, "ActivatingConnection now %s", ac ? nm_active_connection_get_settings_connection_id (ac) : "(none)");
		g_object_notify (G_OBJECT (self), NM_NETNS_ACTIVATING_CONNECTION);
	}
}
#endif

#if 0
static void
nm_netns_update_metered (NMNetns *self)
{
	NMNetnsPrivate *priv;
	NMDevice *device;
	NMMetered value = NM_METERED_UNKNOWN;

	g_return_if_fail (NM_IS_MANAGER (self));
	priv = NM_NETNS_GET_PRIVATE (self);

	if (priv->primary_connection) {
		device =  nm_active_connection_get_device (priv->primary_connection);
		if (device)
			value = nm_device_get_metered (device);
	}

	if (value != priv->metered) {
		priv->metered = value;
		_LOGD (LOGD_CORE, "new metered value: %d", (int) priv->metered);
		g_object_notify (G_OBJECT (self), NM_NETNS_METERED);
	}
}
#endif

#if 0
static void
policy_default_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);
        NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
#if 0
	NMDevice *best;
#endif
	NMActiveConnection *ac;

#if 0
	/* Note: this assumes that it's not possible for the IP4 default
	 * route to be going over the default-ip6-device. If that changes,
	 * we need something more complicated here.
	 */
	best = nm_policy_get_default_ip4_device (priv->policy);
	if (!best)
		best = nm_policy_get_default_ip6_device (priv->policy);

	if (best)
		ac = NM_ACTIVE_CONNECTION (nm_device_get_act_request (best));
	else
		ac = NULL;
#endif

	if (ac != priv->primary_connection) {
		if (priv->primary_connection) {
			g_signal_handlers_disconnect_by_func (priv->primary_connection,
			                                      G_CALLBACK (connection_metered_changed),
			                                      self);
			g_clear_object (&priv->primary_connection);
		}

		priv->primary_connection = ac ? g_object_ref (ac) : NULL;

		if (priv->primary_connection) {
			g_signal_connect (priv->primary_connection, NM_ACTIVE_CONNECTION_DEVICE_METERED_CHANGED,
			                  G_CALLBACK (connection_metered_changed), self);
		}
		_LOGD (LOGD_CORE, "PrimaryConnection now %s", ac ? nm_active_connection_get_settings_connection_id (ac) : "(none)");
		g_object_notify (G_OBJECT (self), NM_MANAGER_PRIMARY_CONNECTION);
		g_object_notify (G_OBJECT (self), NM_MANAGER_PRIMARY_CONNECTION_TYPE);
		nm_netns_update_metered (self);
        }
}
#endif

static gboolean
_internal_activate_generic (NMNetns *self, NMActiveConnection *active, GError **error)
{
#if 0
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
#endif
	gboolean success = FALSE;

	/* Ensure activation request is still valid, eg that its device hasn't gone
	 * away or that some other dependency has not failed.
	 */
	if (nm_active_connection_get_state (active) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_DEPENDENCY_FAILED,
		                     "Activation failed because dependencies failed.");
		return FALSE;
	}

	if (NM_IS_VPN_CONNECTION (active))
		success = _internal_activate_vpn (self, active, error);
	else
		success = _internal_activate_device (self, active, error);

	if (success) {
		/* Force an update of the Manager's activating-connection property.
		 * The device changes state before the AC gets exported, which causes
		 * the manager's 'activating-connection' property to be NULL since the
		 * AC only gets a D-Bus path when it's exported.  So now that the AC
		 * is exported, make sure the manager's activating-connection property
		 * is up-to-date.
		 */

		active_connection_add (self, active);
#if 0
		policy_activating_device_changed (G_OBJECT (priv->policy), NULL, self);
#endif
	}

	return success;
}

static void
_internal_activation_failed (NMNetns *self,
                             NMActiveConnection *active,
                             const char *error_desc)
{
	_LOGD (LOGD_CORE, "Failed to activate '%s': %s",
	       nm_active_connection_get_settings_connection_id (active),
	       error_desc);

	if (nm_active_connection_get_state (active) <= NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATING);
		nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
	}
}

static void
_internal_activation_auth_done (NMActiveConnection *active,
                                gboolean success,
                                const char *error_desc,
                                gpointer user_data1,
                                gpointer user_data2)
{
	NMNetns *self = user_data1;
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GError *error = NULL;

	priv->authorizing_connections = g_slist_remove (priv->authorizing_connections, active);

	if (success) {
		if (_internal_activate_generic (self, active, &error)) {
			g_object_unref (active);
			return;
		}
	}

	g_assert (error_desc || error);
	_internal_activation_failed (self, active, error_desc ? error_desc : error->message);
	g_object_unref (active);
	g_clear_error (&error);
}

/**
 * nm_manager_activate_connection():
 * @self: the #NMNetns
 * @connection: the #NMSettingsConnection to activate on @device
 * @specific_object: the specific object path, if any, for the activation
 * @device: the #NMDevice to activate @connection on
 * @subject: the subject which requested activation
 * @error: return location for an error
 *
 * Begins a new internally-initiated activation of @connection on @device.
 * @subject should be the subject of the activation that triggered this
 * one, or if this is an autoconnect request, a new internal subject.
 * The returned #NMActiveConnection is owned by the Manager and should be
 * referenced by the caller if the caller continues to use it.
 *
 * Returns: (transfer none): the new #NMActiveConnection that tracks
 * activation of @connection on @device
 */
NMActiveConnection *
nm_netns_activate_connection (NMNetns *self,
                              NMSettingsConnection *connection,
                              const char *specific_object,
                              NMDevice *device,
                              NMAuthSubject *subject,
                              GError **error)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMActiveConnection *active;
	char *error_desc = NULL;
	GSList *iter;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	/* Ensure the subject has permissions for this connection */
	if (!nm_auth_is_subject_in_acl (NM_CONNECTION (connection),
	                                subject,
	                                &error_desc)) {
		g_set_error_literal (error,
		                     NM_NETNS_ERROR,
		                     NM_NETNS_ERROR_PERMISSION_DENIED,
		                     error_desc);
		g_free (error_desc);
		return NULL;
	}

	/* Look for a active connection that's equivalent and is already pending authorization
	 * and eventual activation. This is used to de-duplicate concurrent activations which would
	 * otherwise race and cause the device to disconnect and reconnect repeatedly.
	 * In particular, this allows the master and multiple slaves to concurrently auto-activate
	 * while all the slaves would use the same active-connection. */
	for (iter = priv->authorizing_connections; iter; iter = g_slist_next (iter)) {
		active = iter->data;

		if (   connection == nm_active_connection_get_settings_connection (active)
		    && g_strcmp0 (nm_active_connection_get_specific_object (active), specific_object) == 0
		    && nm_active_connection_get_device (active) == device
		    && nm_auth_subject_is_internal (nm_active_connection_get_subject (active))
		    && nm_auth_subject_is_internal (subject))
			return active;
	}

	active = _new_active_connection (self,
	                                 NM_CONNECTION (connection),
	                                 specific_object,
	                                 device,
	                                 subject,
	                                 error);

	if (active) {
		priv->authorizing_connections = g_slist_prepend (priv->authorizing_connections, active);
		nm_active_connection_authorize (active, NULL, _internal_activation_auth_done, self, NULL);
	}

	return active;
}

static void
_activation_auth_done (NMActiveConnection *active,
                       gboolean success,
                       const char *error_desc,
                       gpointer user_data1,
                       gpointer user_data2)
{
	NMNetns *self = user_data1;
	GDBusMethodInvocation *context = user_data2;
	GError *error = NULL;
	NMAuthSubject *subject;
	NMSettingsConnection *connection;

	subject = nm_active_connection_get_subject (active);
	connection = nm_active_connection_get_settings_connection (active);

	if (success) {
		if (_internal_activate_generic (self, active, &error)) {
			g_dbus_method_invocation_return_value (context,
			                                       g_variant_new ("(o)",
			                                       nm_exported_object_get_path (NM_EXPORTED_OBJECT (active))));
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, TRUE,
			                            subject, NULL);
			g_object_unref (active);
			return;
		}
	} else {
		error = g_error_new_literal (NM_NETNS_ERROR,
		                             NM_NETNS_ERROR_PERMISSION_DENIED,
		                             error_desc);
	}

        g_assert (error);
        nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE,
                                    subject, error->message);
        _internal_activation_failed (self, active, error->message);

        g_object_unref (active);
        g_dbus_method_invocation_take_error (context, error);
}

static void
impl_netns_activate_connection (NMNetns *self,
                                GDBusMethodInvocation *context,
                                const char *connection_path,
                                const char *device_path,
                                const char *specific_object_path)
{
	NMActiveConnection *active = NULL;
	NMAuthSubject *subject = NULL;
	NMSettingsConnection *connection = NULL;
	NMDevice *device = NULL;
	gboolean is_vpn = FALSE;
	GError *error = NULL;

	/* Normalize object paths */
	if (g_strcmp0 (connection_path, "/") == 0)
		connection_path = NULL;
	if (g_strcmp0 (specific_object_path, "/") == 0)
		specific_object_path = NULL;
	if (g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

        /* If the connection path is given and valid, that connection is activated.
	 * Otherwise the "best" connection for the device is chosen and activated,
	 * regardless of whether that connection is autoconnect-enabled or not
	 * (since this is an explicit request, not an auto-activation request).
	 */
	if (!connection_path) {
		GPtrArray *available;
		guint64 best_timestamp = 0;
		guint i;

		/* If no connection is given, find a suitable connection for the given device path */
		if (!device_path) {
			error = g_error_new_literal (NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                             "Only devices may be activated without a specifying a connection");
			goto error;
		}
		device = nm_netns_get_device_by_path (self, device_path);
		if (!device) {
			error = g_error_new (NM_NETNS_ERROR, NM_NETNS_ERROR_UNKNOWN_DEVICE,
			                     "Cannot activate unknown device %s", device_path);
			goto error;
		}

		available = nm_device_get_available_connections (device, specific_object_path);
		for (i = 0; available && i < available->len; i++) {
			NMSettingsConnection *candidate = g_ptr_array_index (available, i);
			guint64 candidate_timestamp = 0;

			nm_settings_connection_get_timestamp (candidate, &candidate_timestamp);
			if (!connection_path || (candidate_timestamp > best_timestamp)) {
				connection_path = nm_connection_get_path (NM_CONNECTION (candidate));
				best_timestamp = candidate_timestamp;
			}
		}

		if (available)
			g_ptr_array_free (available, TRUE);

		if (!connection_path) {
			error = g_error_new_literal (NM_NETNS_ERROR,
			                             NM_NETNS_ERROR_UNKNOWN_CONNECTION,
			                             "The device has no connections available.");
			goto error;
		}
	}

	g_assert (connection_path);
	connection = nm_settings_get_connection_by_path (nm_settings_get(), connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_NETNS_ERROR,
		                             NM_NETNS_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		goto error;
	}

	subject = validate_activation_request (self,
	                                       context,
	                                       NM_CONNECTION (connection),
	                                       device_path,
	                                       &device,
	                                       &is_vpn,
	                                       &error);
	if (!subject)
		goto error;

	active = _new_active_connection (self,
	                                 NM_CONNECTION (connection),
	                                 specific_object_path,
	                                 device,
	                                 subject,
	                                 &error);
	if (!active)
		goto error;

	nm_active_connection_authorize (active, NULL, _activation_auth_done, self, context);
	g_clear_object (&subject);
	return;

error:
	if (connection) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE,
		                            subject, error->message);
	}
	g_clear_object (&active);
	g_clear_object (&subject);

	g_assert (error);
	g_dbus_method_invocation_take_error (context, error);
}


/******************************************************************/

#if 0
static void
system_hostname_changed_cb (NMSettings *settings,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	char *hostname;

	hostname = nm_settings_get_hostname (nm_settings_get());

	/* nm_settings_get_hostname() does not return an empty hostname. */
	nm_assert (!hostname || *hostname);

	if (!hostname && !priv->hostname)
		return;
	if (hostname && priv->hostname && !strcmp (hostname, priv->hostname)) {
		g_free (hostname);
		return;
	}

	/* realloc, to free possibly trailing data after NUL. */
	if (hostname)
		hostname = g_realloc (hostname, strlen (hostname) + 1);

	g_free (priv->hostname);
	priv->hostname = hostname;

	g_object_notify (G_OBJECT (self), NM_NETNS_HOSTNAME);

        nm_dhcp_manager_set_default_hostname (nm_dhcp_manager_get (), priv->hostname);
}
#endif

static NMDevice *
find_device_by_hw_addr (NMNetns *netns, const char *hwaddr)
{
	GSList *iter;
	const char *device_addr;

	g_return_val_if_fail (hwaddr != NULL, NULL);

	if (nm_utils_hwaddr_valid (hwaddr, -1)) {
		for (iter = NM_NETNS_GET_PRIVATE (netns)->devices; iter; iter = iter->next) {
			device_addr = nm_device_get_hw_address (NM_DEVICE (iter->data));
			if (device_addr && nm_utils_hwaddr_matches (hwaddr, -1, device_addr, -1))
				return NM_DEVICE (iter->data);
		}
	}
	return NULL;
}

/**
 * nm_netns_get_connection_iface:
 * @self: the #NMNetns
 * @connection: the #NMConnection representing a virtual interface
 * @out_parent: on success, the parent device if any
 * @error: an error if determining the virtual interface name failed
 *
 * Given @connection, returns the interface name that the connection
 * would represent if it is a virtual connection.  %NULL is returned and
 * @error is set if the connection is not virtual, or if the name could
 * not be determined.
 *
 * Returns: the expected interface name (caller takes ownership), or %NULL
 */
char *
nm_netns_get_connection_iface (NMNetns *self,
                               NMConnection *connection,
                               NMDevice **out_parent,
                               GError **error)
{
	NMDeviceFactory *factory;
	char *iface = NULL;
	NMDevice *parent = NULL;

	if (out_parent)
		*out_parent = NULL;

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	if (   !out_parent
	    && !NM_DEVICE_FACTORY_GET_INTERFACE (factory)->get_connection_iface) {
		/* optimization. Shortcut lookup of the partent device. */
		iface = g_strdup (nm_connection_get_interface_name (connection));
		if (!iface) {
			g_set_error (error,
			             NM_NETNS_ERROR,
			             NM_NETNS_ERROR_FAILED,
			             "failed to determine interface name: error determine name for %s",
			             nm_connection_get_connection_type (connection));
		}
		return iface;
        }

	parent = find_parent_device_for_connection (self, connection);
	iface = nm_device_factory_get_connection_iface (factory,
	                                                connection,
	                                                parent ? nm_device_get_ip_iface (parent) : NULL,
	                                                error);
	if (!iface)
		return NULL;

	if (out_parent)
		*out_parent = parent;

	return iface;
}

/**
 * system_create_virtual_device:
 * @self: the #NMNetns
 * @connection: the connection which might require a virtual device
 *
 * If @connection requires a virtual device and one does not yet exist for it,
 * creates that device.
 *
 * Returns: A #NMDevice that was just realized; %NULL if none
 */
static NMDevice *
system_create_virtual_device (NMNetns *self, NMConnection *connection)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	gs_free_slist GSList *connections = NULL;
	GSList *iter;
	gs_free char *iface = NULL;
	NMDevice *device = NULL, *parent = NULL;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_NETNS (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	iface = nm_netns_get_connection_iface (self, connection, &parent, &error);
	if (!iface) {
		nm_log_warn (LOGD_NETNS, "(%s) can't get a name of a virtual device: %s",
		             nm_connection_get_id (connection), error->message);
		g_error_free (error);
		return NULL;
	}

	/* See if there's a device that is already compatible with this connection */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;

		if (   g_strcmp0 (nm_device_get_iface (candidate), iface) == 0
		    && nm_device_check_connection_compatible (candidate, connection)) {

			if (nm_device_is_real (candidate)) {
				nm_log_dbg (LOGD_DEVICE, "(%s) already created virtual interface name %s",
				            nm_connection_get_id (connection), iface);
				return NULL;
			}

			device = candidate;
			break;
		}
	}

	if (!device) {
		/* No matching device found. Proceed creating a new one. */

		factory = nm_device_factory_manager_find_factory_for_connection (connection);
		if (!factory) {
			nm_log_err (LOGD_DEVICE, "(%s:%s) NetworkManager plugin for '%s' unavailable",
			            nm_connection_get_id (connection), iface,
			            nm_connection_get_connection_type (connection));
			return NULL;
		}

		device = nm_device_factory_create_device (factory, iface, NULL, connection, self, NULL, &error);
		if (!device) {
			nm_log_warn (LOGD_DEVICE, "(%s) factory can't create the device: %s",
			             nm_connection_get_id (connection), error->message);
			g_error_free (error);
			return NULL;
		}

		if (!add_device (self, device, &error)) {
			nm_log_warn (LOGD_DEVICE, "(%s) can't register the device with manager: %s",
			             nm_connection_get_id (connection), error->message);
			g_error_free (error);
			g_object_unref (device);
			return NULL;
		}

		/* Add device takes a reference that NMNetns still owns, so it's
		 * safe to unref here and still return @device.
		 */
		g_object_unref (device);
	}

	/* Create backing resources if the device has any autoconnect connections */
	connections = nm_settings_get_connections (nm_settings_get());
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = iter->data;
		NMSettingConnection *s_con;

		if (!nm_device_check_connection_compatible (device, candidate))
			continue;

		s_con = nm_connection_get_setting_connection (candidate);
		g_assert (s_con);
		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		/* Create any backing resources the device needs */
		if (!nm_device_create_and_realize (device, connection, parent, &error)) {
			nm_log_warn (LOGD_DEVICE, "(%s) couldn't create the device: %s",
			             nm_connection_get_id (connection), error->message);
			g_error_free (error);
			remove_device (self, device, FALSE, TRUE);
			return NULL;
		}
		break;
	}

	return device;
}

static NMDevice *
find_parent_device_for_connection (NMNetns *self, NMConnection *connection)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMDeviceFactory *factory; 
	const char *parent_name = NULL;
	NMSettingsConnection *parent_connection;
	NMDevice *parent, *first_compatible = NULL;
	GSList *iter;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory)
		return NULL;

	parent_name = nm_device_factory_get_connection_parent (factory, connection);
	if (!parent_name)
		return NULL;

	/* Try as an interface name of a parent device */ 
	parent = find_device_by_iface (self, parent_name, NULL, NULL);
	if (parent)
		return parent;

	/* Maybe a hardware address */
	parent = find_device_by_hw_addr (self, parent_name);
	if (parent)
		return parent;

	/* Maybe a connection UUID */
	parent_connection = nm_settings_get_connection_by_uuid (nm_settings_get(), parent_name);
	if (!parent_connection)
		return NULL;

	/* Check if the parent connection is currently activated or is comaptible
	 * with some known device.
	 */ 
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		if (nm_device_get_settings_connection (candidate) == parent_connection)
			return candidate;

		if (   !first_compatible
		    && nm_device_check_connection_compatible (candidate, NM_CONNECTION (parent_connection)))
			first_compatible = candidate;
	}

	return first_compatible;
}

static void
retry_connections_for_parent_device (NMNetns *self, NMDevice *device)
{
	GSList *connections, *iter;

	g_return_if_fail (device);

	connections = nm_settings_get_connections (nm_settings_get());
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = iter->data;
		NMDevice *parent;

		parent = find_parent_device_for_connection (self, candidate);
                if (parent == device) {
			char *ifname;
			GError *error;

                        /* Only try to activate devices that don't already exist */
                        ifname = nm_netns_get_connection_iface (self, candidate, &parent, &error);
                        if (ifname) {
                                if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, ifname))
                                        connection_changed (nm_settings_get (), candidate, self);
                        }
                }
	}

	g_slist_free (connections);
}

static void
connection_changed (NMSettings *settings,
                    NMConnection *connection,
                    NMNetns *netns)
{
	NMDevice *device;

	if (!nm_connection_is_virtual (connection))
		return;

	device = system_create_virtual_device (netns, connection);
	if (!device)
		return;

	/* Maybe the device that was created was needed by some other
	 * connection's device (parent of a VLAN). Let the connections
	 * can use the newly created device as a parent know. */
	retry_connections_for_parent_device (netns, device);
}

#if 0
static void
connection_removed (NMSettings *settings,
                    NMSettingsConnection *connection,
                    NMNetns *netns)
{
	/*
	 * Do not delete existing virtual devices to keep connectivity up.
	 * Virtual devices are reused when NetworkManager is restarted.
	 */
}

static void
system_unmanaged_devices_changed_cb (NMSettings *settings,
                                     GParamSpec *pspec,
                                     gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	const GSList *unmanaged_specs, *iter;

	unmanaged_specs = nm_settings_get_unmanaged_specs (nm_settings_get());
	for (iter = priv->devices; iter; iter = g_slist_next (iter))
		nm_device_set_unmanaged_by_user_config (NM_DEVICE (iter->data), unmanaged_specs);
}
#endif

static void
_config_changed_cb (NMConfig *config, NMConfigData *config_data, NMConfigChangeFlags changes, NMConfigData *old_data, NMNetns *self)
{
	g_object_set (NM_NETNS_GET_PRIVATE (self)->connectivity,
	              NM_CONNECTIVITY_URI, nm_config_data_get_connectivity_uri (config_data),
	              NM_CONNECTIVITY_INTERVAL, nm_config_data_get_connectivity_interval (config_data),
	              NM_CONNECTIVITY_RESPONSE, nm_config_data_get_connectivity_response (config_data),
	              NULL);

#if 0
	if (NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG))
		g_object_notify (G_OBJECT (self), NM_MANAGER_GLOBAL_DNS_CONFIGURATION);
#endif
}

#if 0
static void
connectivity_changed (NMConnectivity *connectivity,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	NMNetns *self = NM_NETNS (user_data);

	nm_log_dbg (LOGD_NETNS, "connectivity checking indicates %s",
	            nm_connectivity_state_to_string (nm_connectivity_get_state (connectivity)));

	nm_netns_update_state (self);
	g_object_notify (G_OBJECT (self), NM_MANAGER_CONNECTIVITY);
}
#endif

/******************************************************************/

static void
nm_netns_init (NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMConfigData *config_data;

#if 0
	/*
	 * TODO/BUG: What is this for?
	 */
	_set_prop_filter (self, nm_bus_manager_get_connection (priv->dbus_mgr));

	priv->settings = nm_settings_get ();
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_HOSTNAME,
	                  G_CALLBACK (system_hostname_changed_cb), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (connection_changed), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED_BY_USER,
	                  G_CALLBACK (connection_changed), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed), self);
#endif

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_config_changed_cb),
	                  self);

	config_data = nm_config_get_data (priv->config);
#if 0
	priv->connectivity = nm_connectivity_new (nm_config_data_get_connectivity_uri (config_data),
	                                          nm_config_data_get_connectivity_interval (config_data),
	                                          nm_config_data_get_connectivity_response (config_data));
	g_signal_connect (priv->connectivity, "notify::" NM_CONNECTIVITY_STATE,
	                  G_CALLBACK (connectivity_changed), self);
#endif

	/* Load VPN plugins */
	priv->vpn_manager = g_object_ref (nm_vpn_manager_get ());
}

static gboolean
device_is_real (GObject *device, gpointer user_data)
{
	return nm_device_is_real (NM_DEVICE (device));
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMNetns *self = NM_NETNS (object);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	const char *type;

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_netns_get_name (self));
		break;
	case PROP_DEVICES:
		nm_utils_g_value_set_object_path_array (value, priv->devices, device_is_real, NULL);
		break;
	case PROP_ALL_DEVICES:
		nm_utils_g_value_set_object_path_array (value, priv->devices, NULL, NULL);
		break;
	case PROP_PRIMARY_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->primary_connection);
		break;
	case PROP_PRIMARY_CONNECTION_TYPE:
		type = NULL;
		if (priv->primary_connection) {
			NMConnection *con;

			con = nm_active_connection_get_applied_connection (priv->primary_connection);
			if (con)
				type = nm_connection_get_connection_type (con);
		}
		g_value_set_string (value, type ? type : "");
		break;
	case PROP_ACTIVATING_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->activating_connection);
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	NMNetns *self = NM_NETNS (object);

	switch (prop_id) {
	case PROP_NAME:
		nm_netns_set_name (self, g_value_get_string (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMNetns *netns = NM_NETNS (object);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (netns);

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, _config_changed_cb, netns);
		g_clear_object (&priv->config);
	}

	g_clear_object (&priv->vpn_manager);

#if 0
	if (priv->connectivity) {
		g_signal_handlers_disconnect_by_func (priv->connectivity, connectivity_changed, netns);
		g_clear_object (&priv->connectivity);
	}
#endif

	g_free (priv->hostname);

#if 0
	if (priv->settings) {
		g_signal_handlers_disconnect_by_func (priv->settings, system_unmanaged_devices_changed_cb, netns);
		g_signal_handlers_disconnect_by_func (priv->settings, system_hostname_changed_cb, netns);
		g_signal_handlers_disconnect_by_func (priv->settings, connection_changed, netns);
		g_signal_handlers_disconnect_by_func (priv->settings, connection_removed, netns);
		g_clear_object (&priv->settings);
	}
#endif

        G_OBJECT_CLASS (nm_netns_parent_class)->finalize (object);
}

static void
nm_netns_class_init (NMNetnsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMNetnsPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_NETNS "/%u";

        /* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* Network namespace's name */
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_NETNS_NAME, "", "",
				      NULL,
				      G_PARAM_READABLE |
				      G_PARAM_STATIC_STRINGS));

	/* Realized devices in the network namespace */
	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_NETNS_DEVICES, "", "",
				     G_TYPE_STRV,
				     G_PARAM_READABLE |
				     G_PARAM_STATIC_STRINGS));

	/* All devices in the network namespace */
	g_object_class_install_property
		(object_class, PROP_ALL_DEVICES,
		 g_param_spec_boxed (NM_NETNS_ALL_DEVICES, "", "",
				     G_TYPE_STRV,
				     G_PARAM_READABLE |
				     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_string (NM_NETNS_PRIMARY_CONNECTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION_TYPE,
		 g_param_spec_string (NM_NETNS_PRIMARY_CONNECTION_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_string (NM_NETNS_ACTIVATING_CONNECTION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMManager:metered:
	 *
	 * Whether the connectivity is metered.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_METERED,
		 g_param_spec_uint (NM_NETNS_METERED, "", "",
		                    0, G_MAXUINT32, NM_METERED_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/* Signals */
        signals[DEVICE_ADDED] =
                g_signal_new (NM_NETNS_DEVICE_ADDED,
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0, NULL, NULL, NULL,
                              G_TYPE_NONE, 1, NM_TYPE_DEVICE);

        signals[DEVICE_REMOVED] =
                g_signal_new (NM_NETNS_DEVICE_REMOVED,
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0, NULL, NULL, NULL,
                              G_TYPE_NONE, 1, NM_TYPE_DEVICE);

        signals[INTERNAL_DEVICE_ADDED] =
                g_signal_new (NM_NETNS_INTERNAL_DEVICE_ADDED,
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0, NULL, NULL, NULL,
                              G_TYPE_NONE, 1, NM_TYPE_DEVICE);

        signals[INTERNAL_DEVICE_REMOVED] =
                g_signal_new (NM_NETNS_INTERNAL_DEVICE_REMOVED,
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0, NULL, NULL, NULL,
                              G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	signals[ACTIVE_CONNECTION_ADDED] =
		g_signal_new (NM_NETNS_ACTIVE_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, NM_TYPE_ACTIVE_CONNECTION);

	signals[ACTIVE_CONNECTION_REMOVED] =
		g_signal_new (NM_NETNS_ACTIVE_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, NM_TYPE_ACTIVE_CONNECTION);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
						NMDBUS_TYPE_NET_NS_INSTANCE_SKELETON,
						"GetDevices", impl_netns_get_devices,
						"GetAllDevices", impl_netns_get_all_devices,
						"TakeDevice", impl_netns_take_device,
	                                        "ActivateConnection", impl_netns_activate_connection,
						NULL);
}

