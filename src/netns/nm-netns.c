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

#include "nmdbus-netns.h"

static void
connection_changed (NMSettings *settings,
                    NMConnection *connection,
                    NMNetns *netns);

static void
retry_connections_for_parent_device (NMNetns *self, NMDevice *device);

static NMDevice *
find_parent_device_for_connection (NMNetns *self, NMConnection *connection);

G_DEFINE_TYPE (NMNetns, nm_netns, NM_TYPE_EXPORTED_OBJECT)

#define NM_NETNS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS, NMNetnsPrivate))

enum {
	PROP_0 = 0,
	PROP_NAME,
	PROP_DEVICES,
	PROP_ALL_DEVICES,
};

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	INTERNAL_DEVICE_ADDED,
	INTERNAL_DEVICE_REMOVED,
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

	/*
	 * Hostname in the given network namespace
	 */
        char *hostname;


} NMNetnsPrivate;

/**************************************************************/

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
 */
static void
_device_change_callback_activate_and_remove(NMNetns *self, NMDevice *device)
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
	GSList *iter;

	for (iter = NM_NETNS_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_ifindex (device) == ifindex)
			return device;
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
	_device_change_callback_activate_and_remove(self, device);

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

static void
_get_devices (NMManager *self,
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
impl_netns_get_devices (NMManager *self,
			  GDBusMethodInvocation *context)
{
	_get_devices (self, context, FALSE);
}

static void
impl_netns_get_all_devices (NMManager *self,
			      GDBusMethodInvocation *context)
{
	_get_devices (self, context, TRUE);
}

static NMDevice *
find_device_by_path(NMNetns *self, const char *device_path)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = iter->next) {
		const char *path;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data));

		if (!strcmp(path, device_path))
			return iter->data;
        }

	return NULL;
}

static void
impl_netns_move_device_to_network_namespace (NMNetns *self,
                                             GDBusMethodInvocation *context,
                                             const char *device_path,
                                             const char *netns_path)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);
	NMNetns *target;
	NMDevice *device;

	device = find_device_by_path(self, device_path);

	if (!device) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_UNKNOWN_DEVICE,
		                                       "Target namespace wasn't found.");
		return;
	}

	target = nm_netns_controller_find_netns_by_path(netns_path);

	if (!target) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_TARGET_NETNS_NOT_FOUND,
		                                       "Target namespace wasn't found.");
		return;
	}

	if (target == self) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_DEVICE_ALREADY_IN_NETNS,
		                                       "Device already in target namespace.");
		return;
	}

	if (!nm_platform_link_set_netns(priv->platform, nm_device_get_ifindex(device), nm_netns_get_id(target)))
		g_dbus_method_invocation_return_error (context,
		                                       NM_NETNS_ERROR,
		                                       NM_NETNS_ERROR_FAILED,
		                                       "Error moving device to target namespace");
	else
		g_dbus_method_invocation_return_value (context, NULL);
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

		/* Add device takes a reference that NMManager still owns, so it's
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
		if (parent == device)
			connection_changed (nm_settings_get(), candidate, self);
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

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
						NMDBUS_TYPE_NET_NS_INSTANCE_SKELETON,
						"GetDevices", impl_netns_get_devices,
						"GetAllDevices", impl_netns_get_all_devices,
						"MoveDeviceToNetworkNamespace", impl_netns_move_device_to_network_namespace,
						NULL);
}

