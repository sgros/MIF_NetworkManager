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
#include "nm-device.h"
#include "nm-device-generic.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-netns.h"

#include "nmdbus-netns.h"

G_DEFINE_TYPE (NMNetns, nm_netns, NM_TYPE_EXPORTED_OBJECT)

#define NM_NETNS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS, NMNetnsPrivate))

enum {
	PROP_0 = 0,
	PROP_NAME,
	PROP_DEVICES,
	PROP_ALL_DEVICES,
};

typedef struct {

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
} NMNetnsPrivate;

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

	/*
	 * TODO/BUG: Where is unref?!?!?
	 */
	g_object_ref(platform);
	priv->platform = platform;
}

NMPlatform *
nm_netns_get_platform(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->platform;
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

static void
remove_device (NMNetns *self,
	       NMDevice *device,
	       gboolean quitting,
	       gboolean allow_unmanage)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	nm_log_dbg (LOGD_NETNS, "(%s): removing device (allow_unmanage %d, managed %d)",
		    nm_device_get_iface (device), allow_unmanage, nm_device_get_managed (device));

	if (allow_unmanage && nm_device_get_managed (device)) {
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
				nm_device_set_unmanaged_quitting (device);
			else
				nm_device_set_unmanaged_flags (device, NM_UNMANAGED_INTERNAL, TRUE, NM_DEVICE_STATE_REASON_REMOVED);
		} else if (quitting && nm_config_get_configure_and_quit (nm_config_get ())) {
			nm_device_spawn_iface_helper (device);
		}
	}

#if 0
	g_signal_handlers_disconnect_matched (device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, manager);

	nm_settings_device_removed (priv->settings, device, quitting);
#endif
	priv->devices = g_slist_remove (priv->devices, device);

	if (nm_device_is_real (device)) {
#if 0
		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
#endif
		g_object_notify (G_OBJECT (self), NM_NETNS_DEVICES);
		nm_device_removed (device);
	}
#if 0
	g_signal_emit (self, signals[INTERNAL_DEVICE_REMOVED], 0, device);
#endif
	g_object_notify (G_OBJECT (self), NM_NETNS_ALL_DEVICES);

	nm_exported_object_clear_and_unexport (&device);

#if 0
	check_if_startup_complete (manager);
#endif
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

	g_signal_connect (device, NM_DEVICE_REMOVED,
			  G_CALLBACK (device_removed_cb),
			  self);

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

#if 0
	unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);
	nm_device_set_unmanaged_flags_initial (device,
					       NM_UNMANAGED_USER,
					       nm_device_spec_match_list (device, unmanaged_specs));
	nm_device_set_unmanaged_flags_initial (device,
					       NM_UNMANAGED_INTERNAL,
					       manager_sleeping (self));
#endif

	dbus_path = nm_exported_object_export (NM_EXPORTED_OBJECT (device));
	nm_log_info (LOGD_NETNS, "(%s): new %s device (%s)", iface, type_desc, dbus_path);

	nm_device_finish_init (device);

#if 0
	nm_settings_device_added (priv->settings, device);
	g_signal_emit (self, signals[INTERNAL_DEVICE_ADDED], 0, device);
	g_object_notify (G_OBJECT (self), NM_MANAGER_ALL_DEVICES);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *d = iter->data;

		if (d != device)
			nm_device_notify_new_device_added (d, device);
	}

	/* Virtual connections may refer to the new device as
	 * parent device, retry to activate them.
	 */
	retry_connections_for_parent_device (self, device);
#endif

	return TRUE;
}


static void
platform_link_added (NMNetns *self,
		     int ifindex,
		     const NMPlatformLink *plink)
{
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

		device = nm_device_factory_create_device (factory, plink->name, plink, NULL, &ignore, &error);
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
			device = nm_device_generic_new (plink);
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
nm_netns_setup(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	g_signal_connect (priv->platform,
			  NM_PLATFORM_SIGNAL_LINK_CHANGED,
			  G_CALLBACK (platform_link_cb),
			  self);

	/*
	 * Enumerate all existing devices in the network namespace
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

	while (priv->devices)
		remove_device (self, NM_DEVICE (priv->devices->data), TRUE, TRUE);

	nm_platform_netns_destroy(priv->platform, priv->name);

	g_object_unref(priv->platform);
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

/******************************************************************/

static void
nm_netns_init (NMNetns *self)
{
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
nm_netns_class_init (NMNetnsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMNetnsPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_NETNS "/%u";

        /* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;

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

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
						NMDBUS_TYPE_NET_NS_INSTANCE_SKELETON,
						"GetDevices", impl_netns_get_devices,
						"GetAllDevices", impl_netns_get_all_devices,
						NULL);


}

