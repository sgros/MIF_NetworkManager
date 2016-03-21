/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2005 - 2014 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <gudev/gudev.h>

#include "nm-device-ethernet.h"
#include "nm-device-private.h"
#include "nm-activation-request.h"
#include "NetworkManagerUtils.h"
#include "nm-supplicant-manager.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-enum-types.h"
#include "nm-platform.h"
#include "nm-platform-utils.h"
#include "nm-dcb.h"
#include "nm-settings-connection.h"
#include "nm-config.h"
#include "nm-device-ethernet-utils.h"
#include "nm-connection-provider.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

#include "nmdbus-device-ethernet.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceEthernet);

G_DEFINE_TYPE (NMDeviceEthernet, nm_device_ethernet, NM_TYPE_DEVICE)

#define NM_DEVICE_ETHERNET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_ETHERNET, NMDeviceEthernetPrivate))

#define WIRED_SECRETS_TRIES "wired-secrets-tries"

#define PPPOE_RECONNECT_DELAY 7
#define PPPOE_ENCAP_OVERHEAD  8 /* 2 bytes for PPP, 6 for PPPoE */

typedef struct Supplicant {
	NMSupplicantManager *mgr;
	NMSupplicantInterface *iface;

	/* signal handler ids */
	gulong iface_error_id;
	gulong iface_state_id;

	/* Timeouts and idles */
	guint iface_con_error_cb_id;
	guint con_timeout_id;
} Supplicant;

typedef enum {
	DCB_WAIT_UNKNOWN = 0,
	/* Ensure carrier is up before enabling DCB */
	DCB_WAIT_CARRIER_PREENABLE_UP,
	/* Wait for carrier down when device starts enabling */
	DCB_WAIT_CARRIER_PRECONFIG_DOWN,
	/* Wait for carrier up when device has finished enabling */
	DCB_WAIT_CARRIER_PRECONFIG_UP,
	/* Wait carrier down when device starts configuring */
	DCB_WAIT_CARRIER_POSTCONFIG_DOWN,
	/* Wait carrier up when device has finished configuring */
	DCB_WAIT_CARRIER_POSTCONFIG_UP,
} DcbWait;

typedef struct {
	guint32             speed;

	Supplicant          supplicant;
	guint               supplicant_timeout_id;

	/* s390 */
	char *              subchan1;
	char *              subchan2;
	char *              subchan3;
	char *              subchannels; /* Composite used for checking unmanaged specs */
	char **             subchannels_dbus; /* Array exported on D-Bus */
	char *              s390_nettype;
	GHashTable *        s390_options;

	/* PPPoE */
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;
	gint32        last_pppoe_time;
	guint         pppoe_wait_id;

	/* DCB */
	DcbWait       dcb_wait;
	guint         dcb_timeout_id;
	gulong        dcb_carrier_id;
} NMDeviceEthernetPrivate;

enum {
	PROP_0,
	PROP_PERM_HW_ADDRESS,
	PROP_SPEED,
	PROP_S390_SUBCHANNELS,

	LAST_PROP
};


static char *
get_link_basename (const char *parent_path, const char *name, GError **error)
{
	char *link_dest, *path;
	char *result = NULL;

	path = g_strdup_printf ("%s/%s", parent_path, name);
	link_dest = g_file_read_link (path, error);
	if (link_dest) {
		result = g_path_get_basename (link_dest);
		g_free (link_dest);
	}
	g_free (path);
	return result;
}

static void
_update_s390_subchannels (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMPlatform *platform;
	GUdevDevice *dev;
	GUdevDevice *parent = NULL;
	const char *parent_path, *item, *driver;
	int ifindex;
	GDir *dir;
	GError *error = NULL;

	ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	platform = nm_device_get_platform (NM_DEVICE (self));

	/*
	 * This function is called from the object initialization code
	 * and at that time no platform specific object is created.
	 * So, in that case use the platform object that is bound to
	 * root namespace. In all other cases take platform from the
	 * device itself.
	 */
	dev = (GUdevDevice *) nm_platform_link_get_udev_device (platform ? platform : NM_PLATFORM_GET, ifindex);
	if (!dev) {
		_LOGW (LOGD_DEVICE | LOGD_HW, "failed to find device %d '%s' with udev",
		       ifindex, nm_device_get_iface (NM_DEVICE (self)) ?: "(null)");
		goto out;
	}
	g_object_ref (dev);

	/* Try for the "ccwgroup" parent */
	parent = g_udev_device_get_parent_with_subsystem (dev, "ccwgroup", NULL);
	if (!parent) {
		/* FIXME: whatever 'lcs' devices' subsystem is here... */
		if (!parent) {
			/* Not an s390 device */
			goto out;
		}
	}

	parent_path = g_udev_device_get_sysfs_path (parent);
	dir = g_dir_open (parent_path, 0, &error);
	if (!dir) {
		_LOGW (LOGD_DEVICE | LOGD_HW, "failed to open directory '%s': %s",
		       parent_path, error->message);
		g_clear_error (&error);
		goto out;
	}

	while ((item = g_dir_read_name (dir))) {
		if (!strcmp (item, "cdev0")) {
			priv->subchan1 = get_link_basename (parent_path, "cdev0", &error);
		} else if (!strcmp (item, "cdev1")) {
			priv->subchan2 = get_link_basename (parent_path, "cdev1", &error);
		} else if (!strcmp (item, "cdev2")) {
			priv->subchan3 = get_link_basename (parent_path, "cdev2", &error);
		} else if (!strcmp (item, "driver")) {
			priv->s390_nettype = get_link_basename (parent_path, "driver", &error);
		} else if (   !strcmp (item, "layer2")
		           || !strcmp (item, "portname")
		           || !strcmp (item, "portno")) {
			char *path, *value;
			path = g_strdup_printf ("%s/%s", parent_path, item);
			value = nm_platform_sysctl_get (NM_PLATFORM_GET, path);
			if (value && *value)
				g_hash_table_insert (priv->s390_options, g_strdup (item), g_strdup (value));
			else
				_LOGW (LOGD_DEVICE | LOGD_HW, "error reading %s", path);
			g_free (path);
			g_free (value);
		}
		if (error) {
			_LOGW (LOGD_DEVICE | LOGD_HW, "%s", error->message);
			g_clear_error (&error);
		}
	}

	g_dir_close (dir);

	if (priv->subchan3) {
		priv->subchannels = g_strdup_printf ("%s,%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2,
		                                     priv->subchan3);
	} else if (priv->subchan2) {
		priv->subchannels = g_strdup_printf ("%s,%s",
		                                     priv->subchan1,
		                                     priv->subchan2);
	} else
		priv->subchannels = g_strdup (priv->subchan1);

	priv->subchannels_dbus = g_new (char *, 3 + 1);
	priv->subchannels_dbus[0] = g_strdup (priv->subchan1);
	priv->subchannels_dbus[1] = g_strdup (priv->subchan2);
	priv->subchannels_dbus[2] = g_strdup (priv->subchan3);
	priv->subchannels_dbus[3] = NULL;

	driver = nm_device_get_driver (NM_DEVICE (self));
	_LOGI (LOGD_DEVICE | LOGD_HW, "found s390 '%s' subchannels [%s]",
	       driver ? driver : "(unknown driver)", priv->subchannels);

out:
	if (parent)
		g_object_unref (parent);
	if (dev)
		g_object_unref (dev);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_ethernet_parent_class)->constructor (type,
	                                                                        n_construct_params,
	                                                                        construct_params);
	if (object) {
#ifndef G_DISABLE_ASSERT
		int ifindex = nm_device_get_ifindex (NM_DEVICE (object));
		NMLinkType link_type = nm_platform_link_get_type (NM_PLATFORM_GET, ifindex);

		g_assert (   link_type == NM_LINK_TYPE_ETHERNET
		          || link_type == NM_LINK_TYPE_VETH
		          || link_type == NM_LINK_TYPE_NONE);
#endif

		/* s390 stuff */
		_update_s390_subchannels (NM_DEVICE_ETHERNET (object));
	}

	return object;
}

static void
clear_secrets_tries (NMDevice *device)
{
	NMActRequest *req;
	NMConnection *connection;

	req = nm_device_get_act_request (device);
	if (req) {
		connection = nm_act_request_get_applied_connection (req);
		/* Clear wired secrets tries on success, failure, or when deactivating */
		g_object_set_data (G_OBJECT (connection), WIRED_SECRETS_TRIES, NULL);
	}
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	if (   new_state == NM_DEVICE_STATE_ACTIVATED
	    || new_state == NM_DEVICE_STATE_FAILED
	    || new_state == NM_DEVICE_STATE_DISCONNECTED)
		clear_secrets_tries (device);
}

static void
nm_device_ethernet_init (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	priv->s390_options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
}

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->realize_start_notify (device, plink);

	g_object_notify (G_OBJECT (device), NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS);
}

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);

	if (nm_platform_link_supports_carrier_detect (nm_device_get_platform(device), nm_device_get_ifindex (device)))
	    return NM_DEVICE_CAP_CARRIER_DETECT;
	else {
		_LOGI (LOGD_HW, "driver '%s' does not support carrier detection.",
		       nm_device_get_driver (device));
		return NM_DEVICE_CAP_NONE;
	}
}

static guint32
_subchannels_count_num (const char * const *array)
{
	int i;

	if (!array)
		return 0;
	for (i = 0; array[i]; i++)
		/* NOP */;
	return i;
}

static gboolean
match_subchans (NMDeviceEthernet *self, NMSettingWired *s_wired, gboolean *try_mac)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	const char * const *subchans;
	guint32 num1, num2;
	int i;

	*try_mac = TRUE;

	subchans = nm_setting_wired_get_s390_subchannels (s_wired);
	num1 = _subchannels_count_num (subchans);
	num2 = _subchannels_count_num ((const char * const *) priv->subchannels_dbus);
	/* connection has no subchannels */
	if (num1 == 0)
		return TRUE;
	/* connection requires subchannels but the device has none */
	if (num2 == 0)
		return FALSE;
	/* number of subchannels differ */
	if (num1 != num2)
		return FALSE;

	/* Make sure each subchannel in the connection is a subchannel of this device */
	for (i = 0; subchans[i]; i++) {
		const char *candidate = subchans[i];

		if (   (priv->subchan1 && !strcmp (priv->subchan1, candidate))
		    || (priv->subchan2 && !strcmp (priv->subchan2, candidate))
		    || (priv->subchan3 && !strcmp (priv->subchan3, candidate)))
			continue;

		return FALSE;  /* a subchannel was not found */
	}

	*try_mac = FALSE;
	return TRUE;
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMSettingWired *s_wired;

	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_wired = nm_connection_get_setting_wired (connection);

	if (nm_connection_is_type (connection, NM_SETTING_PPPOE_SETTING_NAME)) {
		/* NOP */
	} else if (nm_connection_is_type (connection, NM_SETTING_WIRED_SETTING_NAME)) {
		if (!s_wired)
			return FALSE;
	} else
		return FALSE;

	if (s_wired) {
		const char *mac, *perm_hw_addr;
		gboolean try_mac = TRUE;
		const char * const *mac_blacklist;
		int i;

		if (!match_subchans (self, s_wired, &try_mac))
			return FALSE;

		perm_hw_addr = nm_device_get_permanent_hw_address (device);
		mac = nm_setting_wired_get_mac_address (s_wired);
		if (perm_hw_addr) {
			if (try_mac && mac && !nm_utils_hwaddr_matches (mac, -1, perm_hw_addr, -1))
				return FALSE;

			/* Check for MAC address blacklist */
			mac_blacklist = nm_setting_wired_get_mac_address_blacklist (s_wired);
			for (i = 0; mac_blacklist[i]; i++) {
				if (!nm_utils_hwaddr_valid (mac_blacklist[i], ETH_ALEN)) {
					g_warn_if_reached ();
					return FALSE;
				}

				if (nm_utils_hwaddr_matches (mac_blacklist[i], -1, perm_hw_addr, -1))
					return FALSE;
			}
		} else if (mac)
			return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/
/* 802.1X */

static void
supplicant_interface_clear_handlers (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	nm_clear_g_source (&priv->supplicant_timeout_id);
	nm_clear_g_source (&priv->supplicant.con_timeout_id);
	nm_clear_g_source (&priv->supplicant.iface_con_error_cb_id);
	nm_clear_g_signal_handler (priv->supplicant.iface, &priv->supplicant.iface_error_id);
}

static void
supplicant_interface_release (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	supplicant_interface_clear_handlers (self);

	nm_clear_g_signal_handler (priv->supplicant.iface, &priv->supplicant.iface_state_id);

	if (priv->supplicant.iface) {
		nm_supplicant_interface_disconnect (priv->supplicant.iface);
		g_clear_object (&priv->supplicant.iface);
	}
}

static void
wired_secrets_cb (NMActRequest *req,
                  NMActRequestGetSecretsCallId call_id,
                  NMSettingsConnection *connection,
                  GError *error,
                  gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDevice *dev = NM_DEVICE (self);

	if (req != nm_device_get_act_request (dev))
		return;

	g_return_if_fail (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH);
	g_return_if_fail (nm_act_request_get_settings_connection (req) == connection);

	if (error) {
		_LOGW (LOGD_ETHER, "%s", error->message);
		nm_device_state_changed (dev,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else
		nm_device_activate_schedule_stage1_device_prepare (dev);
}

static gboolean
link_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *dev = NM_DEVICE (self);
	NMActRequest *req;
	NMConnection *applied_connection;
	const char *setting_name;

	priv->supplicant_timeout_id = 0;

	req = nm_device_get_act_request (dev);

	if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
		nm_device_state_changed (dev,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_SUPPLICANT_TIMEOUT);
		return FALSE;
	}

	/* Disconnect event during initial authentication and credentials
	 * ARE checked - we are likely to have wrong key.  Ask the user for
	 * another one.
	 */
	if (nm_device_get_state (dev) != NM_DEVICE_STATE_CONFIG)
		goto time_out;

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	applied_connection = nm_act_request_get_applied_connection (req);
	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (!setting_name)
		goto time_out;

	_LOGI (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: (ethernet) disconnected during authentication, asking for new key.");
	supplicant_interface_release (self);

	nm_device_state_changed (dev, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);
	nm_act_request_get_secrets (req,
	                            setting_name,
	                            NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW,
	                            NULL,
	                            wired_secrets_cb,
	                            self);

	return FALSE;

time_out:
	_LOGW (LOGD_DEVICE | LOGD_ETHER, "link timed out.");
	nm_device_state_changed (dev, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_DISCONNECT);

	return FALSE;
}

static NMSupplicantConfig *
build_supplicant_config (NMDeviceEthernet *self,
                         GError **error)
{
	const char *con_uuid;
	NMSupplicantConfig *config = NULL;
	NMSetting8021x *security;
	NMConnection *connection;
	guint32 mtu;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_assert (connection);
	con_uuid = nm_connection_get_uuid (connection);
	mtu = nm_platform_link_get_mtu (nm_device_get_platform(NM_DEVICE (self)),
	                                nm_device_get_ifindex (NM_DEVICE (self)));

	config = nm_supplicant_config_new ();

	security = nm_connection_get_setting_802_1x (connection);
	if (!nm_supplicant_config_add_setting_8021x (config, security, con_uuid, mtu, TRUE, error)) {
		g_prefix_error (error, "802-1x-setting: ");
		g_clear_object (&config);
	}

	return config;
}

static void
supplicant_iface_state_cb (NMSupplicantInterface *iface,
                           guint32 new_state,
                           guint32 old_state,
                           int disconnect_reason,
                           gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMSupplicantConfig *config;
	gboolean success = FALSE;
	NMDeviceState devstate;
	GError *error = NULL;

	if (new_state == old_state)
		return;

	_LOGI (LOGD_DEVICE | LOGD_ETHER, "supplicant interface state: %s -> %s",
	       nm_supplicant_interface_state_to_string (old_state),
	       nm_supplicant_interface_state_to_string (new_state));

	devstate = nm_device_get_state (device);

	switch (new_state) {
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		config = build_supplicant_config (self, &error);
		if (config) {
			success = nm_supplicant_interface_set_config (priv->supplicant.iface, config, &error);
			g_object_unref (config);

			if (!success) {
				_LOGE (LOGD_DEVICE | LOGD_ETHER,
				       "Activation: (ethernet) couldn't send security configuration to the supplicant: %s",
				       error->message);
				g_clear_error (&error);
			}
		} else {
			_LOGE (LOGD_DEVICE | LOGD_ETHER,
			       "Activation: (ethernet) couldn't build security configuration: %s",
			       error->message);
			g_clear_error (&error);
		}

		if (!success) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		supplicant_interface_clear_handlers (self);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (devstate == NM_DEVICE_STATE_CONFIG) {
			_LOGI (LOGD_DEVICE | LOGD_ETHER,
			       "Activation: (ethernet) Stage 2 of 5 (Device Configure) successful.");
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			/* Start the link timeout so we allow some time for reauthentication */
			if (!priv->supplicant_timeout_id)
				priv->supplicant_timeout_id = g_timeout_add_seconds (15, link_timeout_cb, device);
		}
		break;
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		supplicant_interface_release (self);

		if ((devstate == NM_DEVICE_STATE_ACTIVATED) || nm_device_is_activating (device)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_SUPPLICANT_FAILED);
		}
		break;
	default:
		break;
	}
}

static gboolean
supplicant_iface_connection_error_cb_handler (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	supplicant_interface_release (self);
	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_SUPPLICANT_CONFIG_FAILED);

	priv->supplicant.iface_con_error_cb_id = 0;
	return FALSE;
}

static void
supplicant_iface_connection_error_cb (NMSupplicantInterface *iface,
                                      const char *name,
                                      const char *message,
                                      gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	guint id;

	_LOGW (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: (ethernet) association request to the supplicant failed: %s - %s",
	       name, message);

	if (priv->supplicant.iface_con_error_cb_id)
		g_source_remove (priv->supplicant.iface_con_error_cb_id);

	id = g_idle_add (supplicant_iface_connection_error_cb_handler, self);
	priv->supplicant.iface_con_error_cb_id = id;
}

static NMActStageReturn
handle_auth_or_fail (NMDeviceEthernet *self,
                     NMActRequest *req,
                     gboolean new_secrets)
{
	const char *setting_name;
	guint32 tries;
	NMConnection *applied_connection;

	applied_connection = nm_act_request_get_applied_connection (req);

	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (applied_connection), WIRED_SECRETS_TRIES));
	if (tries > 3)
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (req));

	setting_name = nm_connection_need_secrets (applied_connection, NULL);
	if (setting_name) {
		NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

		if (new_secrets)
			flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
		nm_act_request_get_secrets (req, setting_name, flags, NULL, wired_secrets_cb, self);

		g_object_set_data (G_OBJECT (applied_connection), WIRED_SECRETS_TRIES, GUINT_TO_POINTER (++tries));
	} else
		_LOGI (LOGD_DEVICE, "Cleared secrets, but setting didn't need any secrets.");

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static gboolean
supplicant_connection_timeout_cb (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self);
	NMActRequest *req;
	NMSettingsConnection *connection;
	guint64 timestamp = 0;
	gboolean new_secrets = TRUE;

	priv->supplicant.con_timeout_id = 0;

	/* Authentication failed; either driver problems, the encryption key is
	 * wrong, the passwords or certificates were wrong or the Ethernet switch's
	 * port is not configured for 802.1x. */
	_LOGW (LOGD_DEVICE | LOGD_ETHER,
	       "Activation: (ethernet) association took too long.");

	supplicant_interface_release (self);
	req = nm_device_get_act_request (device);
	g_assert (req);

	connection = nm_act_request_get_settings_connection (req);
	g_assert (connection);

	/* Ask for new secrets only if we've never activated this connection
	 * before.  If we've connected before, don't bother the user with dialogs,
	 * just retry or fail, and if we never connect the user can fix the
	 * password somewhere else. */
	if (nm_settings_connection_get_timestamp (connection, &timestamp))
		new_secrets = !timestamp;

	if (handle_auth_or_fail (self, req, new_secrets) == NM_ACT_STAGE_RETURN_POSTPONE)
		_LOGW (LOGD_DEVICE | LOGD_ETHER, "Activation: (ethernet) asking for new secrets");
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);

	return FALSE;
}

static gboolean
supplicant_interface_init (NMDeviceEthernet *self)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	supplicant_interface_release (self);

	priv->supplicant.iface = nm_supplicant_manager_create_interface (priv->supplicant.mgr,
	                                                                 nm_device_get_iface (NM_DEVICE (self)),
	                                                                 FALSE);

	if (!priv->supplicant.iface) {
		_LOGE (LOGD_DEVICE | LOGD_ETHER,
		       "Couldn't initialize supplicant interface");
		return FALSE;
	}

	/* Listen for it's state signals */
	priv->supplicant.iface_state_id = g_signal_connect (priv->supplicant.iface,
	                                                    NM_SUPPLICANT_INTERFACE_STATE,
	                                                    G_CALLBACK (supplicant_iface_state_cb),
	                                                    self);

	/* Hook up error signal handler to capture association errors */
	priv->supplicant.iface_error_id = g_signal_connect (priv->supplicant.iface,
	                                                    "connection-error",
	                                                    G_CALLBACK (supplicant_iface_connection_error_cb),
	                                                    self);

	/* Set up a timeout on the connection attempt to fail it after 25 seconds */
	priv->supplicant.con_timeout_id = g_timeout_add_seconds (25, supplicant_connection_timeout_cb, self);

	return TRUE;
}

static gboolean
pppoe_reconnect_delay (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	priv->pppoe_wait_id = 0;
	_LOGI (LOGD_DEVICE, "PPPoE reconnect delay complete, resuming connection...");
	nm_device_activate_schedule_stage2_device_config (NM_DEVICE (self));
	return FALSE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (dev);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingWired *s_wired;
	const char *cloned_mac;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage1_prepare (dev, reason);
	if (ret == NM_ACT_STAGE_RETURN_SUCCESS) {
		s_wired = (NMSettingWired *) nm_device_get_applied_setting (dev, NM_TYPE_SETTING_WIRED);
		if (s_wired) {
			/* Set device MAC address if the connection wants to change it */
			cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
			nm_device_set_hw_addr (dev, cloned_mac, "set", LOGD_ETHER);
		}

		/* If we're re-activating a PPPoE connection a short while after
		 * a previous PPPoE connection was torn down, wait a bit to allow the
		 * remote side to handle the disconnection.  Otherwise the peer may
		 * get confused and fail to negotiate the new connection. (rh #1023503)
		 */
		if (priv->last_pppoe_time) {
			gint32 delay = nm_utils_get_monotonic_timestamp_s () - priv->last_pppoe_time;

			if (   delay < PPPOE_RECONNECT_DELAY
			    && nm_device_get_applied_setting (dev, NM_TYPE_SETTING_PPPOE)) {
				_LOGI (LOGD_DEVICE, "delaying PPPoE reconnect for %d seconds to ensure peer is ready...",
				       delay);
				g_assert (!priv->pppoe_wait_id);
				priv->pppoe_wait_id = g_timeout_add_seconds (delay,
				                                             pppoe_reconnect_delay,
				                                             self);
				ret = NM_ACT_STAGE_RETURN_POSTPONE;
			} else
				priv->last_pppoe_time = 0;
		}
	}

	return ret;
}

static NMActStageReturn
nm_8021x_stage2_config (NMDeviceEthernet *self, NMDeviceStateReason *reason)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMConnection *connection;
	NMSetting8021x *security;
	const char *setting_name;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	connection = nm_device_get_applied_connection (NM_DEVICE (self));
	g_assert (connection);
	security = nm_connection_get_setting_802_1x (connection);
	if (!security) {
		_LOGE (LOGD_DEVICE, "Invalid or missing 802.1X security");
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return ret;
	}

	if (!priv->supplicant.mgr)
		priv->supplicant.mgr = g_object_ref (nm_supplicant_manager_get ());

	/* If we need secrets, get them */
	setting_name = nm_connection_need_secrets (connection, NULL);
	if (setting_name) {
		NMActRequest *req = nm_device_get_act_request (NM_DEVICE (self));

		_LOGI (LOGD_DEVICE | LOGD_ETHER,
		       "Activation: (ethernet) connection '%s' has security, but secrets are required.",
		       nm_connection_get_id (connection));

		ret = handle_auth_or_fail (self, req, FALSE);
		if (ret != NM_ACT_STAGE_RETURN_POSTPONE)
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
	} else {
		_LOGI (LOGD_DEVICE | LOGD_ETHER,
		       "Activation: (ethernet) connection '%s' requires no security. No secrets needed.",
		       nm_connection_get_id (connection));

		if (supplicant_interface_init (self))
			ret = NM_ACT_STAGE_RETURN_POSTPONE;
		else
			*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
	}

	return ret;
}

/*****************************************************************************/
/* PPPoE */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
                const char *iface,
                NMIP4Config *config,
                gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	/* Ignore PPP IP4 events that come in after initial configuration */
	if (nm_device_activate_ip4_state_in_conf (device)) {
		nm_device_set_ip_iface (device, iface);
		nm_device_activate_schedule_ip4_config_result (device, config);
	}
}

static NMActStageReturn
pppoe_stage3_ip4_config_start (NMDeviceEthernet *self, NMDeviceStateReason *reason)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingPppoe *s_pppoe;
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_FAILURE;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	s_pppoe = (NMSettingPppoe *) nm_device_get_applied_setting (self, NM_TYPE_SETTING_PPPOE);
	g_assert (s_pppoe);

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (NM_DEVICE (self)));
	if (nm_ppp_manager_start (priv->ppp_manager, req, nm_setting_pppoe_get_username (s_pppoe), 30, &err)) {
		g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_STATE_CHANGED,
		                  G_CALLBACK (ppp_state_changed),
		                  self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
		                  G_CALLBACK (ppp_ip4_config),
		                  self);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		_LOGW (LOGD_DEVICE, "PPPoE failed to start: %s", err->message);
		g_error_free (err);

		nm_exported_object_clear_and_unexport (&priv->ppp_manager);

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
	}

	return ret;
}

/****************************************************************/

static void
dcb_timeout_cleanup (NMDevice *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

	nm_clear_g_source (&priv->dcb_timeout_id);
}

static void
dcb_carrier_cleanup (NMDevice *device)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

	nm_clear_g_signal_handler (device, &priv->dcb_carrier_id);
}

static void dcb_state (NMDevice *device, gboolean timeout);

static gboolean
dcb_carrier_timeout (gpointer user_data)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (user_data);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (user_data);

	g_return_val_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG, G_SOURCE_REMOVE);

	priv->dcb_timeout_id = 0;
	if (priv->dcb_wait != DCB_WAIT_CARRIER_POSTCONFIG_DOWN) {
		_LOGW (LOGD_DCB, "DCB: timed out waiting for carrier (step %d)",
		       priv->dcb_wait);
	}
	dcb_state (device, TRUE);
	return G_SOURCE_REMOVE;
}

static gboolean
dcb_configure (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	NMSettingDcb *s_dcb;
	GError *error = NULL;

	dcb_timeout_cleanup (device);

	s_dcb = (NMSettingDcb *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);
	g_assert (s_dcb);
	if (!nm_dcb_setup (nm_device_get_iface (device), s_dcb, &error)) {
		_LOGW (LOGD_DCB, "Activation: (ethernet) failed to enable DCB/FCoE: %s",
		       error->message);
		g_clear_error (&error);
		return FALSE;
	}

	/* Pause again just in case the device takes the carrier down when
	 * setting specific DCB attributes.
	 */
	_LOGD (LOGD_DCB, "waiting for carrier (postconfig down)");
	priv->dcb_wait = DCB_WAIT_CARRIER_POSTCONFIG_DOWN;
	priv->dcb_timeout_id = g_timeout_add_seconds (3, dcb_carrier_timeout, device);
	return TRUE;
}

static gboolean
dcb_enable (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	GError *error = NULL;

	dcb_timeout_cleanup (device);
	if (!nm_dcb_enable (nm_device_get_iface (device), TRUE, &error)) {
		_LOGW (LOGD_DCB, "Activation: (ethernet) failed to enable DCB/FCoE: %s",
		       error->message);
		g_clear_error (&error);
		return FALSE;
	}

	/* Pause for 3 seconds after enabling DCB to let the card reconfigure
	 * itself.  Drivers will often re-initialize internal settings which
	 * takes the carrier down for 2 or more seconds.  During this time,
	 * lldpad will refuse to do anything else with the card since the carrier
	 * is down.  But NM might get the carrier-down signal long after calling
	 * "dcbtool dcb on", so we have to first wait for the carrier to go down.
	 */
	_LOGD (LOGD_DCB, "waiting for carrier (preconfig down)");
	priv->dcb_wait = DCB_WAIT_CARRIER_PRECONFIG_DOWN;
	priv->dcb_timeout_id = g_timeout_add_seconds (3, dcb_carrier_timeout, device);
	return TRUE;
}

static void
dcb_state (NMDevice *device, gboolean timeout)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	gboolean carrier;

	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);


	carrier = nm_platform_link_is_connected (nm_device_get_platform (device), nm_device_get_ifindex (device));
	_LOGD (LOGD_DCB, "dcb_state() wait %d carrier %d timeout %d", priv->dcb_wait, carrier, timeout);

	switch (priv->dcb_wait) {
	case DCB_WAIT_CARRIER_PREENABLE_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() enabling DCB");
			dcb_timeout_cleanup (device);
			if (!dcb_enable (device)) {
				dcb_carrier_cleanup (device);
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED);
			}
		}
		break;
	case DCB_WAIT_CARRIER_PRECONFIG_DOWN:
		dcb_timeout_cleanup (device);
		priv->dcb_wait = DCB_WAIT_CARRIER_PRECONFIG_UP;

		if (!carrier) {
			/* Wait for the carrier to come back up */
			_LOGD (LOGD_DCB, "waiting for carrier (preconfig up)");
			priv->dcb_timeout_id = g_timeout_add_seconds (5, dcb_carrier_timeout, device);
			break;
		}
		_LOGD (LOGD_DCB, "dcb_state() preconfig down falling through");
		/* carrier never went down? fall through */
	case DCB_WAIT_CARRIER_PRECONFIG_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() preconfig up configuring DCB");
			dcb_timeout_cleanup (device);
			if (!dcb_configure (device)) {
				dcb_carrier_cleanup (device);
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_FAILED,
				                         NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED);
			}
		}
		break;
	case DCB_WAIT_CARRIER_POSTCONFIG_DOWN:
		dcb_timeout_cleanup (device);
		priv->dcb_wait = DCB_WAIT_CARRIER_POSTCONFIG_UP;

		if (!carrier) {
			/* Wait for the carrier to come back up */
			_LOGD (LOGD_DCB, "waiting for carrier (postconfig up)");
			priv->dcb_timeout_id = g_timeout_add_seconds (5, dcb_carrier_timeout, device);
			break;
		}
		_LOGD (LOGD_DCB, "dcb_state() postconfig down falling through");
		/* carrier never went down? fall through */
	case DCB_WAIT_CARRIER_POSTCONFIG_UP:
		if (timeout || carrier) {
			_LOGD (LOGD_DCB, "dcb_state() postconfig up starting IP");
			dcb_timeout_cleanup (device);
			dcb_carrier_cleanup (device);
			priv->dcb_wait = DCB_WAIT_UNKNOWN;
			nm_device_activate_schedule_stage3_ip_config_start (device);
		}
		break;
	default:
		g_assert_not_reached ();
	}
}

static void
dcb_carrier_changed (NMDevice *device, GParamSpec *pspec, gpointer unused)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_CONFIG);

	if (priv->dcb_timeout_id) {
		_LOGD (LOGD_DCB, "carrier_changed() calling dcb_state()");
		dcb_state (device, FALSE);
	}
}

/****************************************************************/

static gboolean
wake_on_lan_enable (NMDevice *device)
{
	NMSettingWiredWakeOnLan wol;
	NMSettingWired *s_wired;
	const char *password = NULL;
	gs_free char *value = NULL;

	s_wired = (NMSettingWired *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRED);
	if (s_wired) {
		wol = nm_setting_wired_get_wake_on_lan (s_wired);
		password = nm_setting_wired_get_wake_on_lan_password (s_wired);
		if (wol != NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)
			goto found;
	}

	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "ethernet.wake-on-lan",
	                                               device);

	if (value) {
		wol = _nm_utils_ascii_str_to_int64 (value, 10,
		                                    NM_SETTING_WIRED_WAKE_ON_LAN_NONE,
		                                    G_MAXINT32,
		                                    NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT);

		if (   NM_FLAGS_ANY (wol, NM_SETTING_WIRED_WAKE_ON_LAN_EXCLUSIVE_FLAGS)
		    && !nm_utils_is_power_of_two (wol)) {
			nm_log_dbg (LOGD_ETHER, "invalid default value %u for wake-on-lan", (guint) wol);
			wol = NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT;
		}
		if (wol != NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)
			goto found;
	}
	wol = NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE;
found:
	return nm_platform_ethtool_set_wake_on_lan (NM_PLATFORM_GET, nm_device_get_iface (device), wol, password);
}

/****************************************************************/

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *connection_type;
	NMActStageReturn ret = NM_ACT_STAGE_RETURN_SUCCESS;
	NMSettingDcb *s_dcb;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_con = NM_SETTING_CONNECTION (nm_device_get_applied_setting (device,
	                                                              NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	dcb_timeout_cleanup (device);
	dcb_carrier_cleanup (device);

	/* 802.1x has to run before any IP configuration since the 802.1x auth
	 * process opens the port up for normal traffic.
	 */
	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (connection_type, NM_SETTING_WIRED_SETTING_NAME)) {
		NMSetting8021x *security;

		security = (NMSetting8021x *) nm_device_get_applied_setting (device,
		                                                             NM_TYPE_SETTING_802_1X);
		if (security) {
			/* FIXME: for now 802.1x is mutually exclusive with DCB */
			return nm_8021x_stage2_config (self, reason);
		}
	}

	wake_on_lan_enable (device);

	/* DCB and FCoE setup */
	s_dcb = (NMSettingDcb *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);
	if (s_dcb) {
		/* lldpad really really wants the carrier to be up */
		if (nm_platform_link_is_connected (nm_device_get_platform (device), nm_device_get_ifindex (device))) {
			if (!dcb_enable (device)) {
				*reason = NM_DEVICE_STATE_REASON_DCB_FCOE_FAILED;
				return NM_ACT_STAGE_RETURN_FAILURE;
			}
		} else {
			_LOGD (LOGD_DCB, "waiting for carrier (preenable up)");
			priv->dcb_wait = DCB_WAIT_CARRIER_PREENABLE_UP;
			priv->dcb_timeout_id = g_timeout_add_seconds (4, dcb_carrier_timeout, device);
		}

		/* Watch carrier independently of NMDeviceClass::carrier_changed so
		 * we get instant notifications of disconnection that aren't deferred.
		 */
		priv->dcb_carrier_id = g_signal_connect (device,
		                                         "notify::" NM_DEVICE_CARRIER,
		                                         G_CALLBACK (dcb_carrier_changed),
		                                         NULL);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	}

	/* PPPoE setup */
	if (nm_connection_is_type (nm_device_get_applied_connection (device),
	                           NM_SETTING_PPPOE_SETTING_NAME)) {
		NMSettingPpp *s_ppp;

		s_ppp = (NMSettingPpp *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_PPP);
		if (s_ppp) {
			guint32 mtu = 0, mru = 0, mxu;

			mtu = nm_setting_ppp_get_mtu (s_ppp);
			mru = nm_setting_ppp_get_mru (s_ppp);
			mxu = mru > mtu ? mru : mtu;
			if (mxu) {
				_LOGD (LOGD_PPP, "set MTU to %u (PPP interface MRU %u, MTU %u)",
				       mxu + PPPOE_ENCAP_OVERHEAD, mru, mtu);
				nm_platform_link_set_mtu (nm_device_get_platform (device),
				                          nm_device_get_ifindex (device),
				                          mxu + PPPOE_ENCAP_OVERHEAD);
			}
		}
	}

	return ret;
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	NMSettingConnection *s_con;
	const char *connection_type;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	s_con = NM_SETTING_CONNECTION (nm_device_get_applied_setting (device, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	connection_type = nm_setting_connection_get_connection_type (s_con);
	if (!strcmp (connection_type, NM_SETTING_PPPOE_SETTING_NAME))
		return pppoe_stage3_ip4_config_start (NM_DEVICE_ETHERNET (device), reason);

	return NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->act_stage3_ip4_config_start (device, out_config, reason);
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	guint32 mtu;

	/* MTU only set for plain ethernet */
	if (NM_DEVICE_ETHERNET_GET_PRIVATE (device)->ppp_manager)
		return;

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);
	s_wired = nm_connection_get_setting_wired (connection);
	g_assert (s_wired);

	/* MTU override */
	mtu = nm_setting_wired_get_mtu (s_wired);
	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
}

static void
deactivate (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	NMSettingDcb *s_dcb;
	GError *error = NULL;

	/* Clear wired secrets tries when deactivating */
	clear_secrets_tries (device);

	nm_clear_g_source (&priv->pppoe_wait_id);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	nm_exported_object_clear_and_unexport (&priv->ppp_manager);

	supplicant_interface_release (self);

	priv->dcb_wait = DCB_WAIT_UNKNOWN;
	dcb_timeout_cleanup (device);
	dcb_carrier_cleanup (device);

	/* Tear down DCB/FCoE if it was enabled */
	s_dcb = (NMSettingDcb *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_DCB);
	if (s_dcb) {
		if (!nm_dcb_cleanup (nm_device_get_iface (device), &error)) {
			_LOGW (LOGD_DEVICE | LOGD_HW, "failed to disable DCB/FCoE: %s",
			       error->message);
			g_clear_error (&error);
		}
	}

	/* Set last PPPoE connection time */
	if (nm_device_get_applied_setting (device, NM_TYPE_SETTING_PPPOE))
		NM_DEVICE_ETHERNET_GET_PRIVATE (device)->last_pppoe_time = nm_utils_get_monotonic_timestamp_s ();

	/* Reset MAC address back to initial address */
	if (nm_device_get_initial_hw_address (device))
		nm_device_set_hw_addr (device, nm_device_get_initial_hw_address (device), "reset", LOGD_ETHER);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingWired *s_wired;
	NMSettingPppoe *s_pppoe;
	const char *setting_mac;
	const char *perm_hw_addr;

	s_pppoe = nm_connection_get_setting_pppoe (connection);

	/* We can't telepathically figure out the service name or username, so if
	 * those weren't given, we can't complete the connection.
	 */
	if (s_pppoe && !nm_setting_verify (NM_SETTING (s_pppoe), NULL, error))
		return FALSE;

	/* Default to an ethernet-only connection, but if a PPPoE setting was given
	 * then PPPoE should be our connection type.
	 */
	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           s_pppoe ? NM_SETTING_PPPOE_SETTING_NAME : NM_SETTING_WIRED_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           s_pppoe ? _("PPPoE connection") : _("Wired connection"),
	                           NULL,
	                           s_pppoe ? FALSE : TRUE); /* No IPv6 by default yet for PPPoE */

	s_wired = nm_connection_get_setting_wired (connection);
	if (!s_wired) {
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_wired));
	}

	perm_hw_addr = nm_device_get_permanent_hw_address (device);
	if (perm_hw_addr) {
		setting_mac = nm_setting_wired_get_mac_address (s_wired);
		if (setting_mac) {
			/* Make sure the setting MAC (if any) matches the device's permanent MAC */
			if (!nm_utils_hwaddr_matches (setting_mac, -1, perm_hw_addr, -1)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("connection does not match device"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
				return FALSE;
			}
		} else {
			g_object_set (G_OBJECT (s_wired),
			              NM_SETTING_WIRED_MAC_ADDRESS, perm_hw_addr,
			              NULL);
		}
	}

	return TRUE;
}

static NMConnection *
new_default_connection (NMDevice *self)
{
	NMConnection *connection;
	const GSList *connections;
	NMSetting *setting;
	const char *hw_address;
	char *defname, *uuid;

	if (nm_config_get_no_auto_default_for_device (nm_config_get (), self))
		return NULL;

	hw_address = nm_device_get_hw_address (self);
	if (!hw_address)
		return NULL;

	connection = nm_simple_connection_new ();
	setting = nm_setting_connection_new ();
	nm_connection_add_setting (connection, setting);

	connections = nm_connection_provider_get_connections (nm_connection_provider_get ());
	defname = nm_device_ethernet_utils_get_default_wired_name (connections);
	uuid = nm_utils_uuid_generate ();
	g_object_set (setting,
	              NM_SETTING_CONNECTION_ID, defname,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
	              NULL);
	g_free (uuid);
	g_free (defname);

	/* Lock the connection to the device */
	setting = nm_setting_wired_new ();
	g_object_set (setting, NM_SETTING_WIRED_MAC_ADDRESS, hw_address, NULL);
	nm_connection_add_setting (connection, setting);

	return connection;
}

static NMMatchSpecMatchType
spec_match_list (NMDevice *device, const GSList *specs)
{
	NMMatchSpecMatchType matched = NM_MATCH_SPEC_NO_MATCH, m;
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);

	if (priv->subchannels)
		matched = nm_match_spec_s390_subchannels (specs, priv->subchannels);
	if (matched != NM_MATCH_SPEC_NEG_MATCH) {
		m = NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->spec_match_list (device, specs);
		matched = MAX (matched, m);
	}
	return matched;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (device);
	NMSettingWired *s_wired = nm_connection_get_setting_wired (connection);
	const char *perm_hw_addr = nm_device_get_permanent_hw_address (device);
	const char *mac = nm_device_get_hw_address (device);
	const char *mac_prop = NM_SETTING_WIRED_MAC_ADDRESS;
	GHashTableIter iter;
	gpointer key, value;

	if (!s_wired) {
		s_wired = (NMSettingWired *) nm_setting_wired_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_wired);
	}

	g_object_set (nm_connection_get_setting_connection (connection),
	              NM_SETTING_CONNECTION_TYPE, nm_connection_get_setting_pppoe (connection)
	                                          ? NM_SETTING_PPPOE_SETTING_NAME
	                                          : NM_SETTING_WIRED_SETTING_NAME, NULL);

	/* If the device reports a permanent address, use that for the MAC address
	 * and the current MAC, if different, is the cloned MAC.
	 */
	if (perm_hw_addr) {
		g_object_set (s_wired, NM_SETTING_WIRED_MAC_ADDRESS, perm_hw_addr, NULL);

		mac_prop = NULL;
		if (mac && !nm_utils_hwaddr_matches (perm_hw_addr, -1, mac, -1))
			mac_prop = NM_SETTING_WIRED_CLONED_MAC_ADDRESS;
	}

	if (mac_prop && mac && nm_utils_hwaddr_valid (mac, ETH_ALEN))
		g_object_set (s_wired, mac_prop, mac, NULL);

	/* We don't set the MTU as we don't know whether it was set explicitly */

	/* s390 */
	if (priv->subchannels_dbus)
		g_object_set (s_wired, NM_SETTING_WIRED_S390_SUBCHANNELS, priv->subchannels_dbus, NULL);
	if (priv->s390_nettype)
		g_object_set (s_wired, NM_SETTING_WIRED_S390_NETTYPE, priv->s390_nettype, NULL);
	g_hash_table_iter_init (&iter, priv->s390_options);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		nm_setting_wired_add_s390_option (s_wired, (const char *) key, (const char *) value);
	}

}

static void
get_link_speed (NMDevice *device)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	guint32 speed;

	if (!nm_platform_ethtool_get_link_speed (NM_PLATFORM_GET, nm_device_get_iface (device), &speed))
		return;
	if (priv->speed == speed)
		return;

	priv->speed = speed;
	g_object_notify (G_OBJECT (device), "speed");

	_LOGD (LOGD_HW | LOGD_ETHER, "speed is now %d Mb/s", speed);
}

static void
carrier_changed (NMDevice *device, gboolean carrier)
{
	if (carrier)
		get_link_speed (device);

	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->carrier_changed (device, carrier);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (device);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);
	static const guint8 zero_hwaddr[ETH_ALEN];
	const guint8 *hwaddr;
	gsize hwaddrlen = 0;

	NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->link_changed (device, info);
	if (!priv->subchan1 && info->initialized)
		_update_s390_subchannels (self);

	if (!nm_device_get_initial_hw_address (device)) {
		hwaddr = nm_platform_link_get_address (nm_device_get_platform (device),
		                                       nm_device_get_ifindex (self),
		                                       &hwaddrlen);
		if (!nm_utils_hwaddr_matches (hwaddr, hwaddrlen, zero_hwaddr, ETH_ALEN)) {
			_LOGD (LOGD_DEVICE, "device got a valid hw address");
			nm_device_update_hw_address (self);
			nm_device_update_initial_hw_address (self);
			if (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE) {
				/*
				 * If the device is UNAVAILABLE, any previous try to
				 * bring it up probably has failed because of the
				 * invalid hardware address; try again.
				 */
				nm_device_bring_up (self, TRUE, NULL);
				nm_device_queue_recheck_available (device,
				                                   NM_DEVICE_STATE_REASON_NONE,
				                                   NM_DEVICE_STATE_REASON_NONE);
			}
		}
	}
}

static gboolean
is_available (NMDevice *device, NMDeviceCheckDevAvailableFlags flags)
{
	if (!NM_DEVICE_CLASS (nm_device_ethernet_parent_class)->is_available (device, flags))
		return FALSE;

	return !!nm_device_get_initial_hw_address (device);
}

static void
dispose (GObject *object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	supplicant_interface_release (self);

	nm_clear_g_source (&priv->pppoe_wait_id);

	dcb_timeout_cleanup (NM_DEVICE (self));
	dcb_carrier_cleanup (NM_DEVICE (self));

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	g_clear_object (&priv->supplicant.mgr);
	g_free (priv->subchan1);
	g_free (priv->subchan2);
	g_free (priv->subchan3);
	g_free (priv->subchannels);
	g_strfreev (priv->subchannels_dbus);
	g_free (priv->s390_nettype);
	g_hash_table_destroy (priv->s390_options);

	G_OBJECT_CLASS (nm_device_ethernet_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceEthernet *self = NM_DEVICE_ETHERNET (object);
	NMDeviceEthernetPrivate *priv = NM_DEVICE_ETHERNET_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PERM_HW_ADDRESS:
		g_value_set_string (value, nm_device_get_permanent_hw_address (NM_DEVICE (object)));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, priv->speed);
		break;
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, priv->subchannels_dbus);
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
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ethernet_class_init (NMDeviceEthernetClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceEthernetPrivate));

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_WIRED_SETTING_NAME, NM_LINK_TYPE_ETHERNET)

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->realize_start_notify = realize_start_notify;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;
	parent_class->new_default_connection = new_default_connection;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->act_stage2_config = act_stage2_config;
	parent_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;
	parent_class->deactivate = deactivate;
	parent_class->spec_match_list = spec_match_list;
	parent_class->update_connection = update_connection;
	parent_class->carrier_changed = carrier_changed;
	parent_class->link_changed = link_changed;
	parent_class->is_available = is_available;

	parent_class->state_changed = device_state_changed;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PERM_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_ETHERNET_PERMANENT_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_DEVICE_ETHERNET_SPEED, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_S390_SUBCHANNELS,
		 g_param_spec_boxed (NM_DEVICE_ETHERNET_S390_SUBCHANNELS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_ETHERNET_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_ETHERNET_FACTORY (nm_ethernet_factory_get_type ())
#define NM_ETHERNET_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ETHERNET_FACTORY, NMEthernetFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_ETHERNET,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Ethernet",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ETHERNET,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_ETHERNET,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (ETHERNET, Ethernet, ethernet,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_ETHERNET)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_PPPOE_SETTING_NAME),
	factory_iface->create_device = create_device;
	)

