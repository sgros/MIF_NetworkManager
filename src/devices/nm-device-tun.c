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
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "nm-activation-request.h"
#include "nm-device-tun.h"
#include "nm-device-private.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-setting-tun.h"
#include "nm-core-internal.h"

#include "nmdbus-device-tun.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceTun);

G_DEFINE_TYPE (NMDeviceTun, nm_device_tun, NM_TYPE_DEVICE)

#define NM_DEVICE_TUN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_TUN, NMDeviceTunPrivate))

typedef struct {
	NMPlatformTunProperties props;
	const char *mode;
} NMDeviceTunPrivate;

enum {
	PROP_0,
	PROP_OWNER,
	PROP_GROUP,
	PROP_MODE,
	PROP_NO_PI,
	PROP_VNET_HDR,
	PROP_MULTI_QUEUE,

	LAST_PROP
};

static void
reload_tun_properties (NMDeviceTun *self)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	GObject *object = G_OBJECT (self);
	NMPlatformTunProperties props;
	int ifindex;

	ifindex = nm_device_get_ifindex (NM_DEVICE (self));
	if (ifindex > 0) {
		if (!nm_platform_link_tun_get_properties (nm_device_get_platform(NM_DEVICE(self)), ifindex, &props)) {
			_LOGD (LOGD_DEVICE, "tun-properties: cannot loading tun properties from platform for ifindex %d", ifindex);
			ifindex = 0;
		} else if (g_strcmp0 (priv->mode, props.mode) != 0) {
			/* if the mode differs, we ignore what we loaded. A NMDeviceTun cannot
			 * change the mode after construction. */
			_LOGD (LOGD_DEVICE, "tun-properties: loading tun properties yielded tun-mode %s%s%s, but %s%s%s expected (ifindex %d)",
			       NM_PRINT_FMT_QUOTE_STRING (props.mode),
			       NM_PRINT_FMT_QUOTE_STRING (priv->mode),
			       ifindex);
			ifindex = 0;
		}
	} else
		_LOGD (LOGD_DEVICE, "tun-properties: ignore loading properties due to missing ifindex");
	if (ifindex <= 0)
		memset (&props, 0, sizeof (props));

	g_object_freeze_notify (object);

	if (priv->props.owner != props.owner)
		g_object_notify (object, NM_DEVICE_TUN_OWNER);
	if (priv->props.group != props.group)
		g_object_notify (object, NM_DEVICE_TUN_GROUP);
	if (priv->props.no_pi != props.no_pi)
		g_object_notify (object, NM_DEVICE_TUN_NO_PI);
	if (priv->props.vnet_hdr != props.vnet_hdr)
		g_object_notify (object, NM_DEVICE_TUN_VNET_HDR);
	if (priv->props.multi_queue != props.multi_queue)
		g_object_notify (object, NM_DEVICE_TUN_MULTI_QUEUE);

	memcpy (&priv->props, &props, sizeof (NMPlatformTunProperties));

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_tun_parent_class)->link_changed (device, info);

	reload_tun_properties (NM_DEVICE_TUN (device));
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingTun *s_tun;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_TUN_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("TUN connection"),
	                           NULL,
	                           TRUE);

	s_tun = nm_connection_get_setting_tun (connection);
	if (!s_tun) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     "A 'tun' setting is required.");
		return FALSE;
	}

	return TRUE;
}

static int
tun_mode_from_string (const char *string)
{
	if (!g_strcmp0 (string, "tap"))
		return NM_SETTING_TUN_MODE_TAP;
	else
		return NM_SETTING_TUN_MODE_TUN;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMSettingTun *s_tun = nm_connection_get_setting_tun (connection);
	NMPlatformTunProperties props;
	NMSettingTunMode mode;
	gint64 user, group;
	char *str;

	if (!s_tun) {
		s_tun = (NMSettingTun *) nm_setting_tun_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_tun);
	}

	if (!nm_platform_link_tun_get_properties (nm_device_get_platform(device), nm_device_get_ifindex (device), &props)) {
		_LOGW (LOGD_HW, "failed to get TUN interface info while updating connection.");
		return;
	}

	mode = tun_mode_from_string (props.mode);

	if (mode != nm_setting_tun_get_mode (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_MODE, mode, NULL);

	user = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_owner (s_tun), 10, 0, G_MAXINT32, -1);
	group = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_group (s_tun), 10, 0, G_MAXINT32, -1);

	if (props.owner != user) {
		str = props.owner >= 0 ? g_strdup_printf ("%" G_GINT32_FORMAT, (gint32) props.owner) : NULL;
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_OWNER, str, NULL);
		g_free (str);
	}

	if (props.group != group) {
		str = props.group >= 0 ? g_strdup_printf ("%" G_GINT32_FORMAT, (gint32) props.group) : NULL;
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_GROUP, str, NULL);
		g_free (str);
	}

	if ((!props.no_pi) != nm_setting_tun_get_pi (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_PI, !props.no_pi, NULL);
	if (props.vnet_hdr != nm_setting_tun_get_vnet_hdr (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_VNET_HDR, props.vnet_hdr, NULL);
	if (props.multi_queue != nm_setting_tun_get_multi_queue (s_tun))
		g_object_set (G_OBJECT (s_tun), NM_SETTING_TUN_MULTI_QUEUE, props.multi_queue, NULL);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	const char *iface = nm_device_get_iface (device);
	NMPlatformError plerr;
	NMSettingTun *s_tun;
	gint64 user, group;

	s_tun = nm_connection_get_setting_tun (connection);
	g_assert (s_tun);

	user = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_owner (s_tun), 10, 0, G_MAXINT32, -1);
	group = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_group (s_tun), 10, 0, G_MAXINT32, -1);

	plerr = nm_platform_link_tun_add (nm_device_get_platform (device), iface,
	                                  nm_setting_tun_get_mode (s_tun) == NM_SETTING_TUN_MODE_TAP,
	                                  user, group,
	                                  nm_setting_tun_get_pi (s_tun),
	                                  nm_setting_tun_get_vnet_hdr (s_tun),
	                                  nm_setting_tun_get_multi_queue (s_tun),
	                                  out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create TUN/TAP interface '%s' for '%s': %s",
		             iface,
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	return TRUE;
}

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NM_DEVICE_CLASS (nm_device_tun_parent_class)->realize_start_notify (device, plink);
	reload_tun_properties (device);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	NMSettingTunMode mode;
	NMSettingTun *s_tun;
	gint64 user, group;

	if (!NM_DEVICE_CLASS (nm_device_tun_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	s_tun = nm_connection_get_setting_tun (connection);
	if (!s_tun)
		return FALSE;

	if (nm_device_is_real (device)) {
		mode = tun_mode_from_string (priv->mode);
		if (mode != nm_setting_tun_get_mode (s_tun))
			return FALSE;

		user = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_owner (s_tun), 10, 0, G_MAXINT32, -1);
		group = _nm_utils_ascii_str_to_int64 (nm_setting_tun_get_group (s_tun), 10, 0, G_MAXINT32, -1);

		if (user != priv->props.owner)
			return FALSE;
		if (group != priv->props.group)
			return FALSE;
		if (nm_setting_tun_get_pi (s_tun) == priv->props.no_pi)
			return FALSE;
		if (nm_setting_tun_get_vnet_hdr (s_tun) != priv->props.vnet_hdr)
			return FALSE;
		if (nm_setting_tun_get_multi_queue (s_tun) != priv->props.multi_queue)
			return FALSE;
	}

	return TRUE;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	NMSettingWired *s_wired;
	const char *cloned_mac;
	NMActStageReturn ret;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_tun_parent_class)->act_stage1_prepare (device, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	/* Nothing to do for TUN devices */
	if (g_strcmp0 (priv->mode, "tap"))
		return NM_ACT_STAGE_RETURN_SUCCESS;

	s_wired = (NMSettingWired *) nm_device_get_applied_setting (device, NM_TYPE_SETTING_WIRED);
	if (s_wired) {
		/* Set device MAC address if the connection wants to change it */
		cloned_mac = nm_setting_wired_get_cloned_mac_address (s_wired);
		nm_device_set_hw_addr (device, cloned_mac, "set", LOGD_DEVICE);
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingWired *s_wired;
	guint32 mtu;

	connection = nm_device_get_applied_connection (device);
	g_assert (connection);

	s_wired = nm_connection_get_setting_wired (connection);
	if (s_wired) {
		mtu = nm_setting_wired_get_mtu (s_wired);
		if (mtu)
			nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
	}
}

static void
unrealize_notify (NMDevice *device)
{
	NMDeviceTun *self = NM_DEVICE_TUN (device);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	GParamSpec **properties;
	guint n_properties, i;

	NM_DEVICE_CLASS (nm_device_tun_parent_class)->unrealize_notify (device);

	memset (&priv->props, 0, sizeof (NMPlatformTunProperties));

	properties = g_object_class_list_properties (G_OBJECT_GET_CLASS (self), &n_properties);
	for (i = 0; i < n_properties; i++)
		g_object_notify_by_pspec (G_OBJECT (self), properties[i]);
	g_free (properties);
}

/**************************************************************/

static void
nm_device_tun_init (NMDeviceTun *self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceTun *self = NM_DEVICE_TUN (object);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_OWNER:
		g_value_set_int64 (value, priv->props.owner);
		break;
	case PROP_GROUP:
		g_value_set_int64 (value, priv->props.group);
		break;
	case PROP_MODE:
		g_value_set_string (value, priv->mode);
		break;
	case PROP_NO_PI:
		g_value_set_boolean (value, priv->props.no_pi);
		break;
	case PROP_VNET_HDR:
		g_value_set_boolean (value, priv->props.vnet_hdr);
		break;
	case PROP_MULTI_QUEUE:
		g_value_set_boolean (value, priv->props.multi_queue);
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
	NMDeviceTun *self = NM_DEVICE_TUN (object);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);
	const char *str;

	switch (prop_id) {
	case PROP_MODE:
		/* construct-only */
		str = g_value_get_string (value);

		/* mode is G_PARAM_STATIC_STRINGS */
		if (g_strcmp0 (str, "tun") == 0)
			priv->mode = "tun";
		else if (g_strcmp0 (str, "tap") == 0)
			priv->mode = "tap";
		else
			g_return_if_fail (FALSE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_tun_class_init (NMDeviceTunClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceTunPrivate));

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_TUN, NM_LINK_TYPE_TAP)

	object_class->get_property = get_property;
	object_class->set_property = set_property;

	device_class->connection_type = NM_SETTING_TUN_SETTING_NAME;

	device_class->link_changed = link_changed;
	device_class->complete_connection = complete_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->create_and_realize = create_and_realize;
	device_class->realize_start_notify = realize_start_notify;
	device_class->unrealize_notify = unrealize_notify;
	device_class->update_connection = update_connection;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_OWNER,
		 g_param_spec_int64 (NM_DEVICE_TUN_OWNER, "", "",
		                     -1, G_MAXUINT32, -1,
		                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_int64 (NM_DEVICE_TUN_GROUP, "", "",
		                     -1, G_MAXUINT32, -1,
		                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_DEVICE_TUN_MODE, "", "",
		                      "tun",
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NO_PI,
		 g_param_spec_boolean (NM_DEVICE_TUN_NO_PI, "", "",
		                       FALSE,
		                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_VNET_HDR,
		 g_param_spec_boolean (NM_DEVICE_TUN_VNET_HDR, "", "",
		                       FALSE,
		                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MULTI_QUEUE,
		 g_param_spec_boolean (NM_DEVICE_TUN_MULTI_QUEUE, "", "",
		                       FALSE,
		                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_TUN_SKELETON,
	                                        NULL);
}


/*************************************************************/

#define NM_TYPE_TUN_FACTORY (nm_tun_factory_get_type ())
#define NM_TUN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_TUN_FACTORY, NMTunFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	NMSettingTun *s_tun;
	NMLinkType link_type = NM_LINK_TYPE_UNKNOWN;
	const char *mode;

	if (plink) {
		link_type = plink->type;
	} else if (connection) {
		s_tun = nm_connection_get_setting_tun (connection);
		if (!s_tun)
			return NULL;
		switch (nm_setting_tun_get_mode (s_tun)) {
		case NM_SETTING_TUN_MODE_TUN:
			link_type = NM_LINK_TYPE_TUN;
			break;
		case NM_SETTING_TUN_MODE_TAP:
			link_type = NM_LINK_TYPE_TAP;
			break;
		case NM_SETTING_TUN_MODE_UNKNOWN:
			g_return_val_if_reached (NULL);
		}
	}

	g_return_val_if_fail (link_type != NM_LINK_TYPE_UNKNOWN, NULL);
	mode = link_type == NM_LINK_TYPE_TUN ? "tun" : "tap";

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_TUN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Tun",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_TUN,
	                                  NM_DEVICE_LINK_TYPE, link_type,
	                                  NM_DEVICE_TUN_MODE, mode,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (TUN, Tun, tun,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_TUN, NM_LINK_TYPE_TAP)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_TUN_SETTING_NAME),
	factory_iface->create_device = create_device;
	)

