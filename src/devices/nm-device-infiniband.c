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
 * Copyright 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <linux/if_infiniband.h>

#include "nm-device-infiniband.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-activation-request.h"
#include "nm-ip4-config.h"
#include "nm-platform.h"
#include "nm-device-factory.h"
#include "nm-core-internal.h"

#include "nmdbus-device-infiniband.h"

G_DEFINE_TYPE (NMDeviceInfiniband, nm_device_infiniband, NM_TYPE_DEVICE)

#define NM_DEVICE_INFINIBAND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_INFINIBAND, NMDeviceInfinibandPrivate))

#define NM_DEVICE_INFINIBAND_IS_PARTITION "is-partition"

typedef struct {
	gboolean is_partition;
} NMDeviceInfinibandPrivate;

enum {
	PROP_0,
	PROP_IS_PARTITION,

	LAST_PROP
};

/*************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	guint32 caps = NM_DEVICE_CAP_CARRIER_DETECT;

	if (NM_DEVICE_INFINIBAND_GET_PRIVATE (dev)->is_partition)
		caps |= NM_DEVICE_CAP_IS_SOFTWARE;

	return caps;
}

static NMActStageReturn
act_stage1_prepare (NMDevice *dev, NMDeviceStateReason *reason)
{
	NMActStageReturn ret;
	NMSettingInfiniband *s_infiniband;
	const char *transport_mode;
	char *mode_path;
	gboolean ok, no_firmware = FALSE;

	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	ret = NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->act_stage1_prepare (dev, reason);
	if (ret != NM_ACT_STAGE_RETURN_SUCCESS)
		return ret;

	s_infiniband = (NMSettingInfiniband *) nm_device_get_applied_setting (dev, NM_TYPE_SETTING_INFINIBAND);
	g_assert (s_infiniband);

	transport_mode = nm_setting_infiniband_get_transport_mode (s_infiniband);

	mode_path = g_strdup_printf ("/sys/class/net/%s/mode",
	                             NM_ASSERT_VALID_PATH_COMPONENT (nm_device_get_iface (dev)));
	if (!g_file_test (mode_path, G_FILE_TEST_EXISTS)) {
		g_free (mode_path);

		if (!strcmp (transport_mode, "datagram"))
			return NM_ACT_STAGE_RETURN_SUCCESS;
		else {
			*reason = NM_DEVICE_STATE_REASON_INFINIBAND_MODE;
			return NM_ACT_STAGE_RETURN_FAILURE;
		}
	}

	/* With some drivers the interface must be down to set transport mode */
	nm_device_take_down (dev, TRUE);
	ok = nm_platform_sysctl_set (nm_device_get_platform(dev), mode_path, transport_mode);
	g_free (mode_path);
	nm_device_bring_up (dev, TRUE, &no_firmware);

	if (!ok) {
		*reason = NM_DEVICE_STATE_REASON_CONFIG_FAILED;
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
ip4_config_pre_commit (NMDevice *self, NMIP4Config *config)
{
	NMConnection *connection;
	NMSettingInfiniband *s_infiniband;
	guint32 mtu;

	connection = nm_device_get_applied_connection (self);
	g_assert (connection);
	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	/* MTU override */
	mtu = nm_setting_infiniband_get_mtu (s_infiniband);
	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_USER);
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband;

	if (!NM_DEVICE_CLASS (nm_device_infiniband_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME))
		return FALSE;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband)
		return FALSE;

	if (nm_device_is_real (device)) {
		const char *mac;

		mac = nm_setting_infiniband_get_mac_address (s_infiniband);
		if (mac && !nm_utils_hwaddr_matches (mac, -1, nm_device_get_hw_address (device), -1))
			return FALSE;
	}

	return TRUE;
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMSettingInfiniband *s_infiniband;
	const char *setting_mac;
	const char *hw_address;

	nm_utils_complete_generic (NM_PLATFORM_GET,
	                           connection,
	                           NM_SETTING_INFINIBAND_SETTING_NAME,
	                           existing_connections,
	                           NULL,
	                           _("InfiniBand connection"),
	                           NULL,
	                           TRUE);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_infiniband));
	}

	setting_mac = nm_setting_infiniband_get_mac_address (s_infiniband);
	hw_address = nm_device_get_hw_address (device);
	if (setting_mac) {
		/* Make sure the setting MAC (if any) matches the device's MAC */
		if (!nm_utils_hwaddr_matches (setting_mac, -1, hw_address, -1)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("connection does not match device"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_INFINIBAND_SETTING_NAME, NM_SETTING_INFINIBAND_MAC_ADDRESS);
			return FALSE;
		}
	} else {
		/* Lock the connection to this device by default */
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_MAC_ADDRESS, hw_address, NULL);
	}

	if (!nm_setting_infiniband_get_transport_mode (s_infiniband))
		g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, "datagram", NULL);

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband = nm_connection_get_setting_infiniband (connection);
	const char *mac = nm_device_get_hw_address (device);
	const char *transport_mode = "datagram";
	int ifindex;

	if (!s_infiniband) {
		s_infiniband = (NMSettingInfiniband *) nm_setting_infiniband_new ();
		nm_connection_add_setting (connection, (NMSetting *) s_infiniband);
	}

	if (mac && !nm_utils_hwaddr_matches (mac, -1, NULL, INFINIBAND_ALEN))
		g_object_set (s_infiniband, NM_SETTING_INFINIBAND_MAC_ADDRESS, mac, NULL);

	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0) {
		if (!nm_platform_link_infiniband_get_properties (nm_device_get_platform(device), ifindex, NULL, NULL, &transport_mode))
			transport_mode = "datagram";
	}
	g_object_set (G_OBJECT (s_infiniband), NM_SETTING_INFINIBAND_TRANSPORT_MODE, transport_mode, NULL);
}

static gboolean
create_and_realize (NMDevice *device,
                    NMConnection *connection,
                    NMDevice *parent,
                    const NMPlatformLink **out_plink,
                    GError **error)
{
	NMSettingInfiniband *s_infiniband;
	int parent_ifindex, p_key;
	NMPlatformError plerr;

	if (!NM_IS_DEVICE_INFINIBAND (parent)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Parent interface %s must be an InfiniBand interface",
		             nm_device_get_iface (parent));
		return FALSE;
	}

	s_infiniband = nm_connection_get_setting_infiniband (connection);

	/* Can only create partitions at this time */
	p_key = nm_setting_infiniband_get_p_key (s_infiniband);
	if (p_key < 0) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		                     "only InfiniBand partitions can be created");
		return FALSE;
	}

	parent_ifindex = nm_device_get_ifindex (parent);
	if (parent_ifindex <= 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "failed to get InfiniBand parent %s ifindex",
		             nm_device_get_iface (parent));
		return FALSE;
	}

	plerr = nm_platform_link_infiniband_add (nm_device_get_platform(device), parent_ifindex, p_key, out_plink);
	if (plerr != NM_PLATFORM_ERROR_SUCCESS) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_CREATION_FAILED,
		             "Failed to create InfiniBand P_Key interface '%s' for '%s': %s",
		             nm_device_get_iface (device),
		             nm_connection_get_id (connection),
		             nm_platform_error_to_string (plerr));
		return FALSE;
	}

	NM_DEVICE_INFINIBAND_GET_PRIVATE (device)->is_partition = TRUE;
	return TRUE;
}

/*************************************************************/

static void
nm_device_infiniband_init (NMDeviceInfiniband * self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_IS_PARTITION:
		g_value_set_boolean (value, NM_DEVICE_INFINIBAND_GET_PRIVATE (object)->is_partition);
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
	case PROP_IS_PARTITION:
		NM_DEVICE_INFINIBAND_GET_PRIVATE (object)->is_partition = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_infiniband_class_init (NMDeviceInfinibandClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceInfinibandPrivate));

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_INFINIBAND_SETTING_NAME, NM_LINK_TYPE_INFINIBAND)

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->create_and_realize = create_and_realize;
	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->complete_connection = complete_connection;
	parent_class->update_connection = update_connection;

	parent_class->act_stage1_prepare = act_stage1_prepare;
	parent_class->ip4_config_pre_commit = ip4_config_pre_commit;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_IS_PARTITION,
		 g_param_spec_boolean (NM_DEVICE_INFINIBAND_IS_PARTITION, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_INFINIBAND_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_INFINIBAND_FACTORY (nm_infiniband_factory_get_type ())
#define NM_INFINIBAND_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_INFINIBAND_FACTORY, NMInfinibandFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	gboolean is_partition = FALSE;

	if (plink)
		is_partition = (plink->parent > 0 || plink->parent == NM_PLATFORM_LINK_OTHER_NETNS);
	else if (connection) {
		NMSettingInfiniband *s_infiniband;

		s_infiniband = nm_connection_get_setting_infiniband (connection);
		g_return_val_if_fail (s_infiniband, NULL);
		is_partition =    !!nm_setting_infiniband_get_parent (s_infiniband)
		               || (   nm_setting_infiniband_get_p_key (s_infiniband) >= 0
		                   && nm_setting_infiniband_get_mac_address (s_infiniband));
	}

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_INFINIBAND,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "InfiniBand",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_INFINIBAND,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_INFINIBAND,
	                                  /* XXX: Partition should probably be a different link type! */
	                                  NM_DEVICE_INFINIBAND_IS_PARTITION, is_partition,
	                                  NULL);
}

static const char *
get_connection_parent (NMDeviceFactory *factory, NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME), NULL);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	return nm_setting_infiniband_get_parent (s_infiniband);
}

static char *
get_connection_iface (NMDeviceFactory *factory,
                      NMConnection *connection,
                      const char *parent_iface)
{
	NMSettingInfiniband *s_infiniband;

	g_return_val_if_fail (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME), NULL);

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_assert (s_infiniband);

	if (!parent_iface)
		return NULL;

	g_return_val_if_fail (g_strcmp0 (parent_iface, nm_setting_infiniband_get_parent (s_infiniband)) == 0, NULL);

	return g_strdup (nm_setting_infiniband_get_virtual_interface_name (s_infiniband));
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (INFINIBAND, Infiniband, infiniband,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES    (NM_LINK_TYPE_INFINIBAND)
	NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES (NM_SETTING_INFINIBAND_SETTING_NAME),
	factory_iface->create_device = create_device;
	factory_iface->get_connection_parent = get_connection_parent;
	factory_iface->get_connection_iface = get_connection_iface;
	)

