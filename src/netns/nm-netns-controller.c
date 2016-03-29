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

#include <gmodule.h>
#include <nm-dbus-interface.h>

#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-device.h"
#include "nm-netns.h"
#include "nm-netns-controller.h"
#include "NetworkManagerUtils.h"

#include "nmdbus-netns-controller.h"

G_DEFINE_TYPE (NMNetnsController, nm_netns_controller, NM_TYPE_EXPORTED_OBJECT)

enum {
	PROP_0,
	PROP_REGISTER_SINGLETON,
	PROP_NETWORK_NAMESPACES,
	LAST_PROP,
};

enum {
	NETNS_ADDED,
	NETNS_REMOVED,
	LAST_SIGNAL,
};
static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gboolean register_singleton;

	/*
	 * Pointer to a root network namespace
	 */
	NMNetns *root_ns;

	/*
	 * Pointer to a currently active network namespace
	 */
	NMNetns *active_ns;

	/*
	 * Hash table of NMNetns object indexed by DBus path they are
	 * exported at.
	 */
	GHashTable *network_namespaces;
} NMNetnsControllerPrivate;

#define NM_NETNS_CONTROLLER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerPrivate))

NM_DEFINE_SINGLETON_INSTANCE (NMNetnsController);

NM_DEFINE_SINGLETON_REGISTER (NMNetnsController);

#define NETNS_ROOT_NAME			"rootns"

/******************************************************************/

static const char *
find_netns_key_by_name(NMNetnsController *self, const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	GHashTableIter iter;
	gpointer key, value;

        g_hash_table_iter_init (&iter, priv->network_namespaces);
        while (g_hash_table_iter_next (&iter, &key, &value))
		if (!strcmp(netnsname, nm_netns_get_name(value)))
			return key;

	return NULL;
}


/******************************************************************/

NMNetns *
nm_netns_controller_get_root_netns (void)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return priv->root_ns;
}

NMNetns *
nm_netns_controller_find_netns_by_path(const char *netns_path)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return g_hash_table_lookup (priv->network_namespaces, netns_path);
}

NMNetns *
nm_netns_controller_find_netns_by_name(const char *netns_name)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);
	GHashTableIter iter;
	gpointer value;

        g_hash_table_iter_init (&iter, priv->network_namespaces);
        while (g_hash_table_iter_next (&iter, NULL, &value))
		if (!strcmp (nm_netns_get_name(value), netns_name))
			return value;

	return NULL;
}

NMPlatform *
nm_netns_controller_get_root_platform (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	return nm_netns_get_platform(priv->root_ns);
}

/******************************************************************/

NMDevice *
nm_netns_controller_find_device_by_path (const char *device_path)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);
	GHashTableIter iter;
	gpointer value;
	NMDevice *device;

        g_hash_table_iter_init (&iter, priv->network_namespaces);
        while (g_hash_table_iter_next (&iter, NULL, &value))
		if ((device = nm_netns_get_device_by_path (value, device_path)) != NULL)
			return device;

	return NULL;
}

/******************************************************************/

static NMNetns *
create_new_namespace (NMNetnsController *self, const char *netnsname,
                      gboolean isroot)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;

	const char *path;

	netns = nm_netns_new (netnsname);

	if (isroot) {
		priv->root_ns = netns;
		g_object_ref (netns);
	}

	if (!nm_netns_setup (netns, isroot)) {
        	nm_log_dbg (LOGD_NETNS, "error setting up namespace %s ", netnsname);
		g_object_unref (netns);
		return NULL;
	}

	path = nm_netns_export (netns);
	g_hash_table_insert (priv->network_namespaces, (gpointer)path, netns);

	/* Emit D-Bus signals */
	g_signal_emit (self, signals[NETNS_ADDED], 0, netns);
	g_object_notify (G_OBJECT (self), NM_NETNS_CONTROLLER_NETWORK_NAMESPACES);

	return netns;
}

NMNetns *
nm_netns_controller_new_netns(const char *netns_name)
{
	return create_new_namespace (singleton_instance, netns_name, FALSE);
}

void
nm_netns_controller_remove_netns (NMNetnsController *self,
                                  NMNetns *netns)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	const char *path;

	path = nm_exported_object_get_path ( NM_EXPORTED_OBJECT(netns));

	nm_log_dbg (LOGD_NETNS, "Removing network namespace %s (path %s)", nm_netns_get_name (netns), path);

	/* Emit removal D-Bus signal */
	g_signal_emit (self, signals[NETNS_REMOVED], 0, netns);

	/* Stop network namespace */
	nm_netns_stop(netns);

	/* Remove network namespace from a list */
	g_hash_table_remove(priv->network_namespaces, path);

	/* Signal change in property */
	g_object_notify (G_OBJECT (self), NM_NETNS_CONTROLLER_NETWORK_NAMESPACES);
}

/******************************************************************/

static void
impl_netns_controller_list_namespaces (NMNetnsController *self,
                                       GDBusMethodInvocation *context)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	GPtrArray *network_namespaces;
	GHashTableIter iter;
	gpointer key;

	network_namespaces = g_ptr_array_sized_new (g_hash_table_size (priv->network_namespaces) + 1);
        g_hash_table_iter_init (&iter, priv->network_namespaces);
        while (g_hash_table_iter_next (&iter, &key, NULL))
                g_ptr_array_add (network_namespaces, key);
        g_ptr_array_add (network_namespaces, NULL);

        g_dbus_method_invocation_return_value (context,
                                               g_variant_new ("(^ao)", network_namespaces->pdata));
        g_ptr_array_unref (network_namespaces);
}

static void
impl_netns_controller_add_namespace (NMNetnsController *self,
                                     GDBusMethodInvocation *context,
                                     const char *netnsname)
{
	NMNetns *netns;

	if ((netns = create_new_namespace(self, netnsname, FALSE)) != NULL) {
		g_dbus_method_invocation_return_value (context,
						       g_variant_new ("(o)",
						       nm_exported_object_get_path (NM_EXPORTED_OBJECT (netns))));
	} else
		g_dbus_method_invocation_return_error (context,
						       NM_NETNS_ERROR,
						       NM_NETNS_ERROR_FAILED,
						       "Error creating network namespace");
}

static void
impl_netns_controller_remove_namespace (NMNetnsController *self,
                                        GDBusMethodInvocation *context,
                                        const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;
	const char *path;

	path = find_netns_key_by_name(self, netnsname);

	nm_log_dbg (LOGD_NETNS, "Removing network namespace %s (path %s)",
		    netnsname, path);

	if (path == NULL) {
		nm_log_err (LOGD_NETNS, "Network namespace %s not found", netnsname);
		g_dbus_method_invocation_return_error (context,
						       NM_NETNS_ERROR,
						       NM_NETNS_ERROR_NOT_FOUND,
						       "Network name space not found");
		return;
	}

	netns = g_hash_table_lookup(priv->network_namespaces, path);

	if (netns == priv->root_ns) {
		nm_log_err (LOGD_NETNS, "Root namespace %s can not be removed", netnsname);
		g_dbus_method_invocation_return_error (context,
						       NM_NETNS_ERROR,
						       NM_NETNS_ERROR_PERMISSION_DENIED,
						       "Root network namespace can not be removed");
		return;
	}

	nm_netns_controller_remove_netns (self, netns);

	g_dbus_method_invocation_return_value (context,
					       g_variant_new ("(s)",
					       "Success"));
}

/**
 * nm_netns_controller_setup:
 * @instance: the #NMNetnsController instance
 *
 * Failing to set up #NMNetnsController singleton results in a fatal
 * error, as well as trying to initialize it multiple times without
 * freeing it.
 *
 * NetworkManager will typically use only one network manager controller
 * object during its run.
 */
gboolean
nm_netns_controller_setup (void)
{
        g_return_val_if_fail (!singleton_instance, FALSE);

        singleton_instance = nm_netns_controller_new ();

        nm_singleton_instance_register ();

        nm_log_dbg (LOGD_NETNS, "setup %s singleton (%p, %s)",
	                        "NMNetnsController", singleton_instance,
	                        G_OBJECT_TYPE_NAME (singleton_instance));

	return create_new_namespace (singleton_instance, NETNS_ROOT_NAME, TRUE) ? TRUE : FALSE;
}

NMNetnsController *
nm_netns_controller_get (void)
{
	return singleton_instance;
}

void
nm_netns_controller_stop (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv;
	GHashTableIter iter;
	gpointer value;

	if (!self)
		return;

	priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	g_hash_table_iter_init (&iter, priv->network_namespaces);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		nm_netns_stop(value);

	g_hash_table_destroy (priv->network_namespaces);
	priv->network_namespaces = NULL;

	g_object_unref(priv->root_ns);
	g_object_unref(priv->active_ns);

	priv->root_ns = priv->active_ns = NULL;
}

NMNetnsController *
nm_netns_controller_new (void)
{
	NMNetnsController *self;
	NMNetnsControllerPrivate *priv;

        self = g_object_new (NM_TYPE_NETNS_CONTROLLER,
			NM_NETNS_CONTROLLER_REGISTER_SINGLETON, TRUE,
			NULL);

	priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	nm_exported_object_export (NM_EXPORTED_OBJECT (self));

        nm_log_dbg (LOGD_NETNS, "Created network namespace controller.");

	return self;
}

static void
nm_netns_controller_init (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	priv->network_namespaces = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

/******************************************************************/

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv =  NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_REGISTER_SINGLETON:
		/* construct-only */
		priv->register_singleton = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv =  NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_NETWORK_NAMESPACES: {
		GHashTableIter iter;
		gpointer key;
		char **paths;
		guint i;

		paths = g_new (char *, g_hash_table_size (priv->network_namespaces) + 1);

		i = 0;
		g_hash_table_iter_init (&iter, priv->network_namespaces);
		while (g_hash_table_iter_next (&iter, &key, NULL))
			paths[i++] = g_strdup (key);
		paths[i] = NULL;
		g_value_take_boxed (value, paths);
		break;
	}
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_netns_controller_class_init (NMNetnsControllerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMNetnsControllerPrivate));

	exported_object_class->export_path = NM_DBUS_PATH_NETNS_CONTROLLER;

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	g_object_class_install_property
	 (object_class, PROP_REGISTER_SINGLETON,
	     g_param_spec_boolean (NM_NETNS_CONTROLLER_REGISTER_SINGLETON, "", "",
				   FALSE,
				   G_PARAM_WRITABLE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	 (object_class, PROP_NETWORK_NAMESPACES,
	     g_param_spec_boxed (NM_NETNS_CONTROLLER_NETWORK_NAMESPACES, "", "",
				 G_TYPE_STRV,
				 G_PARAM_READABLE |
				 G_PARAM_STATIC_STRINGS));

	/* Signals */
	signals[NETNS_ADDED] =
		g_signal_new (NM_NETNS_CONTROLLER_NETNS_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, NM_TYPE_NETNS);

	signals[NETNS_REMOVED] =
		g_signal_new (NM_NETNS_CONTROLLER_NETNS_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, NM_TYPE_NETNS);

// TODO: Signal that namespace is removed

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
						NMDBUS_TYPE_NETWORK_NAMESPACES_CONTROLLER_SKELETON,
						"ListNetworkNamespaces", impl_netns_controller_list_namespaces,
						"AddNetworkNamespace", impl_netns_controller_add_namespace,
						"RemoveNetworkNamespace", impl_netns_controller_remove_namespace,
						NULL);
}

