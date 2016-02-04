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
#include "nm-netns.h"
#include "nm-netns-controller.h"
#include "NetworkManagerUtils.h"

#include "nmdbus-netns-controller.h"

G_DEFINE_TYPE (NMNetnsController, nm_netns_controller, NM_TYPE_EXPORTED_OBJECT)

enum {
	PROP_0,
	PROP_REGISTER_SINGLETON,
	LAST_PROP,
};

typedef struct {
	gboolean register_singleton;

	/*
	 * Pointer to a root network namespace
	 */
	NMNetns *root_ns;

	/*
	 * Pointer to a currently active network namespace
	 */
	NMNetns *act_ns;

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
impl_netns_controller_add_namespace (NMSettings *self,
			GDBusMethodInvocation *context,
			const char *netnsname)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);
	NMNetns *netns;

	const char *path;
	int netns_id;

	printf("Called AddConnection %s\n", netnsname);

	netns = nm_netns_new(netnsname);

	if (!nm_platform_netns_create(NM_PLATFORM_GET, netnsname, &netns_id)) {
		g_object_unref(netns);
		return;
	}

	nm_netns_set_id(netns, netns_id);

	path = nm_netns_export(netns);
	g_hash_table_insert(priv->network_namespaces, (gpointer)path, netns);
	g_object_ref (netns);

	/* Activate loopback interface */
	nm_platform_netns_activate(NM_PLATFORM_GET, netns_id);
	nm_platform_link_set_up (NM_PLATFORM_GET, 1, NULL);
	nm_platform_netns_activate(NM_PLATFORM_GET, nm_netns_get_id(priv->root_ns));

	return;
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
void
nm_netns_controller_setup (void)
{
	NMNetnsControllerPrivate *priv;

	const char *path;
	int netns_id;

        g_return_if_fail (!singleton_instance);

        singleton_instance = nm_netns_controller_new();

        nm_singleton_instance_register ();

        nm_log_dbg (LOGD_CORE, "setup %s singleton (%p, %s)",
			"NMNetnsController", singleton_instance,
			G_OBJECT_TYPE_NAME (singleton_instance));

	priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	/*
	 * Create root network namespace
	 */

	priv->root_ns = nm_netns_new(NETNS_ROOT_NAME);

	if (!nm_platform_netns_get_root(NM_PLATFORM_GET, NETNS_ROOT_NAME, &netns_id)) {
		g_object_unref(priv->root_ns);
		priv->root_ns = NULL;

		/*
		 * NETNS support should be disabled because setup
		 * failed!
		 */
		return;
	}

	nm_netns_set_id(priv->root_ns, netns_id);

	path = nm_netns_export(priv->root_ns);
	g_hash_table_insert(priv->network_namespaces, (gpointer)path, priv->root_ns);
	g_object_ref (priv->root_ns);
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
	return self;
}

static void
nm_netns_controller_init (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	priv->network_namespaces = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (nm_netns_controller_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMNetnsController *self = NM_NETNS_CONTROLLER (object);
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	g_hash_table_destroy (priv->network_namespaces);

	G_OBJECT_CLASS (nm_netns_controller_parent_class)->finalize (object);
}

/******************************************************************/

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	NMNetnsControllerPrivate *priv =  NM_NETNS_CONTROLLER_GET_PRIVATE (object);

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
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	g_object_class_install_property
	 (object_class, PROP_REGISTER_SINGLETON,
	     g_param_spec_boolean (NM_NETNS_CONTROLLER_REGISTER_SINGLETON, "", "",
				   FALSE,
				   G_PARAM_WRITABLE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_STRINGS));

// TODO: Signal that new namespace is added

// TODO: Signal that namespace is removed

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
                                                NMDBUS_TYPE_NETWORK_NAMESPACES_CONTROLLER_SKELETON,
                                                "ListNetworkNamespaces", impl_netns_controller_list_namespaces,
                                                "AddNetworkNamespace", impl_netns_controller_add_namespace,
                                                NULL);
}
