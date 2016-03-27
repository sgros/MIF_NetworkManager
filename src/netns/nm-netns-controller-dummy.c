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

/*
 * This is a dummy implementation of network namespace controller that
 * doesn't use any namespaces but provides appropriate interface.
 *
 * The reason for introducing this object/class is that nm-iface-helper
 * needs NMRouteManager and NMDefaultRouteManager classes/objects which
 * in turn use NMNetnsController class/object which uses NMNetns class/
 * object which finally uses NMDevice class/object. But, NMDevice class/
 * object isn't used by nm-iface-helper.
 *
 * So, to not introduce dependency of nm-iface-helper on NMDevice, this
 * dummy class/object is introduced that breaks dependency chain
 * described in the previous paragraph.
 */

#include "config.h"

#include <gmodule.h>
#include <nm-dbus-interface.h>

#include "nm-platform.h"
#include "nm-linux-platform.h"
#include "nm-netns.h"
#include "nm-netns-controller.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMNetnsController, nm_netns_controller, G_TYPE_OBJECT)

enum {
	PROP_0,
	PROP_REGISTER_SINGLETON,
	LAST_PROP,
};

typedef struct {
	gboolean register_singleton;

	/*
	 * Only one fixed network namespace
	 */
	NMNetns *netns;

} NMNetnsControllerPrivate;

#define NM_NETNS_CONTROLLER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerPrivate))

NM_DEFINE_SINGLETON_INSTANCE (NMNetnsController);

NM_DEFINE_SINGLETON_REGISTER (NMNetnsController);

NMNetns *
nm_netns_controller_get_root_netns (void)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	return priv->netns;
}

/******************************************************************/

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
	NMNetnsControllerPrivate *priv;

        g_return_val_if_fail (!singleton_instance, FALSE);

        singleton_instance = nm_netns_controller_new();

        nm_singleton_instance_register ();

	priv = NM_NETNS_CONTROLLER_GET_PRIVATE (singleton_instance);

	priv->netns = nm_netns_new(NULL);

        nm_log_dbg (LOGD_NETNS, "setup %s singleton (%p, %s)",
			"NMNetnsController", singleton_instance,
			G_OBJECT_TYPE_NAME (singleton_instance));

	return TRUE;
}

NMNetnsController *
nm_netns_controller_get(void)
{
	return singleton_instance;
}

void
nm_netns_controller_stop (NMNetnsController *self)
{
	NMNetnsControllerPrivate *priv = NM_NETNS_CONTROLLER_GET_PRIVATE (self);

	nm_netns_stop(priv->netns);
	g_clear_object(&priv->netns);
}

NMNetnsController *
nm_netns_controller_new (void)
{
	NMNetnsController *self;

        self = g_object_new (NM_TYPE_NETNS_CONTROLLER,
			NM_NETNS_CONTROLLER_REGISTER_SINGLETON, TRUE,
			NULL);

	return self;
}

/******************************************************************/

static void
nm_netns_controller_init (NMNetnsController *self)
{
}

static void
nm_netns_controller_class_init (NMNetnsControllerClass *klass)
{
	g_type_class_add_private (klass, sizeof (NMNetnsControllerPrivate));
}

