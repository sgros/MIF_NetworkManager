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
#include "nm-default-route-manager.h"
#include "nm-route-manager.h"
#include "nm-platform.h"
#include "nm-netns.h"

G_DEFINE_TYPE (NMNetns, nm_netns, G_TYPE_OBJECT)

#define NM_NETNS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS, NMNetnsPrivate))

typedef struct {
	/*
	 * Route manager instance for the namespace
	 */
        NMRouteManager *route_manager;

} NMNetnsPrivate;

NMPlatform *
nm_netns_get_platform(NMNetns *self)
{
	return nm_platform_get();
}

NMRouteManager *
nm_netns_get_route_manager(NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	return priv->route_manager;
}

void
nm_netns_stop (NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	g_clear_object(&priv->route_manager);
}

NMNetns *
nm_netns_new (const char *netns_name)
{
	return g_object_new (NM_TYPE_NETNS, NULL);
}

/******************************************************************/

static void
nm_netns_init (NMNetns *self)
{
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	priv->route_manager = nm_route_manager_new();
}

static void
nm_netns_class_init (NMNetnsClass *klass)
{
	g_type_class_add_private (klass, sizeof (NMNetnsPrivate));
}

