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

#include "nm-platform.h"
#include "nm-netns.h"

#include "nmdbus-netns.h"

G_DEFINE_TYPE (NMNetns, nm_netns, NM_TYPE_EXPORTED_OBJECT)

#define NM_NETNS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_NETNS, NMNetnsPrivate))

enum {
	PROP_0 = 0,
	PROP_NAME,
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

NMNetns *
nm_netns_new (const char *netns_name)
{
	NMNetns *self;

	self = g_object_new (NM_TYPE_NETNS, NULL);
	nm_netns_set_name(self, netns_name);

	return self;
}

static void
nm_netns_init (NMNetns *self)
{
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_netns_parent_class)->constructed (object);
}

static void
finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_netns_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	G_OBJECT_CLASS (nm_netns_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMNetns *self = NM_NETNS (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_netns_get_name (self));
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
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Network namespace's name */
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_NETNS_NAME, "", "",
				      NULL,
				      G_PARAM_READABLE |
				      G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
                                                NMDBUS_TYPE_NET_NS_INSTANCE_SKELETON,
                                                NULL);

}

