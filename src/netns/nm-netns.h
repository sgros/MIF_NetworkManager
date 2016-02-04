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

#ifndef __NM_NETNS_H__
#define __NM_NETNS_H__

#include "nm-types.h"

#include "nm-exported-object.h"

#define NM_TYPE_NETNS            (nm_netns_get_type ())
#define NM_NETNS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETNS, NMNetns))
#define NM_NETNS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_NETNS, NMNetnsClass))
#define NM_IS_NETNS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETNS))
#define NM_IS_NETNS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_NETNS))
#define NM_NETNS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_NETNS, NMNetnsClass))

struct _NMNetns {
	NMExportedObject parent_instance;
};

typedef struct {
	NMExportedObjectClass parent_class;
} NMNetnsClass;

#define NM_NETNS_NAME			"name"

GType nm_netns_get_type (void);

const char *nm_netns_export(NMNetns *self);

void nm_netns_set_name(NMNetns *netns, const char *name);
const char *nm_netns_get_name(NMNetns *netns);

void nm_netns_set_id(NMNetns *self, int netns_id);
int nm_netns_get_id(NMNetns *self);

NMNetns *nm_netns_new(const char *netns_name);

#endif  /* __NM_NETNS_H__ */