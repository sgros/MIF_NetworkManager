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

#ifndef __NM_NETNS_CONTROLLER_H__
#define __NM_NETNS_CONTROLLER_H__

#include "nm-types.h"

#include "nm-exported-object.h"

#define NM_TYPE_NETNS_CONTROLLER            (nm_netns_controller_get_type ())
#define NM_NETNS_CONTROLLER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETNS_CONTROLLER, NMNetnsController))
#define NM_NETNS_CONTROLLER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerClass))
#define NM_IS_NETNS_CONTROLLER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETNS_CONTROLLER))
#define NM_IS_NETNS_CONTROLLER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_NETNS_CONTROLLER))
#define NM_NETNS_CONTROLLER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_NETNS_CONTROLLER, NMNetnsControllerClass))

struct _NMNetnsController {
	NMExportedObject parent_instance;
};

typedef struct {
	NMExportedObjectClass parent_class;
} NMNetnsControllerClass;

#define NM_NETNS_CONTROLLER_REGISTER_SINGLETON		"register-singleton"

GType nm_netns_controller_get_type (void);

void nm_netns_controller_setup (void);

NMNetnsController *nm_netns_controller_new(void);

#endif  /* __NM_NETNS_CONTROLLER_H__ */