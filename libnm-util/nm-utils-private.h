/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2005 - 2008 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#include "nm-setting-private.h"

gboolean    _nm_utils_string_in_list   (const char *str,
                                        const char **valid_strings);

gboolean    _nm_utils_string_slist_validate (GSList *list,
                                             const char **valid_values);

gboolean    _nm_utils_gvalue_array_validate (GValueArray *elements,
                                             guint n_expected, ...);

void        _nm_value_transforms_register (void);

#endif
