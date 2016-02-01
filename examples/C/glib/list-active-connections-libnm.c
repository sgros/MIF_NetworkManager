/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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

/*
 * The example shows how to list connections.  Contrast this example with
 * list-connections-gdbus.c, which is a bit lower level and talks directly to NM
 * using GDBus.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 libnm` list-connections-libnm.c -o list-connections-libnm
 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <NetworkManager.h>

/* Print details of connection */
static void
show_active_connection (NMActiveConnection *connection)
{
	const char *val1, *val2, *val3, *val4;

	val1 = nm_active_connection_get_id(connection);
	val2 = nm_active_connection_get_uuid(connection);
	val3 = nm_active_connection_get_connection_type(connection);
	val4 = nm_active_connection_get_specific_object_path(connection);

	printf ("%-10s|%37s | %-15s | %-20s |\n", val1, val2, val3, val4);
}

int
main (int argc, char *argv[])
{
	NMClient *client;
	GError *error = NULL;
	const GPtrArray *connections;
	int i;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	/* Initialize GType system */
	g_type_init ();
#endif

	if (!(client = nm_client_new (NULL, &error))) {
		g_message ("Error: Could not connect to NetworkManager: %s.", error->message);
		g_error_free (error);
		return EXIT_FAILURE;
	}

	if (!nm_client_get_nm_running (client)) {
		g_message ("Error: Can't obtain connections: NetworkManager is not running.");
		return EXIT_FAILURE;
	}

	/* Now the connections can be listed. */
	connections = nm_client_get_active_connections (client);

	printf ("Active connections:\n===================\n\n");

	printf ("%-10s| %-37s| %-15s | %-20s |\n", "ID", "UUID", "TYPE", "SPECIFIC OBJECT PATH");
	printf ("-------------------------------------------------------------------------------------------\n");

	for (i = 0; i < connections->len; i++)
		show_active_connection (connections->pdata[i]);

	g_object_unref (client);

	return EXIT_SUCCESS;
}
