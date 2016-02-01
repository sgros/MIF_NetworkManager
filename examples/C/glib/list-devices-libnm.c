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
 * The example shows how to list devices.
 *
 * Compile with:
 *   gcc -Wall `pkg-config --libs --cflags glib-2.0 libnm` list-devices-libnm.c -o list-devices-libnm
 */

#include "config.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <NetworkManager.h>

/* Print details of a device */
static void
show_device (NMDevice *device)
{
	const char *val1, *val2, *val3, *val4;
	GPtrArray *pvds;
	NMIPConfig *pvd;
	int i;
	const PVDID *pvdid;

	val1 = nm_device_get_iface (device);
	val2 = nm_device_get_ip_iface (device);
	val3 = nm_device_get_type_description (device);
	val4 = "";

	pvds = nm_device_get_pvds(device);
	if (pvds && pvds->len > 0) {
		for (i = 0; i < pvds->len; i++) {
			pvd = pvds->pdata[i];
			pvdid = nm_ip_config_get_pvdid(pvd);
			val4 = pvdid->uuid;
			printf ("%-12s|%12s|%15s|%s\n", val1, val2, val3, val4);
			val1 = val2 = val3 = "";
		}
	} else
		printf ("%-12s|%12s|%15s|%s\n", val1, val2, val3, val4);
}

int
main (int argc, char *argv[])
{
	NMClient *client;
	GError *error = NULL;
	const GPtrArray *devices;
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
		g_message ("Error: Can't obtain devices: NetworkManager is not running.");
		return EXIT_FAILURE;
	}

	/* Now the devices can be listed. */
	devices = nm_client_get_devices (client);

	printf ("Devices:\n============\n");

	for (i = 0; i < devices->len; i++)
		show_device (devices->pdata[i]);

	g_object_unref (client);

	return EXIT_SUCCESS;
}
