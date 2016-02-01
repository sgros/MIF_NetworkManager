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
#include <string.h>

#include <NetworkManager.h>

#define BUFFER_SIZE		2048

static void
show_pvd (NMActiveConnection *connection, NMIPConfig *pvd)
{
	const PVDID *pvdid;
	const char *gateway;
	const char * const *nameservers;
	const char * const *domains;
	const char * const *searches;
	const char * const *wins_servers;
	GPtrArray *addresses;
	GPtrArray *routes;
	int i;

	pvdid = nm_ip_config_get_pvdid(pvd);
	printf("Provisioning domain %s\n", pvdid->uuid);

	gateway = nm_ip_config_get_gateway(pvd);
	printf("\tGateway: %s\n", gateway);

	addresses = nm_ip_config_get_addresses(pvd);
	printf("\tAddresses: ");
	for (i = 0; i < addresses->len; i++) {
		NMIPAddress *addr = addresses->pdata[i];
		if (i)
			printf(", ");
		printf("%s/%d", nm_ip_address_get_address(addr), nm_ip_address_get_prefix(addr));
	}
	printf("\n");

	routes = nm_ip_config_get_routes(pvd);
	printf("\tRoutes: ");
	for (i = 0; i < routes->len; i++) {
		NMIPRoute *route = routes->pdata[i];
		if (i)
			printf(", ");
		if (nm_ip_route_get_next_hop(route))
			printf("%s/%d via %s", nm_ip_route_get_dest(route), nm_ip_route_get_prefix(route), nm_ip_route_get_next_hop(route));
		else
			printf("%s/%d", nm_ip_route_get_dest(route), nm_ip_route_get_prefix(route));
	}
	printf("\n");

	printf("\tNameservers: ");
	nameservers = nm_ip_config_get_nameservers(pvd);
	for(i = 0; nameservers[i]; i++) {
		if (i)
			printf(", ");
		printf("%s", nameservers[i]);
	}
	printf("\n");

	printf("\tDomains: ");
	domains = nm_ip_config_get_domains(pvd);
	for(i = 0; domains[i]; i++) {
		if (i)
			printf(", ");
		printf("%s", domains[i]);
	}
	printf("\n");

	printf("\tSearches: ");
	searches = nm_ip_config_get_searches(pvd);
	for(i = 0; searches[i]; i++) {
		if (i)
			printf(", ");
		printf("%s", searches[i]);
	}
	printf("\n");

	printf("\tWINS servers: ");
	wins_servers = nm_ip_config_get_searches(pvd);
	for(i = 0; wins_servers[i]; i++) {
		if (i)
			printf(", ");
		printf("%s", wins_servers[i]);
	}
	printf("\n");
}

int
main (int argc, char *argv[])
{
	NMClient *client;
	NMActiveConnection *active_connection;
	GError *error = NULL;
	const GPtrArray *connections, *pvds;
	int i, j;

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

	printf ("\nProvisioning domains\n===================\n\n");

	for (i = 0; i < connections->len; i++) {
		active_connection = connections->pdata[i];
		pvds = nm_active_connection_get_pvds(active_connection);
		for (j = 0; pvds != NULL && j < pvds->len; j++)
			show_pvd (active_connection, pvds->pdata[j]);
	}

	g_object_unref (client);

	return EXIT_SUCCESS;
}
