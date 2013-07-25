/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-rdisc.h - Perform IPv6 router discovery
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NM_RDISC_H
#define NM_RDISC_H

#include <glib-object.h>

#include <stdlib.h>
#include <netinet/in.h>

#define NM_TYPE_RDISC            (nm_rdisc_get_type ())
#define NM_RDISC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_RDISC, NMRDisc))
#define NM_RDISC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_RDISC, NMRDiscClass))
#define NM_IS_RDISC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_RDISC))
#define NM_IS_RDISC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_RDISC))
#define NM_RDISC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_RDISC, NMRDiscClass))

#define NM_RDISC_CONFIG_CHANGED "config-changed"

typedef enum {
	NM_RDISC_DHCP_LEVEL_UNKNOWN,
	NM_RDISC_DHCP_LEVEL_NONE,
	NM_RDISC_DHCP_LEVEL_OTHERCONF,
	NM_RDISC_DHCP_LEVEL_MANAGED
} NMRDiscDHCPLevel;

typedef enum {
	NM_RDISC_PREFERENCE_INVALID,
	NM_RDISC_PREFERENCE_LOW,
	NM_RDISC_PREFERENCE_MEDIUM,
	NM_RDISC_PREFERENCE_HIGH
} NMRDiscPreference;

typedef struct {
	struct in6_addr address;
	guint32 timestamp;
	guint32 lifetime;
	NMRDiscPreference preference;
} NMRDiscGateway;

typedef struct {
	struct in6_addr address;
	guint32 timestamp;
	guint32 lifetime;
	guint32 preferred_lft;
} NMRDiscAddress;

typedef struct {
	struct in6_addr network;
	int plen;
	struct in6_addr gateway;
	guint32 timestamp;
	guint32 lifetime;
	NMRDiscPreference preference;
} NMRDiscRoute;

typedef struct {
	struct in6_addr address;
	guint32 timestamp;
	guint32 lifetime;
} NMRDiscDNSServer;

typedef struct {
	char *domain;
	guint32 timestamp;
	guint32 lifetime;
} NMRDiscDNSDomain;

typedef enum {
	NM_RDISC_CONFIG_DHCP_LEVEL = 1 << 0,
	NM_RDISC_CONFIG_GATEWAYS = 1 << 1,
	NM_RDISC_CONFIG_ADDRESSES = 1 << 2,
	NM_RDISC_CONFIG_ROUTES = 1 << 3,
	NM_RDISC_CONFIG_DNS_SERVERS = 1 << 4,
	NM_RDISC_CONFIG_DNS_DOMAINS = 1 << 5
} NMRDiscConfigMap;

/**
 * NMRDisc:
 * @ifindex: Interface index
 *
 * Interface-specific structure that handles incoming router advertisements,
 * caches advertised items and removes them when they are obsolete.
 */
typedef struct {
	GObject parent;

	int ifindex;
	char *ifname;
	GBytes *lladdr;

	NMRDiscDHCPLevel dhcp_level;
	GArray *gateways;
	GArray *addresses;
	GArray *routes;
	GArray *dns_servers;
	GArray *dns_domains;
} NMRDisc;

typedef struct {
	GObjectClass parent;

	void (*start) (NMRDisc *rdisc);
	void (*config_changed) (NMRDisc *rdisc, NMRDiscConfigMap changed);
} NMRDiscClass;

GType nm_rdisc_get_type (void);

void nm_rdisc_set_lladdr (NMRDisc *rdisc, const char *addr, size_t addrlen);
void nm_rdisc_start (NMRDisc *rdisc);

#endif /* NM_RDISC_H */