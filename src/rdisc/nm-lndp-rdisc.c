/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-lndp-rdisc.c - Router discovery implementation using libndp
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

#include "config.h"

#include <string.h>
#include <arpa/inet.h>
/* stdarg.h included because of a bug in ndp.h */
#include <stdarg.h>
#include <ndp.h>

#include "nm-lndp-rdisc.h"
#include "nm-rdisc-private.h"

#include "NetworkManagerUtils.h"
#include "nm-default.h"
#include "nm-platform.h"

#include "nm-utils.h"
#include "nm-core-internal.h"

#include "nm-netns-controller.h"

#define _NMLOG_PREFIX_NAME                "rdisc-lndp"

typedef struct {
	struct ndp *ndp;

	NMNetns *netns;

	GIOChannel *event_channel;
	guint event_id;
	guint ra_timeout_id;  /* first RA timeout */
} NMLNDPRDiscPrivate;

#define NM_LNDP_RDISC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_LNDP_RDISC, NMLNDPRDiscPrivate))

G_DEFINE_TYPE (NMLNDPRDisc, nm_lndp_rdisc, NM_TYPE_RDISC)

/******************************************************************/

static gboolean
send_rs (NMRDisc *rdisc, GError **error)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	struct ndp_msg *msg;
	int errsv;

	errsv = ndp_msg_new (&msg, NDP_MSG_RS);
	if (errsv) {
		errsv = errsv > 0 ? errsv : -errsv;
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "cannot create router solicitation");
		return FALSE;
	}
	ndp_msg_ifindex_set (msg, rdisc->ifindex);

	nm_netns_controller_activate_netns(priv->netns);
	errsv = ndp_msg_send (priv->ndp, msg);
	nm_netns_controller_activate_root_netns();
	ndp_msg_destroy (msg);
	if (errsv) {
		errsv = errsv > 0 ? errsv : -errsv;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "%s (%d)",
		             g_strerror (errsv), errsv);
		return FALSE;
	}

	return TRUE;
}

static NMRDiscPreference
translate_preference (enum ndp_route_preference preference)
{
	switch (preference) {
	case NDP_ROUTE_PREF_LOW:
		return NM_RDISC_PREFERENCE_LOW;
	case NDP_ROUTE_PREF_MEDIUM:
		return NM_RDISC_PREFERENCE_MEDIUM;
	case NDP_ROUTE_PREF_HIGH:
		return NM_RDISC_PREFERENCE_HIGH;
	default:
		return NM_RDISC_PREFERENCE_INVALID;
	}
}

static void
pvd_dns_domain_free (gpointer data)
{
	g_free (((NMRDiscDNSDomain *)(data))->domain);
}

#define expiry(item) (item->timestamp + item->lifetime)

static void
pvd_dump (NMRDisc *rdisc, NMRDiscPVD *pvd)
{
	int i;
	char addrstr[INET6_ADDRSTRLEN];

	switch(pvd->pvdid.type) {
	case NDP_PVDID_TYPE_UUID:
		_LOGD ("PvD_ID type=%u id=%s", pvd->pvdid.type, pvd->pvdid.uuid);
		break;

	default:
		_LOGW ("received unrecognized PvD ID type %u", pvd->pvdid.type);
		break;
	}

	for (i = 0; i < pvd->gateways->len; i++) {
		NMRDiscGateway *gateway = &g_array_index (pvd->gateways, NMRDiscGateway, i);

		inet_ntop (AF_INET6, &gateway->address, addrstr, sizeof (addrstr));
		_LOGD ("  gateway %s pref %d exp %u", addrstr, gateway->preference, expiry (gateway));
	}
	for (i = 0; i < pvd->addresses->len; i++) {
		NMRDiscAddress *address = &g_array_index (pvd->addresses, NMRDiscAddress, i);

		inet_ntop (AF_INET6, &address->address, addrstr, sizeof (addrstr));
		_LOGD ("  address %s exp %u", addrstr, expiry (address));
	}
	for (i = 0; i < pvd->routes->len; i++) {
		NMRDiscRoute *route = &g_array_index (pvd->routes, NMRDiscRoute, i);

		inet_ntop (AF_INET6, &route->network, addrstr, sizeof (addrstr));
		_LOGD ("  route %s/%d via %s pref %d exp %u", addrstr, route->plen,
			nm_utils_inet6_ntop (&route->gateway, NULL), route->preference,
			expiry (route));
	}
	for (i = 0; i < pvd->dns_servers->len; i++) {
		NMRDiscDNSServer *dns_server = &g_array_index (pvd->dns_servers, NMRDiscDNSServer, i);

		inet_ntop (AF_INET6, &dns_server->address, addrstr, sizeof (addrstr));
		_LOGD ("  dns_server %s exp %u", addrstr, expiry (dns_server));
	}
	for (i = 0; i < pvd->dns_domains->len; i++) {
		NMRDiscDNSDomain *dns_domain = &g_array_index (pvd->dns_domains, NMRDiscDNSDomain, i);

		_LOGD ("  dns_domain %s exp %u", dns_domain->domain, expiry (dns_domain));
	}
}

/*
 * TODO: There is a function nm_ip6_config_hash() that might be used
 * instead of this one.
 */
static char *
pvd_generate_uuid (NMRDisc *rdisc, NMRDiscPVD *pvd)
{
	char buf[2048], *uuid;
	gssize buf_len = 0;
	int i;

	for (i = 0; i < pvd->routes->len; i++) {
		NMRDiscRoute *route = &g_array_index (pvd->routes, NMRDiscRoute, i);

		memcpy(buf + buf_len, &route->network, sizeof(route->network));
		buf_len += sizeof(route->network);
	}
	for (i = 0; i < pvd->dns_servers->len; i++) {
		NMRDiscDNSServer *dns_server = &g_array_index (pvd->dns_servers, NMRDiscDNSServer, i);

		memcpy(buf + buf_len, &dns_server->address, sizeof(dns_server->address));
		buf_len += sizeof(dns_server->address);
	}
	for (i = 0; i < pvd->dns_domains->len; i++) {
		NMRDiscDNSDomain *dns_domain = &g_array_index (pvd->dns_domains, NMRDiscDNSDomain, i);

		memcpy(buf + buf_len, &dns_domain->domain, strlen(dns_domain->domain));
		buf_len += sizeof(dns_domain->domain);
	}

	_LOGD("Data length in buffer to create UUID is %lu", buf_len);

	uuid = nm_utils_uuid_generate_from_string (buf, buf_len, NM_UTILS_UUID_TYPE_VARIANT3, NULL);

	_LOGD("Implicit PvD ID is %s", uuid);

	return uuid;
}

static int
receive_ra (struct ndp *ndp, struct ndp_msg *msg, gpointer user_data)
{
	NMRDisc *rdisc = (NMRDisc *) user_data;
	NMRDiscConfigMap changed = 0;
	struct ndp_msgra *msgra = ndp_msgra (msg);
	NMRDiscGateway gateway;
	guint32 now = nm_utils_get_monotonic_timestamp_s ();
	int offset, suboffset;
	int hop_limit;
	gboolean err;

	NMRDiscPVD *pvd;
	char *pvd_uuid;

	// Initialize PvD structure
	pvd = (NMRDiscPVD *)g_malloc0(sizeof(*pvd));

	pvd->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
	pvd->addresses = g_array_new (FALSE, FALSE, sizeof (NMRDiscAddress));
	pvd->routes = g_array_new (FALSE, FALSE, sizeof (NMRDiscRoute));
	pvd->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
	pvd->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
	g_array_set_clear_func (pvd->dns_domains, pvd_dns_domain_free);

	/* Router discovery is subject to the following RFC documents:
	 *
	 * http://tools.ietf.org/html/rfc4861
	 * http://tools.ietf.org/html/rfc4862
	 *
	 * The biggest difference from good old DHCP is that all configuration
	 * items have their own lifetimes and they are merged from various
	 * sources. Router discovery is *not* contract-based, so there is *no*
	 * single time when the configuration is finished and updates can
	 * come at any time.
	 */
	_LOGD ("received router advertisement at %u", now);

	/* DHCP level:
	 *
	 * The problem with DHCP level is what to do if subsequent
	 * router advertisements carry different flags. Currently we just
	 * rewrite the flag with every inbound RA.
	 */
	{
		NMRDiscDHCPLevel dhcp_level;

		if (ndp_msgra_flag_managed (msgra))
			dhcp_level = NM_RDISC_DHCP_LEVEL_MANAGED;
		else if (ndp_msgra_flag_other (msgra))
			dhcp_level = NM_RDISC_DHCP_LEVEL_OTHERCONF;
		else
			dhcp_level = NM_RDISC_DHCP_LEVEL_NONE;

		if (dhcp_level != rdisc->dhcp_level) {
			rdisc->dhcp_level = dhcp_level;
			changed |= NM_RDISC_CONFIG_DHCP_LEVEL;
		}
	}

	/* Default gateway:
	 *
	 * Subsequent router advertisements can represent new default gateways
	 * on the network. We should present all of them in router preference
	 * order.
	 */
	memset (&gateway, 0, sizeof (gateway));
	gateway.address = *ndp_msg_addrto (msg);
	gateway.timestamp = now;
	gateway.lifetime = ndp_msgra_router_lifetime (msgra);
	gateway.preference = translate_preference (ndp_msgra_route_preference (msgra));
	if (nm_rdisc_add_gateway (rdisc, &gateway))
		changed |= NM_RDISC_CONFIG_GATEWAYS;

	// TODO: If gateway.lifetime is 0 then the router is stopping and all the
	// configuration data sent by this router has to be removed!

	g_array_append_val(pvd->gateways, gateway);

	/* Addresses & Routes */
	ndp_msg_opt_for_each_offset (offset, msg, NDP_MSG_OPT_PREFIX) {
		NMRDiscRoute route;
		NMRDiscAddress address;

		/* Device route */
		memset (&route, 0, sizeof (route));
		route.plen = ndp_msg_opt_prefix_len (msg, offset);
		nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_prefix (msg, offset), route.plen);
		route.timestamp = now;
		if (ndp_msg_opt_prefix_flag_on_link (msg, offset)) {
			route.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
			if (nm_rdisc_add_route (rdisc, &route))
				changed |= NM_RDISC_CONFIG_ROUTES;
			g_array_append_val(pvd->routes, route);
		}

		/* Address */
		if (ndp_msg_opt_prefix_flag_auto_addr_conf (msg, offset)) {
			if (route.plen == 64) {
				memset (&address, 0, sizeof (address));
				address.address = route.network;
				address.timestamp = now;
				address.lifetime = ndp_msg_opt_prefix_valid_time (msg, offset);
				address.preferred = ndp_msg_opt_prefix_preferred_time (msg, offset);
				if (address.preferred > address.lifetime)
					address.preferred = address.lifetime;

				if (nm_rdisc_complete_and_add_address (rdisc, &address))
					changed |= NM_RDISC_CONFIG_ADDRESSES;

				g_array_append_val(pvd->addresses, address);
			}
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_ROUTE) {
		NMRDiscRoute route;

		/* Routers through this particular gateway */
		memset (&route, 0, sizeof (route));
		route.gateway = gateway.address;
		route.plen = ndp_msg_opt_route_prefix_len (msg, offset);
		nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_route_prefix (msg, offset), route.plen);
		route.timestamp = now;
		route.lifetime = ndp_msg_opt_route_lifetime (msg, offset);
		route.preference = translate_preference (ndp_msg_opt_route_preference (msg, offset));
		if (nm_rdisc_add_route (rdisc, &route))
			changed |= NM_RDISC_CONFIG_ROUTES;
		g_array_append_val(pvd->routes, route);
	}

	/* DNS information */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_RDNSS) {
		static struct in6_addr *addr;
		int addr_index;

		ndp_msg_opt_rdnss_for_each_addr (addr, addr_index, msg, offset) {
			NMRDiscDNSServer dns_server;

			memset (&dns_server, 0, sizeof (dns_server));
			dns_server.address = *addr;
			dns_server.timestamp = now;
			dns_server.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset);
			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like WiFi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_server.lifetime && dns_server.lifetime < 7200)
				dns_server.lifetime = 7200;
			if (nm_rdisc_add_dns_server (rdisc, &dns_server))
				changed |= NM_RDISC_CONFIG_DNS_SERVERS;

			g_array_append_val(pvd->dns_servers, dns_server);
		}
	}
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_DNSSL) {
		char *domain;
		int domain_index;

		ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, offset) {
			NMRDiscDNSDomain dns_domain, *item;

			memset (&dns_domain, 0, sizeof (dns_domain));
			dns_domain.domain = domain;
			dns_domain.timestamp = now;
			dns_domain.lifetime = ndp_msg_opt_rdnss_lifetime (msg, offset);
			/* Pad the lifetime somewhat to give a bit of slack in cases
			 * where one RA gets lost or something (which can happen on unreliable
			 * links like WiFi where certain types of frames are not retransmitted).
			 * Note that 0 has special meaning and is therefore not adjusted.
			 */
			if (dns_domain.lifetime && dns_domain.lifetime < 7200)
				dns_domain.lifetime = 7200;
			if (nm_rdisc_add_dns_domain (rdisc, &dns_domain))
				changed |= NM_RDISC_CONFIG_DNS_DOMAINS;

			g_array_append_val (pvd->dns_domains, dns_domain);
			item = &g_array_index (pvd->dns_domains, NMRDiscDNSDomain,
					pvd->dns_domains->len - 1);
			item->domain = g_strdup (domain);
		}
	}

	hop_limit = ndp_msgra_curhoplimit (msgra);
	if (rdisc->hop_limit != hop_limit) {
		rdisc->hop_limit = hop_limit;
		changed |= NM_RDISC_CONFIG_HOP_LIMIT;
	}

	/* MTU */
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_MTU) {
		guint32 mtu = ndp_msg_opt_mtu(msg, offset);
		if (mtu >= 1280) {
			rdisc->mtu = mtu;
			changed |= NM_RDISC_CONFIG_MTU;
			pvd->mtu = mtu;
		} else {
			/* All sorts of bad things would happen if we accepted this.
			 * Kernel would set it, but would flush out all IPv6 addresses away
			 * from the link, even the link-local, and we wouldn't be able to
			 * listen for further RAs that could fix the MTU. */
			_LOGW ("MTU too small for IPv6 ignored: %d", mtu);
		}
	}

	pvd_uuid = pvd_generate_uuid(rdisc, pvd);
	strncpy(pvd->pvdid.uuid, pvd_uuid, 36);
	g_free(pvd_uuid);

	pvd->pvdid.type = NDP_PVDID_TYPE_UUID;

	_LOGD("Received implicit PvD");
	pvd_dump(rdisc, pvd);

	if (g_hash_table_replace(rdisc->pvds, pvd, pvd))
		_LOGD("Received new implicit PvD");
	else
		_LOGD("Received existing implicit PvD");

	/*
	 * If something changed in RA then it certainly changed something
	 * in PvD, too.
	 */
	if (changed)
		changed |= NM_RDISC_CONFIG_PVD;

	/* PvD Container option */
	err = FALSE;
	ndp_msg_opt_for_each_offset(offset, msg, NDP_MSG_OPT_PVDCO) {

		/*
		 * TODO: It would be better to find PvD and then remove elements
		 * from it than to create a completely new structure and replace
		 * the old one. Replacing the old one we don't know what exactly
		 * changed and we are thus more inefficient.
		 */

		/*
		 * TODO: Gateway lifetime found in RA has to be takein into account
		 * also for PvDs received from the given gateway! This can be done
		 * in two ways: implicitly, when some router is removed, evertying
		 * that has the given gateway is removed; explicitly, every PvD has
		 * its own copy of router lifetime.
		 */

		_LOGD ("received PvD CO option");

		pvd = (NMRDiscPVD *)g_malloc0(sizeof(*pvd));

		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_PVDID, offset, NDP_MSG_OPT_PVDCO) {

			pvd->pvdid.type = ndp_msg_opt_pvdid_type(msg, suboffset);
			pvd->pvdid.len = ndp_msg_opt_pvdid_len(msg, suboffset);

			switch(pvd->pvdid.type) {
			case NDP_PVDID_TYPE_UUID:
				memcpy(pvd->pvdid.uuid, ndp_msg_opt_pvdid(msg, suboffset), pvd->pvdid.len);
				pvd->pvdid.uuid[pvd->pvdid.len + 1] = 0;
				break;

			default:
				_LOGW ("received unrecognized PvD ID type %u, skipping PvD CO", pvd->pvdid.type);
				err = true;
				break;
			}

			if (err)
				break;
		}

		if (err) {
			g_free(pvd);
			continue;
		}

		pvd->gateways = g_array_new (FALSE, FALSE, sizeof (NMRDiscGateway));
		pvd->addresses = g_array_new (FALSE, FALSE, sizeof (NMRDiscAddress));
		pvd->routes = g_array_new (FALSE, FALSE, sizeof (NMRDiscRoute));
		pvd->dns_servers = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSServer));
		pvd->dns_domains = g_array_new (FALSE, FALSE, sizeof (NMRDiscDNSDomain));
		g_array_set_clear_func (pvd->dns_domains, pvd_dns_domain_free);

		/*
		 * Add current gateway
		 *
		 * TODO: Note that we do not currently support the case in which there are
		 * two or more routers on the network announcing the same prefixes and
		 * routes. This was the "problem" even before the introduction of PvDs.
		 * Namely, each address created and added to a list of addresses has also
		 * a gateway information, so it's not possible to have two gateways for a
		 * single route.
		 */
		g_array_append_val(pvd->gateways, gateway);

		/* MTU */
		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_MTU, offset, NDP_MSG_OPT_PVDCO) {

			guint32 mtu = ndp_msg_opt_mtu(msg, suboffset);
			if (mtu >= 1280) {
				pvd->mtu = mtu;
			} else {
				/* All sorts of bad things would happen if we accepted this.
				 * Kernel would set it, but would flush out all IPv6 addresses away
				 * from the link, even the link-local, and we wouldn't be able to
				 * listen for further RAs that could fix the MTU. */
				_LOGW ("MTU too small for IPv6 ignored: %d", mtu);
			}
		}

		/* Addresses & Routes */
		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_PREFIX, offset, NDP_MSG_OPT_PVDCO) {
			NMRDiscRoute route;
			NMRDiscAddress address;

			memset (&route, 0, sizeof (route));
			memset (&address, 0, sizeof (address));

			/* Device route */
			memset (&route, 0, sizeof (route));
			route.plen = ndp_msg_opt_prefix_len (msg, suboffset);
			nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_prefix (msg, suboffset), route.plen);
			route.timestamp = now;
			if (ndp_msg_opt_prefix_flag_on_link (msg, suboffset)) {
				route.lifetime = ndp_msg_opt_prefix_valid_time (msg, suboffset);
				g_array_append_val (pvd->routes, route);
			}

			/* Address */
			if (ndp_msg_opt_prefix_flag_auto_addr_conf (msg, suboffset)) {
				if (route.plen == 64) {
					memset (&address, 0, sizeof (address));
					address.address = route.network;
					address.timestamp = now;
					address.lifetime = ndp_msg_opt_prefix_valid_time (msg, suboffset);
					address.preferred = ndp_msg_opt_prefix_preferred_time (msg, suboffset);
					if (address.preferred > address.lifetime)
						address.preferred = address.lifetime;

					g_array_append_val (pvd->addresses, address);
				}
			}
		}

		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_ROUTE, offset, NDP_MSG_OPT_PVDCO) {
			NMRDiscRoute route;

			/* Routers through this particular gateway */
			memset (&route, 0, sizeof (route));
			route.gateway = gateway.address;
			route.plen = ndp_msg_opt_route_prefix_len (msg, suboffset);
			nm_utils_ip6_address_clear_host_address (&route.network, ndp_msg_opt_route_prefix (msg, suboffset), route.plen);
			route.timestamp = now;
			route.lifetime = ndp_msg_opt_route_lifetime (msg, suboffset);
			route.preference = translate_preference (ndp_msg_opt_route_preference (msg, suboffset));
			g_array_append_val (pvd->routes, route);
		}

		/* DNS information */
		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_RDNSS, offset, NDP_MSG_OPT_PVDCO) {
			static struct in6_addr *addr;
			int addr_index;

			ndp_msg_opt_rdnss_for_each_addr (addr, addr_index, msg, suboffset) {
				NMRDiscDNSServer dns_server;

				memset (&dns_server, 0, sizeof (dns_server));
				dns_server.address = *addr;
				dns_server.timestamp = now;
				dns_server.lifetime = ndp_msg_opt_rdnss_lifetime (msg, suboffset);
				/* Pad the lifetime somewhat to give a bit of slack in cases
				 * where one RA gets lost or something (which can happen on unreliable
				 * links like WiFi where certain types of frames are not retransmitted).
				 * Note that 0 has special meaning and is therefore not adjusted.
				 */
				if (dns_server.lifetime && dns_server.lifetime < 7200)
					dns_server.lifetime = 7200;
				g_array_append_val (pvd->dns_servers, dns_server);
			}
		}

		ndp_msg_subopt_for_each_suboffset(suboffset, msg,
				NDP_MSG_OPT_DNSSL, offset, NDP_MSG_OPT_PVDCO) {
			char *domain;
			int domain_index;
			NMRDiscDNSDomain *item;

			ndp_msg_opt_dnssl_for_each_domain (domain, domain_index, msg, suboffset) {
				NMRDiscDNSDomain dns_domain;

				memset (&dns_domain, 0, sizeof (dns_domain));
				dns_domain.domain = domain;
				dns_domain.timestamp = now;
				dns_domain.lifetime = ndp_msg_opt_rdnss_lifetime (msg, suboffset);
				/* Pad the lifetime somewhat to give a bit of slack in cases
				 * where one RA gets lost or something (which can happen on unreliable
				 * links like WiFi where certain types of frames are not retransmitted).
				 * Note that 0 has special meaning and is therefore not adjusted.
				 */
				if (dns_domain.lifetime && dns_domain.lifetime < 7200)
					dns_domain.lifetime = 7200;

				g_array_append_val (pvd->dns_domains, dns_domain);
				item = &g_array_index (pvd->dns_domains, NMRDiscDNSDomain,
						pvd->dns_domains->len - 1);
				item->domain = g_strdup (domain);

			}
		}

		pvd_dump(rdisc, pvd);

		if (g_hash_table_replace(rdisc->pvds, pvd, pvd))
			_LOGD("Received new explicit PvD");
		else
			_LOGD("Received existing explicit PvD");

		/*
		 * Mark that PvD changed (TODO: Maybe it isn't, like it
		 * might happen in RA!)
		 */
		changed |= NM_RDISC_CONFIG_PVD;
	}

	nm_rdisc_ra_received (rdisc, now, changed);
	return 0;
}

static gboolean
event_ready (GIOChannel *source, GIOCondition condition, NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	_LOGD ("Processing libndp events");
	nm_netns_controller_activate_netns(priv->netns);
	ndp_callall_eventfd_handler (priv->ndp);
	nm_netns_controller_activate_root_netns();
	return G_SOURCE_CONTINUE;
}

static void
start (NMRDisc *rdisc)
{
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	int fd = ndp_get_eventfd (priv->ndp);

	priv->event_channel = g_io_channel_unix_new (fd);
	priv->event_id = g_io_add_watch (priv->event_channel, G_IO_IN, (GIOFunc) event_ready, rdisc);

	/* Flush any pending messages to avoid using obsolete information */
	event_ready (priv->event_channel, 0, rdisc);

	nm_netns_controller_activate_netns(priv->netns);
	ndp_msgrcv_handler_register (priv->ndp, receive_ra, NDP_MSG_RA, rdisc->ifindex, rdisc);
	nm_netns_controller_activate_root_netns();
}

/******************************************************************/

static inline gint32
ipv6_sysctl_get (const char *ifname, const char *property, gint32 defval)
{
	return nm_platform_sysctl_get_int32 (NM_PLATFORM_GET, nm_utils_ip6_property_path (ifname, property), defval);
}

NMRDisc *
nm_lndp_rdisc_new (NMNetns *netns,
                   int ifindex,
                   const char *ifname,
                   const char *uuid,
                   NMSettingIP6ConfigAddrGenMode addr_gen_mode,
                   GError **error)
{
	NMRDisc *rdisc;
	NMLNDPRDiscPrivate *priv;
	int errsv;

	g_return_val_if_fail (!error || !*error, NULL);

	rdisc = g_object_new (NM_TYPE_LNDP_RDISC, NULL);

	rdisc->ifindex = ifindex;
	rdisc->ifname = g_strdup (ifname);
	rdisc->uuid = g_strdup (uuid);
	rdisc->addr_gen_mode = addr_gen_mode;

	rdisc->max_addresses = ipv6_sysctl_get (ifname, "max_addresses",
	                                        NM_RDISC_MAX_ADDRESSES_DEFAULT);
	rdisc->rtr_solicitations = ipv6_sysctl_get (ifname, "router_solicitations",
	                                            NM_RDISC_RTR_SOLICITATIONS_DEFAULT);
	rdisc->rtr_solicitation_interval = ipv6_sysctl_get (ifname, "router_solicitation_interval",
	                                                    NM_RDISC_RTR_SOLICITATION_INTERVAL_DEFAULT);

	priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);
	priv->netns = netns;
	g_object_ref(priv->netns);

	nm_netns_controller_activate_netns(priv->netns);
	errsv = ndp_open (&priv->ndp);
	nm_netns_controller_activate_root_netns();

	if (errsv != 0) {
		errsv = errsv > 0 ? errsv : -errsv;
		g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		             "failure creating libndp socket: %s (%d)",
		             g_strerror (errsv), errsv);
		g_object_unref (rdisc);
		return NULL;
	}
	return rdisc;
}

static void
nm_lndp_rdisc_init (NMLNDPRDisc *lndp_rdisc)
{
}

static void
dispose (GObject *object)
{
	NMLNDPRDisc *rdisc = NM_LNDP_RDISC (object);
	NMLNDPRDiscPrivate *priv = NM_LNDP_RDISC_GET_PRIVATE (rdisc);

	nm_clear_g_source (&priv->event_id);
	g_clear_pointer (&priv->event_channel, g_io_channel_unref);

	if (priv->ndp) {
		ndp_msgrcv_handler_unregister (priv->ndp, receive_ra, NDP_MSG_RA, NM_RDISC (rdisc)->ifindex, rdisc);
		ndp_close (priv->ndp);
		priv->ndp = NULL;
	}

	G_OBJECT_CLASS (nm_lndp_rdisc_parent_class)->dispose (object);
}

static void
nm_lndp_rdisc_class_init (NMLNDPRDiscClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMRDiscClass *rdisc_class = NM_RDISC_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMLNDPRDiscPrivate));

	object_class->dispose = dispose;
	rdisc_class->start = start;
	rdisc_class->send_rs = send_rs;
}
