/* ipproto.h
 * Declarations of IP protocol numbers, and of routines for converting
 * IP protocol numbers into strings.
 *
 * $Id: ipproto.h,v 1.4 2001/11/13 23:55:29 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __IPPROTO_H__
#define __IPPROTO_H__

/*
 * IP protocol numbers.
 */
#define IP_PROTO_IP		0		/* dummy for IP */
#define IP_PROTO_HOPOPTS	0		/* IP6 hop-by-hop options */
#define IP_PROTO_ICMP		1		/* control message protocol */
#define IP_PROTO_IGMP		2		/* group mgmt protocol */
#define IP_PROTO_GGP		3		/* gateway^2 (deprecated) */
#define IP_PROTO_IPIP		4		/* IP inside IP */
#define IP_PROTO_IPV4		4		/* IP header */
#define IP_PROTO_TCP		6		/* tcp */
#define IP_PROTO_EGP		8		/* exterior gateway protocol */
#define IP_PROTO_IGRP		9
#define IP_PROTO_PUP		12		/* pup */
#define IP_PROTO_UDP		17		/* user datagram protocol */
#define IP_PROTO_IDP		22		/* xns idp */
#define IP_PROTO_TP		29 		/* tp-4 w/ class negotiation */
#define IP_PROTO_IPV6		41		/* IP6 header */
#define IP_PROTO_ROUTING	43		/* IP6 routing header */
#define IP_PROTO_FRAGMENT	44		/* IP6 fragmentation header */
#define IP_PROTO_RSVP           46              /* Resource ReSerVation protocol */
#define IP_PROTO_GRE		47		/* GRE */
#define IP_PROTO_ESP		50		/* ESP */
#define IP_PROTO_AH		51		/* AH */
#define IP_PROTO_ICMPV6		58		/* ICMP6 */
#define IP_PROTO_NONE		59		/* IP6 no next header */
#define IP_PROTO_DSTOPTS	60		/* IP6 no next header */
#define IP_PROTO_EON		80		/* ISO cnlp */
#define IP_PROTO_VINES		83		/* Vines over raw IP */
#define IP_PROTO_EIGRP		88
#define IP_PROTO_OSPF		89
#define IP_PROTO_ENCAP		98		/* encapsulation header */
#define IP_PROTO_PIM		103		/* Protocol Independent Mcast */
#define IP_PROTO_IPCOMP		108		/* IP payload compression */
#define IP_PROTO_VRRP		112		/* Virtual Router Redundancy Protocol */
#define IP_PROTO_PGM		113		/* Pragmatic General Multicast */
#define IP_PROTO_SCTP		132		/* Stream Control Transmission Protocol */

extern const char *ipprotostr(int proto);

#endif /* ipproto.h */
