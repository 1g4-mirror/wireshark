/* packet-pim.c
 * Routines for PIM disassembly
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id: packet-pim.c,v 1.39 2002/02/01 07:06:32 guy Exp $
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

#ifdef HAVE_CONFIG_H 
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stddef.h>  /* For offsetof */
#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "ipproto.h"
#include "afn.h"
#include "packet-ipv6.h"
#include "in_cksum.h"

#define PIM_TYPE(x)	((x) & 0x0f)
#define PIM_VER(x)	(((x) & 0xf0) >> 4)

enum pimv2_addrtype {
	pimv2_unicast, pimv2_group, pimv2_source
};

static int proto_pim = -1;
static int hf_pim_version = -1;
static int hf_pim_type = -1;
static int hf_pim_code = -1;
static int hf_pim_cksum = -1;

static gint ett_pim = -1;

static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;

/*
 * For PIM v1, see the PDF slides at
 *
 *	http://www.mbone.de/training/Module3.pdf
 *
 * Is it documented anywhere else?
 */
static const char *
dissect_pimv1_addr(tvbuff_t *tvb, int offset) {
    static char buf[512];
    guint16 flags_masklen;

    flags_masklen = tvb_get_ntohs(tvb, offset);
    if (flags_masklen & 0x0180) {
	(void)snprintf(buf, sizeof(buf),
	    "(%s%s%s) ",
	    flags_masklen & 0x0100 ? "S" : "",
	    flags_masklen & 0x0080 ? "W" : "",
	    flags_masklen & 0x0040 ? "R" : "");
    } else
	buf[0] = '\0';
    (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s/%u",
	ip_to_str(tvb_get_ptr(tvb, offset + 2, 4)), flags_masklen & 0x3f);

    return buf;
}

static const value_string type1vals[] = {
    { 0, "Query" },
    { 1, "Register" },
    { 2, "Register-stop" },
    { 3, "Join/Prune" },
    { 4, "RP-Reachable" },
    { 5, "Assert" },
    { 6, "Graft" },
    { 7, "Graft-Ack" },
    { 8, "Mode" },
    { 0, NULL },
};

/* This function is only called from the IGMP dissector */
int
dissect_pimv1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	      int offset) {
    guint8 pim_type;
    guint8 pim_ver;
    guint length, pim_length;
    guint16 pim_cksum, computed_cksum;
    vec_t cksum_vec[1];
    proto_tree *pim_tree = NULL;
    proto_item *ti; 
    proto_tree *pimopt_tree = NULL;
    proto_item *tiopt; 

    if (!proto_is_protocol_enabled(proto_pim)) {
	/*
	 * We are not enabled; skip entire packet to be nice to the
	 * IGMP layer (so clicking on IGMP will display the data).
	 */
	return offset+tvb_length_remaining(tvb, offset);
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PIMv1");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
	ti = proto_tree_add_item(tree, proto_pim, tvb, offset, -1, FALSE);
	pim_tree = proto_item_add_subtree(ti, ett_pim);

	/* Put IGMP type, 0x14, into the tree */
	proto_tree_add_text(pim_tree, tvb, offset, 1,
	    "Type: PIM (0x14)");
    }
    offset += 1;

    pim_type = tvb_get_guint8(tvb, offset);
    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO,
	    val_to_str(pim_type, type1vals, "Unknown (%u)"));

    if (tree) {
	proto_tree_add_uint(pim_tree, hf_pim_code, tvb, offset, 1, pim_type);
    }
    offset += 1;

    pim_cksum = tvb_get_ntohs(tvb, offset);
    pim_ver = PIM_VER(tvb_get_guint8(tvb, offset + 2));
    if (pim_ver != 1) {
	/*
	 * Not PIMv1 - what gives?
	 */
    	if (tree) {
	    proto_tree_add_uint(pim_tree, hf_pim_cksum, tvb,
		    offset, 2, pim_cksum);
	}
	offset += 2;
    	if (tree)
	    proto_tree_add_uint(pim_tree, hf_pim_version, tvb, offset, 1, pim_ver);
	return offset+tvb_length_remaining(tvb, offset);
    }

    /*
     * Well, it's PIM v1, so we can check whether this is a
     * Register message, and thus can figure out how much to
     * checksum and whether to make the columns read-only.
     */
    length = tvb_length(tvb);
    if (pim_type == 1) {
	/*
	 * Register message - the PIM header is 8 bytes long.
	 * Also set the columns non-writable. Otherwise the IPv4 or
	 * IPv6 dissector for the encapsulated packet that caused
	 * this register will overwrite the PIM info in the columns.
	 */
	pim_length = 8;
	col_set_writable(pinfo->cinfo, FALSE);
    } else {
	/*
	 * Other message - checksum the entire packet.
	 */
	pim_length = tvb_reported_length(tvb);
    }

    if (tree) {
	if (!pinfo->fragmented && length >= pim_length) {
	    /*
	     * The packet isn't part of a fragmented datagram and isn't
	     * truncated, so we can checksum it.
	     */
	    cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, pim_length);
	    cksum_vec[0].len = pim_length;
	    computed_cksum = in_cksum(&cksum_vec[0], 1);
	    if (computed_cksum == 0) {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			    offset, 2, pim_cksum,
			    "Checksum: 0x%04x (correct)",
			    pim_cksum);
	    } else {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			    offset, 2, pim_cksum,
			    "Checksum: 0x%04x (incorrect, should be 0x%04x)",
			    pim_cksum, in_cksum_shouldbe(pim_cksum, computed_cksum));
	    }
	} else {
	    proto_tree_add_uint(pim_tree, hf_pim_cksum, tvb,
		    offset, 2, pim_cksum);
        }
    }
    offset += 2;

    if (tree)
	proto_tree_add_uint(pim_tree, hf_pim_version, tvb, offset, 1, pim_ver);
    offset += 1;

    offset += 3;	/* skip reserved stuff */

    if (tree) {
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
	    tiopt = proto_tree_add_text(pim_tree, tvb, offset, -1,
		    "PIM parameters");
	    pimopt_tree = proto_item_add_subtree(tiopt, ett_pim);
	} else
	    goto done;

	/* version 1 decoder */
	switch (pim_type) {
	case 0:	/* query */
	  {
	    guint8 mode;
	    guint16 holdtime;
	    static const value_string pimv1_modevals[] = {
		{ 0, "Dense" },
		{ 1, "Sparse" },
		{ 2, "Sparse-Dense" },
		{ 0, NULL },
	    };

	    mode = tvb_get_guint8(tvb, offset) >> 4;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Mode: %s",
		val_to_str(mode, pimv1_modevals, "Unknown (%u)"));
	    offset += 2;
	    holdtime = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Holdtime: %u%s", holdtime,
		holdtime == 0xffff ? " (infty)" : "");
	    offset += 2;
	    break;
	  }

	case 1:	/* register */
	  {
	    guint8 v_hl;
	    tvbuff_t *next_tvb;

	    /*
	     * The rest of the packet is a multicast data packet.
	     */
	    next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	    /*
	     * It's an IP packet - determine whether it's IPv4 or IPv6.
	     */
	    v_hl = tvb_get_guint8(tvb, offset);
	    switch((v_hl & 0xf0) >> 4) {
	    case 0:     /* Null-Register dummy header.
			 * Has the same address family as the encapsulating PIM packet,
			 * e.g. an IPv6 data packet is encapsulated in IPv6 PIM packet.
			 */
		    if (pinfo->src.type == AT_IPv4) {
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"IPv4 dummy header");
			    proto_tree_add_text(pimopt_tree, tvb, offset + 12, 4,
						"Source: %s",
						ip_to_str(tvb_get_ptr(tvb, offset + 12, 4)));
			    proto_tree_add_text(pimopt_tree, tvb, offset + 16, 4,
						"Group: %s",
						ip_to_str(tvb_get_ptr(tvb, offset + 16, 4)));
		    } else if (pinfo->src.type == AT_IPv6) {
			    struct ip6_hdr ip6_hdr;
			    tvb_memcpy(tvb, (guint8 *)&ip6_hdr, offset,
				       sizeof ip6_hdr);
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"IPv6 dummy header");
			    proto_tree_add_text(pimopt_tree, tvb,
						offset + offsetof(struct ip6_hdr, ip6_src), 16,
						"Source: %s",
						ip6_to_str(&ip6_hdr.ip6_src));
			    proto_tree_add_text(pimopt_tree, tvb,
						offset + offsetof(struct ip6_hdr, ip6_dst), 16,
						"Group: %s",
						ip6_to_str(&ip6_hdr.ip6_dst));
		    } else
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"Dummy header for an unknown protocol");
		    break;
	    case 4:	/* IPv4 */
#if 0
		    call_dissector(ip_handle, next_tvb, pinfo, tree);
#else
		    call_dissector(ip_handle, next_tvb, pinfo, pimopt_tree);
#endif
		    break;
	    case 6:	/* IPv6 */
#if 0
		    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
#else
		    call_dissector(ipv6_handle, next_tvb, pinfo, pimopt_tree);
#endif
		    break;
	    default:
		    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
			"Unknown IP version %d", (v_hl & 0xf0) >> 4);
		    break;
	    }
	    break;
	  }

	case 2:	/* register-stop */
	  {
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Group: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Source: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;
	    break;
	  }

	case 3:	/* join/prune */
	case 6:	/* graft */
	case 7:	/* graft-ack */
	  {
	    int off;
	    const char *s;
	    int ngroup, i, njoin, nprune, j;
	    guint16 holdtime;
	    guint8 mask_len;
	    guint8 adr_len;
	    proto_tree *grouptree = NULL;
	    proto_item *tigroup; 
	    proto_tree *subtree = NULL;
	    proto_item *tisub; 

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
		"Upstream-neighbor: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    offset += 2;	/* skip reserved stuff */

	    holdtime = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Holdtime: %u%s", holdtime,
		holdtime == 0xffff ? " (infty)" : "");
	    offset += 2;

	    offset += 1;	/* skip reserved stuff */

	    mask_len = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Mask length: %u", mask_len);
	    offset += 1;

	    adr_len = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Address length: %u", adr_len);
	    offset += 1;

	    ngroup = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Groups: %u", ngroup);
	    offset += 1;

	    for (i = 0; i < ngroup; i++) {
		tigroup = proto_tree_add_text(pimopt_tree, tvb, offset, 4,
		    "Group %d: %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		grouptree = proto_item_add_subtree(tigroup, ett_pim);
		offset += 4;

		proto_tree_add_text(grouptree, tvb, offset, 4,
		    "Group %d Mask: %s", i,
		    ip_to_str(tvb_get_ptr(tvb, offset, 4)));
		offset += 4;

		njoin = tvb_get_ntohs(tvb, offset);
		nprune = tvb_get_ntohs(tvb, offset + 2);

		tisub = proto_tree_add_text(grouptree, tvb, offset, 2,
		    "Join: %d", njoin);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		off = offset + 4;
		for (j = 0; j < njoin; j++) {
		    s = dissect_pimv1_addr(tvb, off);
		    proto_tree_add_text(subtree, tvb, off, 6,
			"IP address: %s", s);
		    off += 6;
		}

		tisub = proto_tree_add_text(grouptree, tvb, offset + 2, 2,
		    "Prune: %d", nprune);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		for (j = 0; j < nprune; j++) {
		    s = dissect_pimv1_addr(tvb, off);
		    proto_tree_add_text(subtree, tvb, off, 6,
			"IP address: %s", s);
		    off += 6;
		}
	    }
	    break;
	  }

	case 4:	/* rp-reachability */
	  {
	    guint16 holdtime;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Group Address: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Group Mask: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "RP Address: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    offset += 2;	/* skip reserved stuff */

	    holdtime = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Holdtime: %u%s", holdtime,
		holdtime == 0xffff ? " (infty)" : "");
	    offset += 2;
	    break;
	  }

	case 5:	/* assert */
	  {
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Group Address: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4,
	        "Group Mask: %s",
		ip_to_str(tvb_get_ptr(tvb, offset, 4)));
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(tvb_get_guint8(tvb, offset), 0x80, 8,
		    "RP Tree", "Not RP Tree"));
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Preference: %u",
		tvb_get_ntohl(tvb, offset) & 0x7fffffff);
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Metric: %u",
		tvb_get_ntohl(tvb, offset));

	    break;
	  }

	default:
	    break;
	}
    }
done:;

    return offset+tvb_length_remaining(tvb, offset);
}

static const char *
dissect_pim_addr(tvbuff_t *tvb, int offset, enum pimv2_addrtype at,
	int *advance) {
    static char buf[512];
    guint8 af;
    guint8 et;
    guint8 flags;
    guint8 mask_len;
    int len = 0;

    af = tvb_get_guint8(tvb, offset);
    if (af != AFNUM_INET && af != AFNUM_INET6) {
	/*
	 * We don't handle the other formats, and addresses don't include
	 * a length field, so we can't even show them as raw bytes.
	 */
	return NULL;
    }

    et = tvb_get_guint8(tvb, offset + 1);
    if (et != 0) {
	/*
	 * The only defined encoding type is 0, for the native encoding;
	 * again, as addresses don't include a length field, we can't
	 * even show addresses with a different encoding type as raw
	 * bytes.
	 */
	return NULL;
    }

    switch (at) {
    case pimv2_unicast:
	switch (af) {
	case AFNUM_INET:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s",
	        ip_to_str(tvb_get_ptr(tvb, offset + 2, len)));
	    break;

	case AFNUM_INET6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 2, len)));
	    break;
	}
	if (advance)
	    *advance = 2 + len;
	break;

    case pimv2_group:
	mask_len = tvb_get_guint8(tvb, offset + 3);
	switch (af) {
	case AFNUM_INET:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip_to_str(tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;

	case AFNUM_INET6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;
	}
	if (advance)
	    *advance = 4 + len;
	break;

    case pimv2_source:
	flags = tvb_get_guint8(tvb, offset + 2);
	mask_len = tvb_get_guint8(tvb, offset + 3);
	switch (af) {
	case AFNUM_INET:
	    len = 4;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip_to_str(tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;

	case AFNUM_INET6:
	    len = 16;
	    (void)snprintf(buf, sizeof(buf), "%s/%u",
		ip6_to_str((struct e_in6_addr *)tvb_get_ptr(tvb, offset + 4, len)), mask_len);
	    break;
	}
	if (flags) {
	    (void)snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		" (%s%s%s)",
		flags & 0x04 ? "S" : "",
		flags & 0x02 ? "W" : "",
		flags & 0x01 ? "R" : "");
	}
	if (advance)
	    *advance = 4 + len;
	break;
    default:
	return NULL;
    }

    return buf;
}

static const value_string type2vals[] = {
    { 0, "Hello" },
    { 1, "Register" },
    { 2, "Register-stop" },
    { 3, "Join/Prune" },
    { 4, "Bootstrap" },
    { 5, "Assert" },
    { 6, "Graft" },
    { 7, "Graft-Ack" },
    { 8, "Candidate-RP-Advertisement" },
    { 0, NULL },
};

/*
 * For PIM v2, see RFC 2362, and draft-ietf-pim-sm-v2-new-03 (when PIM
 * is run over IPv6, the rules for computing the PIM checksum from the
 * draft in question, not from RFC 2362, should be used).
 */
static void 
dissect_pim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int offset = 0;
    guint8 pim_typever;
    guint length, pim_length;
    guint16 pim_cksum, computed_cksum;
    vec_t cksum_vec[4];
    guint32 phdr[2];
    char *typestr;
    proto_tree *pim_tree = NULL;
    proto_item *ti; 
    proto_tree *pimopt_tree = NULL;
    proto_item *tiopt; 

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "PIM");
    if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

    pim_typever = tvb_get_guint8(tvb, 0);

    switch (PIM_VER(pim_typever)) {
    case 2:
	typestr = val_to_str(PIM_TYPE(pim_typever), type2vals, "Unknown (%u)");
	break;
    case 1:	/* PIMv1 - we should never see this */
    default:
	typestr = "Unknown";
	break;
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "PIMv%d",
	    PIM_VER(pim_typever));
    }
    if (check_col(pinfo->cinfo, COL_INFO))
	col_add_str(pinfo->cinfo, COL_INFO, typestr); 

    if (tree) {
	ti = proto_tree_add_item(tree, proto_pim, tvb, offset, -1, FALSE);
	pim_tree = proto_item_add_subtree(ti, ett_pim);

	proto_tree_add_uint(pim_tree, hf_pim_version, tvb, offset, 1,
	    PIM_VER(pim_typever)); 
	proto_tree_add_uint(pim_tree, hf_pim_type, tvb, offset, 1,
	    PIM_TYPE(pim_typever)); 

	pim_cksum = tvb_get_ntohs(tvb, offset + 2);
	length = tvb_length(tvb);
	if (PIM_VER(pim_typever) == 2) {
	    /*
	     * Well, it's PIM v2, so we can check whether this is a Register
	     * message, and thus can figure out how much to checksum and
	     * whether to make the columns read-only.
	     */
	    if (PIM_TYPE(pim_typever) == 1) {
		/*
		 * Register message - the PIM header is 8 bytes long.
		 * Also set the columns non-writable. Otherwise the IPv4 or
		 * IPv6 dissector for the encapsulated packet that caused
		 * this register will overwrite the PIM info in the columns.
		 */
		pim_length = 8;
		col_set_writable(pinfo->cinfo, FALSE);
	    } else {
		/*
		 * Other message - checksum the entire packet.
		 */
		pim_length = tvb_reported_length(tvb);
	    }
	} else {
	    /*
	     * We don't know what type of message this is, so say that
	     * the length is 0, to force it not to be checksummed.
	     */
	    pim_length = 0;
	}
	if (!pinfo->fragmented && length >= pim_length) {
	    /*
	     * The packet isn't part of a fragmented datagram and isn't
	     * truncated, so we can checksum it.
	     */

	    switch (pinfo->src.type) {
	    case AT_IPv4:
		cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, pim_length);
		cksum_vec[0].len = pim_length;
		computed_cksum = in_cksum(&cksum_vec[0], 1);
		break;
	    case AT_IPv6:
		/* Set up the fields of the pseudo-header. */
		cksum_vec[0].ptr = pinfo->src.data;
		cksum_vec[0].len = pinfo->src.len;
		cksum_vec[1].ptr = pinfo->dst.data;
		cksum_vec[1].len = pinfo->dst.len;
		cksum_vec[2].ptr = (const guint8 *)&phdr;
		phdr[0] = htonl(pim_length);
		phdr[1] = htonl(IP_PROTO_PIM);
		cksum_vec[2].len = 8;
		cksum_vec[3].ptr = tvb_get_ptr(tvb, 0, pim_length);
		cksum_vec[3].len = pim_length;
		computed_cksum = in_cksum(&cksum_vec[0], 4);
		break;
	    default:
	    	/* PIM is available for IPv4 and IPv6 right now */
	    	computed_cksum = 0;	/* squelch GCC complaints */
		g_assert_not_reached();
		break;
	    }

	    if (computed_cksum == 0) {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			offset + 2, 2, pim_cksum,
			"Checksum: 0x%04x (correct)",
			pim_cksum);
	    } else {
		proto_tree_add_uint_format(pim_tree, hf_pim_cksum, tvb,
			offset + 2, 2, pim_cksum,
			"Checksum: 0x%04x (incorrect, should be 0x%04x)",
			pim_cksum, in_cksum_shouldbe(pim_cksum, computed_cksum));
	    }
	} else {
	    proto_tree_add_uint(pim_tree, hf_pim_cksum, tvb,
		offset + 2, 2, pim_cksum);
	}

	offset += 4;

	if (tvb_reported_length_remaining(tvb, offset) > 0) {
	    tiopt = proto_tree_add_text(pim_tree, tvb, offset, -1,
	        "PIM parameters");
	    pimopt_tree = proto_item_add_subtree(tiopt, ett_pim);
	} else
	    goto done;

	if (PIM_VER(pim_typever) != 2)
	    goto done;

	/* version 2 decoder */
	switch (PIM_TYPE(pim_typever)) {
	case 0:	/*hello*/
	  {
	    while (tvb_reported_length_remaining(tvb, offset) >= 2) {
		if (tvb_get_ntohs(tvb, offset) == 1 &&
		    tvb_get_ntohs(tvb, offset + 2) == 2) {
		    guint16 holdtime;

		    holdtime = tvb_get_ntohs(tvb, offset + 4);
		    proto_tree_add_text(pimopt_tree, tvb, offset, 6,
			"Holdtime: %u%s", holdtime,
			holdtime == 0xffff ? " (infty)" : "");
		    offset += 6;
		} else
		    break;
	    }
	    break;
	  }

	case 1:	/* register */
	  {
	    guint32 flags;
	    guint8 v_hl;
	    tvbuff_t *next_tvb;
	    proto_tree *flag_tree = NULL;
	    proto_item *tiflag; 

	    flags = tvb_get_ntohl(tvb, offset);
	    tiflag = proto_tree_add_text(pimopt_tree, tvb, offset, 4,
		"Flags: 0x%08x", flags);
	    flag_tree = proto_item_add_subtree(tiflag, ett_pim);
	    proto_tree_add_text(flag_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(flags, 0x80000000, 32,
		    "Border", "Not border"));
	    proto_tree_add_text(flag_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(flags, 0x40000000, 32,
		    "Null-Register", "Not Null-Register"));
	    offset += 4;
	    
	    /*
	     * The rest of the packet is a multicast data packet.
	     */
	    next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	    /*
	     * It's an IP packet - determine whether it's IPv4 or IPv6.
	     */
	    v_hl = tvb_get_guint8(tvb, offset);
	    switch((v_hl & 0xf0) >> 4) {
	    case 0:     /* Null-Register dummy header.
			 * Has the same address family as the encapsulating PIM packet,
			 * e.g. an IPv6 data packet is encapsulated in IPv6 PIM packet.
			 */
		    if (pinfo->src.type == AT_IPv4) {
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"IPv4 dummy header");
			    proto_tree_add_text(pimopt_tree, tvb, offset + 12, 4,
						"Source: %s",
						ip_to_str(tvb_get_ptr(tvb, offset + 12, 4)));
			    proto_tree_add_text(pimopt_tree, tvb, offset + 16, 4,
						"Group: %s",
						ip_to_str(tvb_get_ptr(tvb, offset + 16, 4)));
		    } else if (pinfo->src.type == AT_IPv6) {
			    struct ip6_hdr ip6_hdr;
			    tvb_memcpy(tvb, (guint8 *)&ip6_hdr, offset,
				       sizeof ip6_hdr);
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"IPv6 dummy header");
			    proto_tree_add_text(pimopt_tree, tvb,
						offset + offsetof(struct ip6_hdr, ip6_src), 16,
						"Source: %s",
						ip6_to_str(&ip6_hdr.ip6_src));
			    proto_tree_add_text(pimopt_tree, tvb,
						offset + offsetof(struct ip6_hdr, ip6_dst), 16,
						"Group: %s",
						ip6_to_str(&ip6_hdr.ip6_dst));
		    } else
			    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
						"Dummy header for an unknown protocol");
		    break;
	    case 4:	/* IPv4 */
#if 0
		    call_dissector(ip_handle, next_tvb, pinfo, tree);
#else
		    call_dissector(ip_handle, next_tvb, pinfo, pimopt_tree);
#endif
		    break;
	    case 6:	/* IPv6 */
#if 0
		    call_dissector(ipv6_handle, next_tvb, pinfo, tree);
#else
		    call_dissector(ipv6_handle, next_tvb, pinfo, pimopt_tree);
#endif
		    break;
	    default:
		    proto_tree_add_text(pimopt_tree, tvb, offset, -1,
			"Unknown IP version %d", (v_hl & 0xf0) >> 4);
		    break;
	    }
	    break;
	  }

	case 2:	/* register-stop */
	  {
	    int advance;
	    const char *s;

	    s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Group: %s", s);
	    offset += advance;
	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Source: %s", s);
	    break;
	  }

	case 3:	/* join/prune */
	case 6:	/* graft */
	case 7:	/* graft-ack */
	  {
	    int advance;
	    int off;
	    const char *s;
	    int ngroup, i, njoin, nprune, j;
	    guint16 holdtime;
	    proto_tree *grouptree = NULL;
	    proto_item *tigroup; 
	    proto_tree *subtree = NULL;
	    proto_item *tisub; 

	    if (PIM_TYPE(pim_typever) != 7) {
		/* not graft-ack */
		s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
		if (s == NULL)
		    break;
		proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Upstream-neighbor: %s", s);
		offset += advance;
	    }

	    offset += 1;	/* skip reserved field */

	    ngroup = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Groups: %u", ngroup);
	    offset += 1;

	    if (PIM_TYPE(pim_typever) != 7)	{
		/* not graft-ack */
		holdtime = tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		    "Holdtime: %u%s", holdtime,
		    holdtime == 0xffff ? " (infty)" : "");
	    }
	    offset += 2;

	    for (i = 0; i < ngroup; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak3;
		tigroup = proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ett_pim);
		offset += advance;

		njoin = tvb_get_ntohs(tvb, offset);
		nprune = tvb_get_ntohs(tvb, offset + 2);

		tisub = proto_tree_add_text(grouptree, tvb, offset, 2,
		    "Join: %d", njoin);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		off = offset + 4;
		for (j = 0; j < njoin; j++) {
		    s = dissect_pim_addr(tvb, off, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, tvb, off, advance,
			"IP address: %s", s);
		    off += advance;
		}

		tisub = proto_tree_add_text(grouptree, tvb, offset + 2, 2,
		    "Prune: %d", nprune);
		subtree = proto_item_add_subtree(tisub, ett_pim);
		for (j = 0; j < nprune; j++) {
		    s = dissect_pim_addr(tvb, off, pimv2_source,
			&advance);
		    if (s == NULL)
			goto breakbreak3;
		    proto_tree_add_text(subtree, tvb, off, advance,
			"IP address: %s", s);
		    off += advance;
		}
	    }
    breakbreak3:
	    break;
	  }

	case 4:	/* bootstrap */
	  {
	    const char *s;
	    int advance;
	    int i, j;
	    int frpcnt;
	    guint16 holdtime;
	    proto_tree *grouptree = NULL;
	    proto_item *tigroup; 

	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Fragment tag: 0x%04x", tvb_get_ntohs(tvb, offset));
	    offset += 2;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Hash mask len: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"BSR priority: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "BSR: %s", s);
	    offset += advance;

	    for (i = 0; tvb_reported_length_remaining(tvb, offset) > 0; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak4;
		tigroup = proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		grouptree = proto_item_add_subtree(tigroup, ett_pim);
		offset += advance;

		proto_tree_add_text(grouptree, tvb, offset, 1,
		    "RP count: %u", tvb_get_guint8(tvb, offset));
		offset += 1;
		frpcnt = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(grouptree, tvb, offset, 1,
		    "FRP count: %u", frpcnt);
		offset += 3;

		for (j = 0; j < frpcnt; j++) {
		    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
		    if (s == NULL)
			goto breakbreak4;
		    proto_tree_add_text(grouptree, tvb, offset, advance,
			"RP %d: %s", j, s);
		    offset += advance;

		    holdtime = tvb_get_ntohs(tvb, offset);
		    proto_tree_add_text(grouptree, tvb, offset, 2,
			"Holdtime: %u%s", holdtime,
			holdtime == 0xffff ? " (infty)" : "");
		    offset += 2;
		    proto_tree_add_text(grouptree, tvb, offset, 1,
			"Priority: %u", tvb_get_guint8(tvb, offset));
		    offset += 2;	/* also skips reserved field */
		}
	    }

    breakbreak4:
	    break;
	  }

	case 5:	/* assert */
	  {
	    const char *s;
	    int advance;

	    s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Group: %s", s);
	    offset += advance;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "Source: %s", s);
	    offset += advance;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 1, "%s",
		decode_boolean_bitfield(tvb_get_guint8(tvb, offset), 0x80, 8,
		    "RP Tree", "Not RP Tree"));
	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Preference: %u",
		tvb_get_ntohl(tvb, offset) & 0x7fffffff);
	    offset += 4;

	    proto_tree_add_text(pimopt_tree, tvb, offset, 4, "Metric: %u",
		tvb_get_ntohl(tvb, offset));

	    break;
	  }

	case 8:	/* Candidate-RP-Advertisement */
	  {
	    const char *s;
	    int advance;
	    int pfxcnt;
	    guint16 holdtime;
	    int i;

	    pfxcnt = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Prefix-count: %u", pfxcnt);
	    offset += 1;
	    proto_tree_add_text(pimopt_tree, tvb, offset, 1,
		"Priority: %u", tvb_get_guint8(tvb, offset));
	    offset += 1;
	    holdtime = tvb_get_ntohs(tvb, offset);
	    proto_tree_add_text(pimopt_tree, tvb, offset, 2,
		"Holdtime: %u%s", holdtime,
		holdtime == 0xffff ? " (infty)" : "");
	    offset += 2;

	    s = dissect_pim_addr(tvb, offset, pimv2_unicast, &advance);
	    if (s == NULL)
		break;
	    proto_tree_add_text(pimopt_tree, tvb, offset, advance, "RP: %s", s);
	    offset += advance;

	    for (i = 0; i < pfxcnt; i++) {
		s = dissect_pim_addr(tvb, offset, pimv2_group, &advance);
		if (s == NULL)
		    goto breakbreak8;
		proto_tree_add_text(pimopt_tree, tvb, offset, advance,
		    "Group %d: %s", i, s);
		offset += advance;
	    }
    breakbreak8:
	    break;
	  }

	default:
	    break;
	}
    }
done:;
}

void
proto_register_pim(void)
{
    static hf_register_info hf[] = {
      { &hf_pim_version,
	{ "Version",		"pim.version",
				FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
      { &hf_pim_type,
	{ "Type",		"pim.type",
				FT_UINT8, BASE_DEC, VALS(type2vals), 0x0, "", HFILL }},
      { &hf_pim_code,
	{ "Code",		"pim.code",
				FT_UINT8, BASE_DEC, VALS(type1vals), 0x0, "", HFILL }},
      { &hf_pim_cksum,
	{ "Checksum",		"pim.cksum",
				FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
    };
    static gint *ett[] = {
        &ett_pim,
    };

    proto_pim = proto_register_protocol("Protocol Independent Multicast",
	"PIM", "pim");
    proto_register_field_array(proto_pim, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pim(void)
{
    dissector_handle_t pim_handle;

    pim_handle = create_dissector_handle(dissect_pim, proto_pim);
    dissector_add("ip.proto", IP_PROTO_PIM, pim_handle);

    /*
     * Get handles for the IPv4 and IPv6 dissectors.
     */
    ip_handle = find_dissector("ip");
    ipv6_handle = find_dissector("ipv6");
}
