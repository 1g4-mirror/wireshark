/* packet-connect-ip.c
 * Routines for CONNECT-IP dissection
 * Copyright 2025, Yaroslav Rosomakho <yaroslavros@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Processes "Proxying IP in HTTP" protocol as defined in RFC9484
 *
 * Initially only implements processing of IP packets encapsulated in HTTP/3 datagrams
 */

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-http.h"

void proto_reg_handoff_http_connect_ip(void);
void proto_register_http_connect_ip(void);

static dissector_handle_t http_connect_ip_datagram_handle;

static int proto_http_connect_ip;

typedef struct {
    wmem_map_t      * pfds;     /**< PFD storage for new frames. 64-bit key has pinfo->num followed by data offset */
} http_connect_ip_conv_t;

static int hf_http_datagram;
static int hf_http_datagram_context_id;
static int hf_http_datagram_payload;

static expert_field ei_http_datagram_unknown_context_id;

static int ett_http_datagram;

static int
dissect_http_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_tree             * datragram_tree;
    proto_item             * ti;
    int32_t                  lenvar;
    uint64_t                 context_id;
    http_connect_ip_conv_t * http_connect_ip_conv;
    int                      offset = 0;

    ti = proto_tree_add_item(tree, hf_http_datagram, tvb, 0, -1, ENC_NA);
    datragram_tree = proto_item_add_subtree(ti, ett_http_datagram);
    proto_tree_add_item_ret_varint(datragram_tree, hf_http_datagram_context_id, tvb, 0, -1, ENC_VARINT_QUIC, &context_id, &lenvar);

    /*
     * Currently there are no non-0 Context IDs in CONNECT-IP
     */
    if (context_id) {
        proto_tree_add_expert_format(datragram_tree, pinfo, &ei_http_datagram_unknown_context_id, tvb, 0, lenvar,
                                             "Unknown Context ID");
    }

    offset += lenvar;

    proto_tree_add_item(datragram_tree, hf_http_datagram_payload, tvb, offset, -1, ENC_NA);

    if (context_id) { // We don't know how to deal with non-0 Conect ID. Give up.
        return tvb_captured_length(tvb);
    }

    http_upgrade_info_t *http_info = (http_upgrade_info_t *)data;
    if (!http_info->dissector_data) {
        http_info->dissector_data = wmem_new0(wmem_file_scope(), http_connect_ip_conv_t);
    }
    http_connect_ip_conv = (http_connect_ip_conv_t *)http_info->dissector_data;
    if (!http_connect_ip_conv->pfds) {
        http_connect_ip_conv->pfds = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    }

    bool no_pfd = false;
    uint64_t local_num = ((uint64_t)pinfo->num << 32) + tvb_offset_from_real_beginning(tvb);

    frame_data *new_fd = wmem_memdup(pinfo->pool, pinfo->fd, sizeof(frame_data));
    new_fd->pfd = (GSList *)wmem_map_lookup(http_connect_ip_conv->pfds, &local_num);
    if (!new_fd->pfd) {
        no_pfd = true;
    }
    new_fd->pkt_len = tvb_captured_length_remaining(tvb, offset);
    new_fd->cap_len = tvb_captured_length_remaining(tvb, offset);
    packet_info *new_pinfo = wmem_alloc0(pinfo->pool, sizeof(packet_info));
    new_pinfo->fd = new_fd;
    new_pinfo->cinfo = pinfo->cinfo;
    new_pinfo->presence_flags = pinfo->presence_flags;
    new_pinfo->num = pinfo->num;
    new_pinfo->abs_ts = pinfo->abs_ts;
    new_pinfo->rel_ts = pinfo->rel_ts;
    new_pinfo->rel_cap_ts = pinfo->rel_cap_ts;
    new_pinfo->rel_cap_ts_present = pinfo->rel_cap_ts_present;
    new_pinfo->rec = pinfo->rec;
    new_pinfo->data_src = pinfo->data_src;
    new_pinfo->layers = wmem_list_new(pinfo->pool);
    new_pinfo->pool = pinfo->pool;
    new_pinfo->epan = pinfo->epan;

    dissector_handle_t ip_handle = find_dissector("ip");

    call_dissector_only(ip_handle, tvb_new_subset_remaining(tvb, offset), new_pinfo, tree, NULL);

    if (!PINFO_FD_VISITED(pinfo) && new_fd->pfd && no_pfd) {
        uint64_t * pfd_key = wmem_new(wmem_file_scope(), uint64_t);
        *pfd_key = local_num;
        wmem_map_insert(http_connect_ip_conv->pfds, pfd_key, new_fd->pfd);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_http_connect_ip(void)
{
    expert_module_t *expert_http_connect_ip;
    static hf_register_info hf[] = {
        { &hf_http_datagram,
            { "IP Proxying HTTP Datagram", "connect-ip",
              FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http_datagram_context_id,
            { "Context ID", "connect-ip.context-id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http_datagram_payload,
            { "Payload", "connect-ip.payload",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Proxied IP in HTTP payload", HFILL }
        },
    };

    static int *ett[] = {&ett_http_datagram};

    static ei_register_info ei[] = {
        { &ei_http_datagram_unknown_context_id,
          { "connect-ip.unknown-context-id", PI_UNDECODED, PI_WARN,
          "Encountered unknown Context ID", EXPFILL}
        },
    };

    proto_http_connect_ip = proto_register_protocol("IP in HTTP", "CONNECT-IP", "connect-ip");
    proto_register_field_array(proto_http_connect_ip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_http_connect_ip = expert_register_protocol(proto_http_connect_ip);
    expert_register_field_array(expert_http_connect_ip, ei, array_length(ei));
    http_connect_ip_datagram_handle = register_dissector("connect-ip", dissect_http_datagram, proto_http_connect_ip);
}

void
proto_reg_handoff_http_connect_ip(void)
{
    dissector_add_string("http3.datagram", "connect-ip", http_connect_ip_datagram_handle);
}