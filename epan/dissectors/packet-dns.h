/* packet-dns.h
 * Definitions for packet disassembly structures and routines used both by
 * DNS and NBNS.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __PACKET_DNS_H__
#define __PACKET_DNS_H__

extern const value_string dns_classes[];
extern const value_string dns_svcb_param_key_vals[];

/*
 * Expands DNS name from TVB into a byte string.
 *
 * Returns int: byte size of DNS data.
 * Returns char *name: a dot (.) separated raw string of DNS domain name labels.
 * This string is null terminated. Labels are copied directly from raw packet
 * data without any validation for a string encoding. This is the callers responsibility.
 * Return int name_len: byte length of "name".
 */
int get_dns_name(wmem_allocator_t* scope, tvbuff_t *tvb, int offset, int max_len, int dns_data_offset,
    const char **name, int* name_len);

#define MAX_DNAME_LEN   255             /* maximum domain name length */

/*
 * Shared svcb param parsing helpers.
 */
typedef struct dns_svcb_params_common_dissect {
    struct {
        int dns_svcb_param_key;
        int dns_svcb_param_length;
        int dns_svcb_param_value;
        int dns_svcb_param;
        int dns_svcb_param_mandatory_key;
        int dns_svcb_param_alpn_length;
        int dns_svcb_param_alpn;
        int dns_svcb_param_port;
        int dns_svcb_param_ipv4hint_ip;
        int dns_svcb_param_ipv6hint_ip;
        int dns_svcb_param_dohpath;
        int dns_svcb_param_odohconfig;
        /* do not forget to update DNS_SVCB_PARAMS_COMMON_HF_LIST! */
    } hf;
    struct {
        int dns_svcb;
        /* do not forget to update DNS_SVCB_PARAMS_COMMON_ETT_LIST! */
    } ett;
} dns_svcb_params_common_dissect_t;

/* {{{ */
#define DNS_SVCB_PARAMS_COMMON_LIST_T(name) \
dns_svcb_params_common_dissect_t name
/* }}} */

/* {{{ */
#define DNS_SVCB_PARAMS_COMMON_HF_LIST(name, prefix)                    \
    { & name .hf.dns_svcb_param_key,                                    \
      { "SvcParamKey", prefix ".svcparam.key",                          \
        FT_UINT16, BASE_DEC, VALS(dns_svcb_param_key_vals), 0x0,        \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_length,                                 \
      { "SvcParamValue length", prefix ".svcparam.value.length",        \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_value,                                  \
      { "SvcParamValue", prefix ".svcparam.value",                      \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param,                                        \
      { "SvcParam", prefix ".svcparam",                                 \
        FT_NONE, BASE_NONE, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_mandatory_key,                          \
      { "Mandatory key", prefix ".svcparam.mandatory.key",              \
        FT_UINT16, BASE_DEC, VALS(dns_svcb_param_key_vals), 0x0,        \
        "Mandatory keys in this RR", HFILL }                            \
    },                                                                  \
    { & name .hf.dns_svcb_param_alpn_length,                            \
      { "ALPN length", prefix ".svcparam.alpn.length",                  \
        FT_UINT8, BASE_DEC, NULL, 0x0,                                  \
        NULL, HFILL }                                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_alpn,                                   \
      { "ALPN", prefix ".svcparam.alpn",                                \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        "Additional supported protocols", HFILL }                       \
    },                                                                  \
    { & name .hf.dns_svcb_param_port,                                   \
      { "Port", prefix ".svcparam.port",                                \
        FT_UINT16, BASE_DEC, NULL, 0x0,                                 \
        "Port for alternative endpoint", HFILL }                        \
    },                                                                  \
    { & name .hf.dns_svcb_param_ipv4hint_ip,                            \
      { "IP", prefix ".svcparam.ipv4hint.ip",                           \
        FT_IPv4, BASE_NONE, NULL, 0x0,                                  \
        "IPv4 address hints", HFILL }                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_ipv6hint_ip,                            \
      { "IP", prefix ".svcparam.ipv6hint.ip",                           \
        FT_IPv6, BASE_NONE, NULL, 0x0,                                  \
        "IPv6 address hints", HFILL }                                   \
    },                                                                  \
    { & name .hf.dns_svcb_param_dohpath,                                \
      { "DoH path", prefix ".svcparam.dohpath",                         \
        FT_STRING, BASE_NONE, NULL, 0x0,                                \
        "DoH URI template", HFILL}                                      \
    },                                                                  \
    { & name .hf.dns_svcb_param_odohconfig,                             \
      { "ODoHConfig", prefix ".svcparam.odohconfig",                    \
        FT_BYTES, BASE_NONE, NULL, 0x0,                                 \
        "Oblivious DoH keys", HFILL }                                   \
    }
/* }}} */

/* {{{ */
#define DNS_SVCB_PARAMS_COMMON_ETT_LIST(name)       \
    & name .ett.dns_svcb                           \
/* }}}*/

int
dns_dissect_svcb_params(dns_svcb_params_common_dissect_t *hf, tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, int offset, int offset_end);

#endif /* packet-dns.h */
