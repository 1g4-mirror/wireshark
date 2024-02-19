/* packet-roon_discovery.c
 * Routines for Roon Discovery dissection
 * Copyright 2022, Aaron Turner <synfinatic@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ROON_DISCOVERY_H__
#define __PACKET_ROON_DISCOVERY_H__

#include <config.h>
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */

/* Transaction tracking structure */
typedef struct _roon_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} roon_transaction_t;

typedef struct _roon_conv_info_t {
    wmem_tree_t *unmatched_pdus;
    wmem_tree_t *matched_pdus;
} roon_conv_info_t;

typedef struct {
    char *key;
    char *name;
    int *value;
} roon_map;


typedef struct {
    char *uuid;
    char *name;
} roon_uuid_map;


#endif /* __PACKET_ROON_DISCOVERY_H__ */