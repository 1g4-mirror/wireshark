/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_IOUSERS_H__
#define __TAP_IOUSERS_H__


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _io_users_t {
	const char *type;
	const char *filter;
	conv_hash_t hash;
} io_users_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TAP_IOUSERS_H__ */
