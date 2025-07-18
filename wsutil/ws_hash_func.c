/* ws_hash_func.c
 * Wrappers around xxhash functions to
 * make them usabe in g_hash_tables
 *
 * Copyright 2025 Anders Broman <a.broman58[at]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#ifdef HAVE_XXHASH
#include <xxhash.h>
#endif /* HAVE_XXHASH */
#include "ws_hash_func.h"

guint
ws_str_hash(gconstpointer v)
{
#ifdef HAVE_XXHASH
    return (uint32_t)XXH32((const uint8_t*)v, strlen((const char*)v), 0);
#else
    g_str_hash(v)
#endif
}
