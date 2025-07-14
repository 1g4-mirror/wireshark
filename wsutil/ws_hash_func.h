/* ws_hash_func.h
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

#ifndef WS_HASH_FUNC_H
#define WS_HASH_FUNC_H

#include <wireshark.h>

#ifdef __cplusplus
extern "C"{
#endif

WS_DLL_PUBLIC guint ws_str_hash(gconstpointer v);

#ifdef __cplusplus
}
#endif

#endif  /* WS_HASH_FUNC_H */
