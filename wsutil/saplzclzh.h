/* saplzclzh.h
 * Routines for decompression with SAP LZC/LZH algorithms
 * Copyright 2022, Martin Gallo <martin.gallo [AT] gmail.com>
 * Code contributed by SecureAuth Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __SAPLZCLZH_H__
#define __SAPLZCLZH_H__

/* Return code for memory errors */
#define SAP_LZC_LZH_CS_E_MEMORY_ERROR -99

/* SAP LZC/LZH Decompression routine return codes */
WS_DLL_PUBLIC const char *sap_lzclzh_decompress_error_string(int return_code);

/* SAP LZC/LZH Decompression routine */
WS_DLL_PUBLIC int sap_lzclzh_decompress(wmem_allocator_t *wmem_scope, const guint8 *in, gint in_length, guint8 *out, guint *out_length);

#endif /* __SAPLZCLZH_H__ */
