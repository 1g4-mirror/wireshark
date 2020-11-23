/* packet-ssh.c
 * Routines for ssh packet dissection
 *
 * Huagang XIE <huagang@intruvert.com>
 * Kees Cook <kees@outflux.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-mysql.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * Note:  support SSH v1 and v2  now.
 *
 */

/* SSH version 2 is defined in:
 *
 * RFC 4250: The Secure Shell (SSH) Protocol Assigned Numbers
 * RFC 4251: The Secure Shell (SSH) Protocol Architecture
 * RFC 4252: The Secure Shell (SSH) Authentication Protocol
 * RFC 4253: The Secure Shell (SSH) Transport Layer Protocol
 * RFC 4254: The Secure Shell (SSH) Connection Protocol
 *
 * SSH versions under 2 were never officially standardized.
 *
 * Diffie-Hellman Group Exchange is defined in:
 *
 * RFC 4419: Diffie-Hellman Group Exchange for
 *   the Secure Shell (SSH) Transport Layer Protocol
 */

/* "SSH" prefixes are for version 2, whereas "SSH1" is for version 1 */

#include "config.h"

/* Start with G_MESSAGES_DEBUG=ssh to see messages. */
#define G_LOG_DOMAIN "ssh"

#include <errno.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/sctpppids.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <wsutil/strtoi.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/curve25519.h>
#include <wsutil/pint.h>
#include <version_info.h>
#include <epan/secrets.h>
#include <wiretap/secrets-types.h>

#if defined(HAVE_LIBGNUTLS)
#include <gnutls/abstract.h>            // Really needed???
#endif

#include "packet-tcp.h"

void proto_register_ssh(void);
void proto_reg_handoff_ssh(void);

/* SSH Version 1 definition , from openssh ssh1.h */
#define SSH1_MSG_NONE           0   /* no message */
#define SSH1_MSG_DISCONNECT     1   /* cause (string) */
#define SSH1_SMSG_PUBLIC_KEY    2   /* ck,msk,srvk,hostk */
#define SSH1_CMSG_SESSION_KEY   3   /* key (BIGNUM) */
#define SSH1_CMSG_USER          4   /* user (string) */


#define SSH_VERSION_UNKNOWN     0
#define SSH_VERSION_1           1
#define SSH_VERSION_2           2

/* proto data */

#if GCRYPT_VERSION_NUMBER >= 0x010700 /* 1.7.0 */
#define SSH_DECRYPTION_SUPPORTED
#endif

#ifdef SSH_DECRYPTION_SUPPORTED
typedef struct {
    guint8  *data;
    guint   length;
} ssh_bignum;

#define SSH_KEX_CURVE25519 0x00010000
#define SSH_KEX_DH_GEX     0x00020000
#define SSH_KEX_DH_GROUP1  0x00030001
#define SSH_KEX_DH_GROUP14 0x00030014
#define SSH_KEX_DH_GROUP16 0x00030016
#define SSH_KEX_DH_GROUP18 0x00030018

#define SSH_KEX_HASH_SHA1   1
#define SSH_KEX_HASH_SHA256 2
#define SSH_KEX_HASH_SHA512 4

typedef struct _ssh_message_info_t {
    guint32 sequence_number;
    guint32 offset;
    guchar *plain_data;     /**< Decrypted data. */
    guint   data_len;       /**< Length of decrypted data. */
    gint    id;             /**< Identifies the exact message within a frame
                                 (there can be multiple records in a frame). */
    guint   is_fragment;
    struct _ssh_message_info_t* next;
} ssh_message_info_t;

typedef struct {
    gboolean from_server;
    ssh_message_info_t * messages;
} ssh_packet_info_t;
#endif

typedef struct _ssh_channel_info_t {
    guint  channel_number;
    dissector_handle_t subdissector_handle;
    struct _ssh_channel_info_t* next;
} ssh_channel_info_t;

struct ssh_peer_data {
    guint   counter;

    guint32 frame_version_start;
    guint32 frame_version_end;

    guint32 frame_key_start;
    guint32 frame_key_end;
    int frame_key_end_offset;

    gchar*  kex_proposal;

    /* For all subsequent proposals,
       [0] is client-to-server and [1] is server-to-client. */
#define CLIENT_TO_SERVER_PROPOSAL 0
#define SERVER_TO_CLIENT_PROPOSAL 1

    gchar*  mac_proposals[2];
    gchar*  mac;
    gint    mac_length;

    gchar*  enc_proposals[2];
    gchar*  enc;

    gchar*  comp_proposals[2];
    gchar*  comp;

    gint    in_fragment;
    gchar   fragment_plain0[16];                // First decrypted bloc that holds PDU length for fragmented frames

    gint    length_is_plaintext;

#ifdef SSH_DECRYPTION_SUPPORTED
    // see libgcrypt source, gcrypt.h:gcry_cipher_algos
    guint            cipher_id;
    // chacha20 needs two cipher handles
    gcry_cipher_hd_t cipher, cipher_2;
    guint            sequence_number;
    ssh_bignum      *bn_cookie;
    guint8           iv[12];
#endif

    ssh_channel_info_t *channel_info;
};

struct ssh_flow_data {
    guint   version;

    gchar*  kex;
    int   (*kex_specific_dissector)(guint8 msg_code, tvbuff_t *tvb,
            packet_info *pinfo, int offset, proto_tree *tree,
            struct ssh_flow_data *global_data);

    /* [0] is client's, [1] is server's */
#define CLIENT_PEER_DATA 0
#define SERVER_PEER_DATA 1
    struct ssh_peer_data peer_data[2];

#ifdef SSH_DECRYPTION_SUPPORTED
    gchar           *session_id;
    guint           session_id_length;
    gchar           *chain;
    ssh_bignum      *kex_e;
    ssh_bignum      *kex_f;
    ssh_bignum      *kex_gex_p;                 // Group modulo
    ssh_bignum      *kex_gex_g;                 // Group generator
    ssh_bignum      *secret;
    wmem_array_t    *kex_client_version;
    wmem_array_t    *kex_server_version;
    wmem_array_t    *kex_client_key_exchange_init;
    wmem_array_t    *kex_server_key_exchange_init;
    wmem_array_t    *kex_server_host_key_blob;
    wmem_array_t    *kex_gex_bits_min;
    wmem_array_t    *kex_gex_bits_req;
    wmem_array_t    *kex_gex_bits_max;
    wmem_array_t    *kex_shared_secret;
    gboolean        do_decrypt;
    ssh_bignum      new_keys[6];
#endif
};

static GHashTable * ssh_master_key_map = NULL;

static int proto_ssh = -1;

/* Version exchange */
static int hf_ssh_protocol = -1;

/* Framing */
static int hf_ssh_packet_length = -1;
static int hf_ssh_packet_length_encrypted = -1;
static int hf_ssh_padding_length = -1;
static int hf_ssh_payload = -1;
static int hf_ssh_encrypted_packet = -1;
static int hf_ssh_padding_string = -1;
static int hf_ssh_mac_string = -1;
static int hf_ssh_direction = -1;

/* Message codes */
static int hf_ssh_msg_code = -1;
static int hf_ssh2_msg_code = -1;
static int hf_ssh2_kex_dh_msg_code = -1;
static int hf_ssh2_kex_dh_gex_msg_code = -1;
static int hf_ssh2_kex_ecdh_msg_code = -1;

/* Algorithm negotiation */
static int hf_ssh_cookie = -1;
static int hf_ssh_kex_algorithms = -1;
static int hf_ssh_server_host_key_algorithms = -1;
static int hf_ssh_encryption_algorithms_client_to_server = -1;
static int hf_ssh_encryption_algorithms_server_to_client = -1;
static int hf_ssh_mac_algorithms_client_to_server = -1;
static int hf_ssh_mac_algorithms_server_to_client = -1;
static int hf_ssh_compression_algorithms_client_to_server = -1;
static int hf_ssh_compression_algorithms_server_to_client = -1;
static int hf_ssh_languages_client_to_server = -1;
static int hf_ssh_languages_server_to_client = -1;
static int hf_ssh_kex_algorithms_length = -1;
static int hf_ssh_server_host_key_algorithms_length = -1;
static int hf_ssh_encryption_algorithms_client_to_server_length = -1;
static int hf_ssh_encryption_algorithms_server_to_client_length = -1;
static int hf_ssh_mac_algorithms_client_to_server_length = -1;
static int hf_ssh_mac_algorithms_server_to_client_length = -1;
static int hf_ssh_compression_algorithms_client_to_server_length = -1;
static int hf_ssh_compression_algorithms_server_to_client_length = -1;
static int hf_ssh_languages_client_to_server_length = -1;
static int hf_ssh_languages_server_to_client_length = -1;
static int hf_ssh_first_kex_packet_follows = -1;
static int hf_ssh_kex_reserved = -1;

/* Key exchange common elements */
static int hf_ssh_hostkey_length = -1;
static int hf_ssh_hostkey_type_length = -1;
static int hf_ssh_hostkey_type = -1;
static int hf_ssh_hostkey_data = -1;
static int hf_ssh_hostkey_rsa_n = -1;
static int hf_ssh_hostkey_rsa_e = -1;
static int hf_ssh_hostkey_dsa_p = -1;
static int hf_ssh_hostkey_dsa_q = -1;
static int hf_ssh_hostkey_dsa_g = -1;
static int hf_ssh_hostkey_dsa_y = -1;
static int hf_ssh_hostkey_ecdsa_curve_id = -1;
static int hf_ssh_hostkey_ecdsa_curve_id_length = -1;
static int hf_ssh_hostkey_ecdsa_q = -1;
static int hf_ssh_hostkey_ecdsa_q_length = -1;
static int hf_ssh_hostkey_eddsa_key = -1;
static int hf_ssh_hostkey_eddsa_key_length = -1;

static int hf_ssh_kex_h_sig = -1;
static int hf_ssh_kex_h_sig_length = -1;

/* Key exchange: Diffie-Hellman */
static int hf_ssh_dh_e = -1;
static int hf_ssh_dh_f = -1;

/* Key exchange: Diffie-Hellman Group Exchange */
static int hf_ssh_dh_gex_min = -1;
static int hf_ssh_dh_gex_nbits = -1;
static int hf_ssh_dh_gex_max = -1;
static int hf_ssh_dh_gex_p = -1;
static int hf_ssh_dh_gex_g = -1;

/* Key exchange: Elliptic Curve Diffie-Hellman */
static int hf_ssh_ecdh_q_c = -1;
static int hf_ssh_ecdh_q_c_length = -1;
static int hf_ssh_ecdh_q_s = -1;
static int hf_ssh_ecdh_q_s_length = -1;

/* Miscellaneous */
static int hf_ssh_mpint_length = -1;

/* */
static int hf_ssh_service_name_length = -1;
static int hf_ssh_service_name = -1;
static int hf_ssh_userauth_user_name_length = -1;
static int hf_ssh_userauth_user_name = -1;
static int hf_ssh_userauth_service_name_length = -1;
static int hf_ssh_userauth_service_name = -1;
static int hf_ssh_userauth_method_name_length = -1;
static int hf_ssh_userauth_method_name = -1;
static int hf_ssh_auth_failure_list_length = -1;
static int hf_ssh_auth_failure_list = -1;
static int hf_ssh_userauth_pka_name_len = -1;
static int hf_ssh_userauth_pka_name = -1;
static int hf_ssh_pk_blob_name_length = -1;
static int hf_ssh_pk_blob_name = -1;
static int hf_ssh_blob_length = -1;
static int hf_ssh_signature_length = -1;
static int hf_ssh_pk_sig_blob_name_length = -1;
static int hf_ssh_pk_sig_blob_name = -1;
static int hf_ssh_connection_type_name_len = -1;
static int hf_ssh_connection_type_name = -1;
static int hf_ssh_connection_sender_channel = -1;
static int hf_ssh_connection_recipient_channel = -1;
static int hf_ssh_connection_initial_window = -1;
static int hf_ssh_connection_maximum_packet_size = -1;
static int hf_ssh_global_request_name_len = -1;
static int hf_ssh_global_request_name = -1;
static int hf_ssh_global_request_want_reply = -1;
static int hf_ssh_channel_request_name_len = -1;
static int hf_ssh_channel_request_name = -1;
static int hf_ssh_channel_request_want_reply = -1;
static int hf_ssh_subsystem_name_len = -1;
static int hf_ssh_subsystem_name = -1;
static int hf_ssh_channel_window_adjust = -1;
static int hf_ssh_channel_data_len = -1;
static int hf_ssh_exit_status = -1;
static int hf_ssh_disconnect_reason = -1;
static int hf_ssh_disconnect_description_length = -1;
static int hf_ssh_disconnect_description = -1;
static int hf_ssh_lang_tag_length = -1;
static int hf_ssh_lang_tag = -1;

static int hf_ssh_blob_p = -1;
static int hf_ssh_blob_e = -1;

static int hf_ssh_pk_sig_s_length = -1;
static int hf_ssh_pk_sig_s = -1;

static gint ett_ssh = -1;
static gint ett_key_exchange = -1;
static gint ett_key_exchange_host_key = -1;
static gint ett_userauth_pk_blob = -1;
static gint ett_userauth_pk_signautre = -1;
static gint ett_key_init = -1;
static gint ett_ssh1 = -1;
static gint ett_ssh2 = -1;

static expert_field ei_ssh_packet_length = EI_INIT;

static gboolean ssh_desegment = TRUE;

static dissector_handle_t ssh_handle;
static dissector_handle_t sftp_handle=NULL;

#ifdef SSH_DECRYPTION_SUPPORTED
static const char   *pref_keylog_file;
static FILE         *ssh_keylog_file;
#endif

// 29418/tcp: Gerrit Code Review
#define TCP_RANGE_SSH  "22,29418"
#define SCTP_PORT_SSH 22

/* Message Numbers (from RFC 4250) (1-255) */

/* Transport layer protocol: generic (1-19) */
#define SSH_MSG_DISCONNECT          1
#define SSH_MSG_IGNORE              2
#define SSH_MSG_UNIMPLEMENTED       3
#define SSH_MSG_DEBUG               4
#define SSH_MSG_SERVICE_REQUEST     5
#define SSH_MSG_SERVICE_ACCEPT      6

/* Transport layer protocol: Algorithm negotiation (20-29) */
#define SSH_MSG_KEXINIT             20
#define SSH_MSG_NEWKEYS             21

/* Transport layer: Key exchange method specific (reusable) (30-49) */
#define SSH_MSG_KEXDH_INIT          30
#define SSH_MSG_KEXDH_REPLY         31
#define SSH_MSG_KEX_DH_GEX_GROUP    31

#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD  30
#define SSH_MSG_KEX_DH_GEX_GROUP        31
#define SSH_MSG_KEX_DH_GEX_INIT         32
#define SSH_MSG_KEX_DH_GEX_REPLY        33
#define SSH_MSG_KEX_DH_GEX_REQUEST      34

#define SSH_MSG_KEX_ECDH_INIT       30
#define SSH_MSG_KEX_ECDH_REPLY      31

/* User authentication protocol: generic (50-59) */
#define SSH_MSG_USERAUTH_REQUEST    50
#define SSH_MSG_USERAUTH_FAILURE    51
#define SSH_MSG_USERAUTH_SUCCESS    52
#define SSH_MSG_USERAUTH_BANNER     53

/* User authentication protocol: method specific (reusable) (50-79) */
#define SSH_MSG_USERAUTH_PK_OK      60

/* Connection protocol: generic (80-89) */
#define SSH_MSG_GLOBAL_REQUEST          80
#define SSH_MSG_REQUEST_SUCCESS         81
#define SSH_MSG_REQUEST_FAILURE         82

/* Connection protocol: channel related messages (90-127) */
#define SSH_MSG_CHANNEL_OPEN                90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION   91
#define SSH_MSG_CHANNEL_OPEN_FAILURE        92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST       93
#define SSH_MSG_CHANNEL_DATA                94
#define SSH_MSG_CHANNEL_EXTENDED_DATA       95
#define SSH_MSG_CHANNEL_EOF                 96
#define SSH_MSG_CHANNEL_CLOSE               97
#define SSH_MSG_CHANNEL_REQUEST             98
#define SSH_MSG_CHANNEL_SUCCESS             99
#define SSH_MSG_CHANNEL_FAILURE             100

/* 128-191 reserved for client protocols */
/* 192-255 local extensions */

#define CIPHER_AES128_CTR               0x00010001
#define CIPHER_AES192_CTR               0x00010003
#define CIPHER_AES256_CTR               0x00010004
#define CIPHER_AES128_CBC               0x00020001
#define CIPHER_AES192_CBC               0x00020002
#define CIPHER_AES256_CBC               0x00020004
#define CIPHER_AES128_GCM               0x00040001
//#define CIPHER_AES192_GCM               0x00040002	-- does not exist
#define CIPHER_AES256_GCM               0x00040004

static const value_string ssh_direction_vals[] = {
    { CLIENT_TO_SERVER_PROPOSAL, "client-to-server" },
    { SERVER_TO_CLIENT_PROPOSAL, "server-to-client" },
    { 0, NULL }
};

static const value_string ssh2_msg_vals[] = {
    { SSH_MSG_DISCONNECT,                "Disconnect" },
    { SSH_MSG_IGNORE,                    "Ignore" },
    { SSH_MSG_UNIMPLEMENTED,             "Unimplemented" },
    { SSH_MSG_DEBUG,                     "Debug" },
    { SSH_MSG_SERVICE_REQUEST,           "Service Request" },
    { SSH_MSG_SERVICE_ACCEPT,            "Service Accept" },
    { SSH_MSG_KEXINIT,                   "Key Exchange Init" },
    { SSH_MSG_NEWKEYS,                   "New Keys" },
    { SSH_MSG_USERAUTH_REQUEST,          "User Authentication Request" },
    { SSH_MSG_USERAUTH_FAILURE,          "User Authentication Failure" },
    { SSH_MSG_USERAUTH_SUCCESS,          "User Authentication Success" },
    { SSH_MSG_USERAUTH_BANNER,           "User Authentication Banner" },
    { SSH_MSG_GLOBAL_REQUEST,            "Global Request" },
    { SSH_MSG_REQUEST_SUCCESS,           "Request Success" },
    { SSH_MSG_REQUEST_FAILURE,           "Request Failure" },
    { SSH_MSG_CHANNEL_OPEN,              "Channel Open" },
    { SSH_MSG_CHANNEL_OPEN_CONFIRMATION, "Channel Open Confirmation" },
    { SSH_MSG_CHANNEL_OPEN_FAILURE,      "Channel Open Failure" },
    { SSH_MSG_CHANNEL_WINDOW_ADJUST,     "Window Adjust" },
    { SSH_MSG_CHANNEL_DATA,              "Channel Data" },
    { SSH_MSG_CHANNEL_EXTENDED_DATA,     "Channel Extended Data" },
    { SSH_MSG_CHANNEL_EOF,               "Channel EOF" },
    { SSH_MSG_CHANNEL_CLOSE,             "Channel Close" },
    { SSH_MSG_CHANNEL_REQUEST,           "Channel Request" },
    { SSH_MSG_CHANNEL_SUCCESS,           "Channel Success" },
    { SSH_MSG_CHANNEL_FAILURE,           "Channel Failure" },
    { SSH_MSG_USERAUTH_PK_OK,            "Public Key algorithm accepted" },
    { 0, NULL }
};

static const value_string ssh2_kex_dh_msg_vals[] = {
    { SSH_MSG_KEXDH_INIT,                "Diffie-Hellman Key Exchange Init" },
    { SSH_MSG_KEXDH_REPLY,               "Diffie-Hellman Key Exchange Reply" },
    { 0, NULL }
};

static const value_string ssh2_kex_dh_gex_msg_vals[] = {
    { SSH_MSG_KEX_DH_GEX_REQUEST_OLD,    "Diffie-Hellman Group Exchange Request (Old)" },
    { SSH_MSG_KEX_DH_GEX_GROUP,          "Diffie-Hellman Group Exchange Group" },
    { SSH_MSG_KEX_DH_GEX_INIT,           "Diffie-Hellman Group Exchange Init" },
    { SSH_MSG_KEX_DH_GEX_REPLY,          "Diffie-Hellman Group Exchange Reply" },
    { SSH_MSG_KEX_DH_GEX_REQUEST,        "Diffie-Hellman Group Exchange Request" },
    { 0, NULL }
};

static const value_string ssh2_kex_ecdh_msg_vals[] = {
    { SSH_MSG_KEX_ECDH_INIT,             "Elliptic Curve Diffie-Hellman Key Exchange Init" },
    { SSH_MSG_KEX_ECDH_REPLY,            "Elliptic Curve Diffie-Hellman Key Exchange Reply" },
    { 0, NULL }
};

static const value_string ssh1_msg_vals[] = {
    {SSH1_MSG_NONE,                      "No Message"},
    {SSH1_MSG_DISCONNECT,                "Disconnect"},
    {SSH1_SMSG_PUBLIC_KEY,               "Public Key"},
    {SSH1_CMSG_SESSION_KEY,              "Session Key"},
    {SSH1_CMSG_USER,                     "User"},
    {0, NULL}
};

static int ssh_dissect_key_init(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
        int is_response,
        struct ssh_flow_data *global_data);
static int ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
        int hf_index_length, int hf_index_value, gchar **store);
static int ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation);
static int ssh_dissect_kex_dh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data);
static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data);
static int ssh_dissect_kex_ecdh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data);
static int ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, guint *version,
        gboolean *need_desegmentation);
static int ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree,
        gboolean *need_desegmentation);
static int ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree);
static void ssh_choose_algo(gchar *client, gchar *server, gchar **result);
static void ssh_set_mac_length(struct ssh_peer_data *peer_data);
static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data);

#ifdef SSH_DECRYPTION_SUPPORTED
static void ssh_keylog_read_file(void);
static void ssh_keylog_process_line(const char *line);
static void ssh_keylog_process_lines(/*const ssh_master_key_map_t *mk_map, */const guint8 *data, guint datalen);
static void ssh_keylog_reset(void);
static ssh_bignum *ssh_kex_make_bignum(const guint8 *data, guint length);
static void ssh_read_e(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static void ssh_read_f(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static ssh_bignum * ssh_read_mpint(tvbuff_t *tvb, int offset);
static void ssh_keylog_hash_write_secret(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data);
static ssh_bignum *ssh_kex_shared_secret(gint kex_type, ssh_bignum *pub, ssh_bignum *priv, ssh_bignum *modulo);
static void ssh_hash_buffer_put_string(wmem_array_t *buffer, const gchar *string,
        guint len);
static void ssh_hash_buffer_put_uint32(wmem_array_t *buffer, guint val);
static gchar *ssh_string(const gchar *string, guint len);
static void ssh_derive_symmetric_keys(ssh_bignum *shared_secret,
        gchar *exchange_hash, guint hash_length,
        struct ssh_flow_data *global_data);
static void ssh_derive_symmetric_key(ssh_bignum *shared_secret,
        gchar *exchange_hash, guint hash_length, gchar id,
        ssh_bignum *result_key, struct ssh_flow_data *global_data);

static void ssh_decryption_set_cipher_id(struct ssh_peer_data *peer);
static void ssh_decryption_setup_cipher(struct ssh_peer_data *peer,
        ssh_bignum *iv, ssh_bignum *key);
static void ssh_increment_message_number(packet_info *pinfo,
        struct ssh_flow_data *global_data, gboolean is_response);
static guint ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree,
        gboolean *need_desegmentation);
static gboolean ssh_decrypt_chacha20(gcry_cipher_hd_t hd, guint32 seqnr,
        guint32 counter, const guchar *ctext, guint ctext_len,
        guchar *plain, guint plain_len);

static int ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo, 
        struct ssh_peer_data *peer_data, proto_tree *tree, 
        gchar *plaintext, guint plaintext_len,
        gchar *mac, guint mac_len, 
        gboolean *need_desegmentation);
static void ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static void ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static void ssh_dissect_userauth_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static void ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_item *msg_type_tree,
        guint msg_code);
static void ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree, guint msg_code);
static void ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);
static void ssh_dissect_public_key_signature(tvbuff_t *packet_tvb, packet_info *pinfo,
        int offset, proto_item *msg_type_tree);

static dissector_handle_t get_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel);
static void set_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel, guint8* subsystem_name);

/* other defines */
typedef enum {
    SSH_ID_CHG_CIPHER_SPEC         = 0x14,
    SSH_ID_ALERT                   = 0x15,
    SSH_ID_HANDSHAKE               = 0x16,
    SSH_ID_APP_DATA                = 0x17,
    SSH_ID_HEARTBEAT               = 0x18,
    SSH_ID_TLS12_CID               = 0x19
} ContentType;

#define SSH_DEBUG_USE_STDERR "-"

typedef struct _SshFlow {
    guint32 byte_seq;
    guint16 flags;
    wmem_tree_t *multisegment_pdus;
} SshFlow;

/**
 * Stored information about a part of a reassembled handshake message. A single
 * handshake record is uniquely identified by (record_id, reassembly_id).
 */
typedef struct _SshHsFragment {
    guint   record_id;      /**< Identifies the exact record within a frame
                                 (there can be multiple records in a frame). */
    guint   reassembly_id;  /**< Identifies the reassembly that this fragment is part of. */
    guint32 offset;         /**< Offset within a reassembly. */
    guint8  type;           /**< Handshake type (first byte of the buffer). */
    int     is_last : 1;    /**< Whether this fragment completes the message. */
    struct _SshHsFragment *next;
} SshHsFragment;

#define SSH_DECRYPT_DEBUG
#ifdef SSH_DECRYPT_DEBUG
extern void
ssh_debug_printf(const gchar* fmt,...) G_GNUC_PRINTF(1,2);
extern void
ssh_print_data(const gchar* name, const guchar* data, size_t len);
extern void
ssh_set_debug(const gchar* name);
extern void
ssh_debug_flush(void);
#else

/* No debug: nullify debug operation*/
static inline void G_GNUC_PRINTF(1,2)
ssh_debug_printf(const gchar* fmt _U_,...)
{
}
#define ssh_print_data(a, b, c)
#define ssh_print_string(a, b)
#define ssh_set_debug(name)
#define ssh_debug_flush()

#endif /* SSH_DECRYPT_DEBUG */

#endif

void print_hex(const guchar *buf, guint len, const guchar *desc)
{
    char sbuf[10*1024];
    int pos = 0;
    sbuf[0] = 0;
//    printf("(%s) hex: ", desc);
    for (guint i = 0; i < len; i ++) {
//        printf("%02X", sbuf[i]);
        pos += snprintf(&sbuf[pos], sizeof(sbuf)-1-pos, "%02X", buf[i]);
    }
//    printf("\n");
    g_debug("(%s) hex: %s", desc, sbuf);
}

const char h2a[] = "0123456789abcdef";
void dump_ssh_style(const guchar *buf, guint len, const guchar *desc, ...)
{
#define ALLOC_SIZE  (1024*1024)
    gchar *gbuf = (gchar *)wmem_alloc0(NULL, ALLOC_SIZE);
    gchar *sbuf = gbuf;
    va_list ap;
    va_start(ap, desc);
    sbuf += vsnprintf((char *)sbuf, ALLOC_SIZE-1-(sbuf-gbuf), desc, ap);
    va_end(ap);
    sbuf += snprintf((char *)sbuf, ALLOC_SIZE-1-(sbuf-gbuf), " [%d]\n", len);

    if(buf){
        int rpos = 0;
        int cpos = 0;
        sbuf[0] = 0;
        guint i = 0;
        const int rlen = 16;
        for (i = 0; i < len; i ++) {
            cpos %= rlen;
            if(cpos==0){
                if(i != 0){
                    rpos += 6 + 3*rlen + 1 + rlen + 1;
                    sbuf[rpos-1] = '\n';
                }
//                sbuf[rpos+0] = h2a[(i >> 12) & 0xF];
//                sbuf[rpos+1] = h2a[(i >>  8) & 0xF];
//                sbuf[rpos+2] = h2a[(i >>  4) & 0xF];
//              sbuf[rpos+3] = h2a[(i >>  0) & 0xF];
                sbuf[rpos+0] = i>=1000?h2a[(i / 1000) % 10]:'0';
                sbuf[rpos+1] = i>= 100?h2a[(i /  100) % 10]:'0';
                sbuf[rpos+2] = i>=  10?h2a[(i /   10) % 10]:'0';
                sbuf[rpos+3] = i>=   1?h2a[(i /    1) % 10]:'0';
                sbuf[rpos+4] = ':';
                sbuf[rpos+5] = ' ';
                sbuf[rpos+6+3*rlen] = ' ';
            }
            sbuf[rpos+6+3*cpos+0] = h2a[(buf[i] >> 4) & 0xF];
            sbuf[rpos+6+3*cpos+1] = h2a[(buf[i] >> 0) & 0xF];
            sbuf[rpos+6+3*cpos+2] = ' ';
            sbuf[rpos+6+3*rlen+1+cpos] = (buf[i]>=32 && buf[i]<127)?buf[i]:'.';
            cpos++;
        }
        sbuf[rpos+6+3*rlen+1+cpos] = 0;
        while(cpos<16){
            sbuf[rpos+6+3*cpos+0] = ' ';
            sbuf[rpos+6+3*cpos+1] = ' ';
            sbuf[rpos+6+3*cpos+2] = ' ';
            sbuf[rpos+6+3*rlen] = ' ';
            cpos++;
        }
        sbuf[rpos+6+3*rlen+1+cpos] = 0;
    }else{
        sbuf += snprintf((char *)sbuf, ALLOC_SIZE-1-(sbuf-gbuf), "(NULL)");
    }
    g_debug("%s", gbuf);
    FILE * oufx = fopen("/tmp/wireshark-ssh.log", "a");
    if(oufx){fprintf(oufx, "%s\n", gbuf);fclose(oufx);}
    wmem_free(NULL, gbuf);
#undef ALLOC_SIZE
}

void dump_bignum(const ssh_bignum * bn, const char * name)
{
    char buf[10*1024];
    int pos;
    guint cnt;
    buf[0] = 0;
    pos = 0;
    for(cnt=0;cnt<bn->length;cnt++){
        pos += snprintf(&buf[pos], sizeof(buf)-1-pos, "%02X", bn->data[cnt]);
    }
    g_debug("%s %s", name, buf);
}

static int
dissect_ssh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree  *ssh_tree;
    proto_item  *ti;
    conversation_t *conversation;
    int         last_offset, offset = 0;

    gboolean    is_response = (pinfo->destport != pinfo->match_uint),
                need_desegmentation;
    guint       version;

    struct ssh_flow_data *global_data = NULL;
    struct ssh_peer_data *peer_data;

    conversation = find_or_create_conversation(pinfo);

    global_data = (struct ssh_flow_data *)conversation_get_proto_data(conversation, proto_ssh);
    if (!global_data) {
        global_data = (struct ssh_flow_data *)wmem_alloc0(wmem_file_scope(), sizeof(struct ssh_flow_data));
        global_data->version = SSH_VERSION_UNKNOWN;
        global_data->kex_specific_dissector = ssh_dissect_kex_dh;
        global_data->peer_data[CLIENT_PEER_DATA].mac_length = -1;
        global_data->peer_data[SERVER_PEER_DATA].mac_length = -1;
#ifdef SSH_DECRYPTION_SUPPORTED
        global_data->peer_data[CLIENT_PEER_DATA].sequence_number = 0;
        global_data->peer_data[SERVER_PEER_DATA].sequence_number = 0;
        global_data->peer_data[CLIENT_PEER_DATA].bn_cookie = NULL;
        global_data->peer_data[SERVER_PEER_DATA].bn_cookie = NULL;
        global_data->peer_data[CLIENT_PEER_DATA].in_fragment = 0;
        global_data->peer_data[SERVER_PEER_DATA].in_fragment = 0;
        global_data->kex_client_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_version = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_client_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_key_exchange_init = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_server_host_key_blob = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_min = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_req = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_gex_bits_max = wmem_array_new(wmem_file_scope(), 1);
        global_data->kex_shared_secret = wmem_array_new(wmem_file_scope(), 1);
        global_data->do_decrypt      = TRUE;
        int err = truncate("/tmp/wireshark-ssh.log", 0);			// Truncate file
        (void)err;
#endif
        conversation_add_proto_data(conversation, proto_ssh, global_data);
    }

    peer_data = &global_data->peer_data[is_response];

    ti = proto_tree_add_item(tree, proto_ssh, tvb, offset, -1, ENC_NA);
    ssh_tree = proto_item_add_subtree(ti, ett_ssh);

    version = global_data->version;

    switch(version) {
    case SSH_VERSION_UNKNOWN:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSH");
        break;
    case SSH_VERSION_1:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv1");
        break;
    case SSH_VERSION_2:
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSHv2");
        break;

    }

    col_clear(pinfo->cinfo, COL_INFO);

    while(tvb_reported_length_remaining(tvb, offset)> 0) {
        gboolean after_version_start = (peer_data->frame_version_start == 0 ||
            pinfo->num >= peer_data->frame_version_start);
        gboolean before_version_end = (peer_data->frame_version_end == 0 ||
            pinfo->num <= peer_data->frame_version_end);

        need_desegmentation = FALSE;
        last_offset = offset;

        peer_data->counter++;

        if (after_version_start && before_version_end &&
              (tvb_strncaseeql(tvb, offset, "SSH-", 4) == 0)) {
            if (peer_data->frame_version_start == 0)
                peer_data->frame_version_start = pinfo->num;

            offset = ssh_dissect_protocol(tvb, pinfo,
                    global_data,
                    offset, ssh_tree, is_response,
                    &version, &need_desegmentation);

            if (!need_desegmentation) {
                peer_data->frame_version_end = pinfo->num;
                global_data->version = version;
            }
        } else {
            switch(version) {

            case SSH_VERSION_UNKNOWN:
                offset = ssh_try_dissect_encrypted_packet(tvb, pinfo,
                        &global_data->peer_data[is_response], offset, ssh_tree,
                        &need_desegmentation);
                break;

            case SSH_VERSION_1:
                offset = ssh_dissect_ssh1(tvb, pinfo, global_data,
                        offset, ssh_tree, is_response,
                        &need_desegmentation);
                break;

            case SSH_VERSION_2:
                offset = ssh_dissect_ssh2(tvb, pinfo, global_data,
                        offset, ssh_tree, is_response,
                        &need_desegmentation);
                break;
            }
        }

        if (need_desegmentation)
            return tvb_captured_length(tvb);
        if (offset <= last_offset) {
            /* XXX - add an expert info in the function
               that decrements offset */
            break;
        }
    }

    col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s: ", is_response ? "Server" : "Client");
    ti = proto_tree_add_boolean_format_value(ssh_tree, hf_ssh_direction, tvb, 0, 0, is_response, "%s",
        try_val_to_str(is_response, ssh_direction_vals));
    proto_item_set_generated(ti);
    return tvb_captured_length(tvb);
}

static int
ssh_dissect_ssh2(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    proto_item *ssh2_tree = NULL;
    gint remain_length;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    remain_length = tvb_captured_length_remaining(tvb, offset);

    while(remain_length>0){
        int last_offset = offset;
        if (tree) {
            wmem_strbuf_t *title = wmem_strbuf_new(wmem_packet_scope(), "SSH Version 2");

            if (peer_data->enc || peer_data->mac || peer_data->comp) {
                wmem_strbuf_append_printf(title, " (");
                if (peer_data->enc)
                    wmem_strbuf_append_printf(title, "encryption:%s%s",
                        peer_data->enc,
                        peer_data->mac || peer_data->comp
                            ? " " : "");
                if (peer_data->mac)
                    wmem_strbuf_append_printf(title, "mac:%s%s",
                        peer_data->mac,
                        peer_data->comp ? " " : "");
                if (peer_data->comp)
                    wmem_strbuf_append_printf(title, "compression:%s",
                        peer_data->comp);
                wmem_strbuf_append_printf(title, ")");
            }

            ssh2_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh2, NULL, wmem_strbuf_get_str(title));
        }

        if ((peer_data->frame_key_start == 0) ||
            ((peer_data->frame_key_start <= pinfo->num) &&
            ((peer_data->frame_key_end == 0) || (pinfo->num < peer_data->frame_key_end) ||
                    ((pinfo->num == peer_data->frame_key_end) && (offset < peer_data->frame_key_end_offset))))) {
            offset = ssh_dissect_key_exchange(tvb, pinfo, global_data,
                offset, ssh2_tree, is_response,
                need_desegmentation);

            if (!*need_desegmentation) {
                ssh_increment_message_number(pinfo, global_data, is_response);
            }
        } else {
            if(!*need_desegmentation){
                offset = ssh_try_dissect_encrypted_packet(tvb, pinfo,
                        &global_data->peer_data[is_response], offset, ssh2_tree,
                        need_desegmentation);
            }else{
                break;
            }
        }

        if (ssh2_tree) {
            proto_item_set_len(ssh2_tree, offset - last_offset);
        }

        remain_length = tvb_captured_length_remaining(tvb, offset);
    }

    return offset;
}
static int
ssh_dissect_ssh1(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    guint   plen, padding_length, len;
    guint8  msg_code;
    guint   remain_length;

    proto_item *ssh1_tree;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    ssh1_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_ssh1, NULL, "SSH Version 1");

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*
     * Can we do reassembly?
     */
    if (ssh_desegment && pinfo->can_desegment) {
        /*
         * Yes - would an SSH header starting at this offset be split
         * across segment boundaries?
         */
        if (remain_length < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;
    padding_length  = 8 - plen%8;


    if (ssh_desegment && pinfo->can_desegment) {
        if (plen+4+padding_length >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+padding_length - remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }

    if (plen >= 0xffff) {
        if (ssh1_tree && plen > 0) {
              proto_tree_add_uint_format(ssh1_tree, hf_ssh_packet_length, tvb,
                offset, 4, plen, "Overly large length %x", plen);
        }
        plen = remain_length-4-padding_length;
    } else {
        if (ssh1_tree && plen > 0) {
              proto_tree_add_uint(ssh1_tree, hf_ssh_packet_length, tvb,
                offset, 4, plen);
        }
    }
    offset+=4;
    /* padding length */

    proto_tree_add_uint(ssh1_tree, hf_ssh_padding_length, tvb,
            offset, padding_length, padding_length);
    offset += padding_length;

    /* msg_code */
    if ((peer_data->frame_key_start == 0) ||
        ((peer_data->frame_key_start >= pinfo->num) && (pinfo->num <= peer_data->frame_key_end))) {
        msg_code = tvb_get_guint8(tvb, offset);

        proto_tree_add_item(ssh1_tree, hf_ssh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_code, ssh1_msg_vals, "Unknown (%u)"));
        offset += 1;
        len = plen -1;
        if (!pinfo->fd->visited) {
            if (peer_data->frame_key_start == 0)
                peer_data->frame_key_start = pinfo->num;
            peer_data->frame_key_end = pinfo->num;
        }
    } else {
        len = plen;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", len);
    }
    /* payload */
    if (ssh1_tree) {
        proto_tree_add_item(ssh1_tree, hf_ssh_payload,
            tvb, offset, len, ENC_NA);
    }
    offset += len;

    return offset;
}

static int
ssh_tree_add_mpint(tvbuff_t *tvb, int offset, proto_tree *tree,
    int hf_ssh_mpint_selection)
{
    guint len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_mpint_length, tvb,
            offset, 4, len);
    offset+=4;
    proto_tree_add_item(tree, hf_ssh_mpint_selection,
            tvb, offset, len, ENC_NA);
    return 4+len;
}

static int
ssh_tree_add_string(tvbuff_t *tvb, int offset, proto_tree *tree,
    int hf_ssh_string, int hf_ssh_string_length)
{
    guint len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_string_length, tvb,
            offset, 4, len);
    offset+=4;
    proto_tree_add_item(tree, hf_ssh_string,
            tvb, offset, len, ENC_NA);
    return 4+len;
}

static guint
ssh_tree_add_hostkey(tvbuff_t *tvb, int offset, proto_tree *parent_tree,
                     const char *tree_name, int ett_idx,
                     struct ssh_flow_data *global_data)
{
    proto_tree *tree = NULL;
    int last_offset;
    int remaining_len;
    guint key_len, type_len;
    guint8* key_type;
    gchar *tree_title;

    last_offset = offset;

    key_len = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Read the key type before creating the tree so we can append it as info. */
    type_len = tvb_get_ntohl(tvb, offset);
    offset += 4;
    key_type = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, type_len, ENC_ASCII|ENC_NA);

    tree_title = wmem_strdup_printf(wmem_packet_scope(), "%s (type: %s)", tree_name, key_type);
    tree = proto_tree_add_subtree(parent_tree, tvb, last_offset, key_len + 4, ett_idx, NULL,
                                  tree_title);

    proto_tree_add_uint(tree, hf_ssh_hostkey_length, tvb, last_offset, 4, key_len);

    // server host key (K_S / Q)
#ifdef SSH_DECRYPTION_SUPPORTED
    gchar *data = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, last_offset + 4, key_len);
    ssh_hash_buffer_put_string(global_data->kex_server_host_key_blob, data, key_len);
g_debug("JH:%s - E xxxxxxxxxxxxxxxxxxxx", __FUNCTION__);
g_debug("JH:%s adding %d bytes to kex_server_host_key_blob new len=%d", __FUNCTION__, key_len, global_data->kex_server_host_key_blob?wmem_array_get_count(global_data->kex_server_host_key_blob):(guint)-1);

#else
    // ignore unused parameter complaint
    (void)global_data;
#endif

    last_offset += 4;
    proto_tree_add_uint(tree, hf_ssh_hostkey_type_length, tvb, last_offset, 4, type_len);
    proto_tree_add_string(tree, hf_ssh_hostkey_type, tvb, offset, type_len, key_type);
    offset += type_len;

    if (0 == strcmp(key_type, "ssh-rsa")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_e);
        ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_rsa_n);
    } else if (0 == strcmp(key_type, "ssh-dss")) {
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_p);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_q);
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_g);
        ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_hostkey_dsa_y);
    } else if (g_str_has_prefix(key_type, "ecdsa-sha2-")) {
        offset += ssh_tree_add_string(tvb, offset, tree,
                                      hf_ssh_hostkey_ecdsa_curve_id, hf_ssh_hostkey_ecdsa_curve_id_length);
        ssh_tree_add_string(tvb, offset, tree,
                            hf_ssh_hostkey_ecdsa_q, hf_ssh_hostkey_ecdsa_q_length);
    } else if (g_str_has_prefix(key_type, "ssh-ed")) {
        ssh_tree_add_string(tvb, offset, tree,
                            hf_ssh_hostkey_eddsa_key, hf_ssh_hostkey_eddsa_key_length);
    } else {
        remaining_len = key_len - (type_len + 4);
        proto_tree_add_item(tree, hf_ssh_hostkey_data, tvb, offset, remaining_len, ENC_NA);
    }

    return 4+key_len;
}

static int
ssh_dissect_key_exchange(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response,
        gboolean *need_desegmentation)
{
    guint   plen, len;
    guint8  padding_length;
    guint   remain_length;
    int     last_offset = offset;
    guint   msg_code;

    proto_item *ti;
    proto_item *key_ex_tree = NULL;
    const gchar *key_ex_title = "Key Exchange";

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*
     * Can we do reassembly?
     */
    if (ssh_desegment && pinfo->can_desegment) {
        /*
         * Yes - would an SSH header starting at this offset
         * be split across segment boundaries?
         */
        if (remain_length < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    plen = tvb_get_ntohl(tvb, offset) ;

    if (ssh_desegment && pinfo->can_desegment) {
        if (plen +4 >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+4 - remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    /*
     * Need to check plen > 0x80000000 here
     */

    ti = proto_tree_add_uint(tree, hf_ssh_packet_length, tvb,
                    offset, 4, plen);
    if (plen >= 0xffff) {
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_length, "Overly large number %d", plen);
        plen = remain_length-4;
    }
    offset+=4;

    /* padding length */
    padding_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, tvb, offset, 1, padding_length);
    offset += 1;

    if (global_data->kex)
        key_ex_title = wmem_strdup_printf(wmem_packet_scope(), "%s (method:%s)", key_ex_title, global_data->kex);
    key_ex_tree = proto_tree_add_subtree(tree, tvb, offset, plen-1, ett_key_exchange, NULL, key_ex_title);

    /* msg_code */
    msg_code = tvb_get_guint8(tvb, offset);

    if (msg_code >= 30 && msg_code < 40) {
        offset = global_data->kex_specific_dissector(msg_code, tvb, pinfo,
                offset, key_ex_tree, global_data);
    } else {
        proto_tree_add_item(key_ex_tree, hf_ssh2_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));

        /* 16 bytes cookie  */
        switch(msg_code)
        {
        case SSH_MSG_KEXINIT:
            if ((peer_data->frame_key_start == 0) || (peer_data->frame_key_start == pinfo->num)) {
                offset = ssh_dissect_key_init(tvb, pinfo, offset, key_ex_tree, is_response, global_data);
                peer_data->frame_key_start = pinfo->num;
            }
            break;
        case SSH_MSG_NEWKEYS:
            if (peer_data->frame_key_end == 0) {
                peer_data->frame_key_end = pinfo->num;
                peer_data->frame_key_end_offset = offset;
                ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].enc_proposals[is_response],
                                global_data->peer_data[SERVER_PEER_DATA].enc_proposals[is_response],
                                &peer_data->enc);

                /* some ciphers have their own MAC so the "negotiated" one is meaningless */
                if(peer_data->enc && (0 == strcmp(peer_data->enc, "aes128-gcm@openssh.com") ||
                                      0 == strcmp(peer_data->enc, "aes256-gcm@openssh.com"))) {
                    peer_data->mac = wmem_strdup(wmem_file_scope(), (const gchar *)"<implicit>");
                    peer_data->mac_length = 16;
                    peer_data->length_is_plaintext = 1;
                }
                else if(peer_data->enc && 0 == strcmp(peer_data->enc, "chacha20-poly1305@openssh.com")) {
                    peer_data->mac = wmem_strdup(wmem_file_scope(), (const gchar *)"<implicit>");
                    peer_data->mac_length = 16;
                }
                else {
                    ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].mac_proposals[is_response],
                                    global_data->peer_data[SERVER_PEER_DATA].mac_proposals[is_response],
                                    &peer_data->mac);
                    ssh_set_mac_length(peer_data);
                }

                ssh_choose_algo(global_data->peer_data[CLIENT_PEER_DATA].comp_proposals[is_response],
                                global_data->peer_data[SERVER_PEER_DATA].comp_proposals[is_response],
                                &peer_data->comp);

                // the client sent SSH_MSG_NEWKEYS
                if (!is_response) {
                    ssh_decryption_set_cipher_id(&global_data->peer_data[CLIENT_PEER_DATA]);
                    g_debug("JH: Activating new keys for CLIENT => SERVER");
                    ssh_decryption_setup_cipher(&global_data->peer_data[CLIENT_PEER_DATA], &global_data->new_keys[0], &global_data->new_keys[2]);
                }else{
                    ssh_decryption_set_cipher_id(&global_data->peer_data[SERVER_PEER_DATA]);
                    g_debug("JH: Activating new keys for SERVER => CLIENT");
                    ssh_decryption_setup_cipher(&global_data->peer_data[SERVER_PEER_DATA], &global_data->new_keys[1], &global_data->new_keys[3]);
                }

            }

            break;
        }
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(key_ex_tree, hf_ssh_payload, tvb, offset, len, ENC_NA);
    }
    offset += len;

    /* padding */
    proto_tree_add_item(tree, hf_ssh_padding_string, tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;

    return offset;
}

static int ssh_dissect_kex_dh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data)
{
    proto_tree_add_item(tree, hf_ssh2_kex_dh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_dh_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEXDH_INIT:
#ifdef SSH_DECRYPTION_SUPPORTED
        if (!PINFO_FD_VISITED(pinfo)) {
            // e (client ephemeral key public part)
            ssh_read_e(tvb, offset, global_data);
            print_hex(global_data->kex_e->data, global_data->kex_e->length, "ssh: JH recorded GEX e ");
        }
#endif


        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_e);
        break;

    case SSH_MSG_KEXDH_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);

#ifdef SSH_DECRYPTION_SUPPORTED
        if (!PINFO_FD_VISITED(pinfo)) {
            // f (server ephemeral key public part), K_S (host key)
            ssh_read_f(tvb, offset, global_data);
            print_hex(global_data->kex_f->data, global_data->kex_f->length, "ssh: JH recorded GEX f ");
            ssh_keylog_hash_write_secret(tvb, offset, global_data);
        }
#endif


        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_f);
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kex_h_sig, hf_ssh_kex_h_sig_length);
        break;
    }

    return offset;
}

static int ssh_dissect_kex_dh_gex(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data)
{
    proto_tree_add_item(tree, hf_ssh2_kex_dh_gex_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_dh_gex_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;

    case SSH_MSG_KEX_DH_GEX_GROUP:
#ifdef SSH_DECRYPTION_SUPPORTED
        // p (Group modulo)
        global_data->kex_gex_p = ssh_read_mpint(tvb, offset);
        dump_bignum(global_data->kex_gex_p, "ssh: JH recorded GEX p ");
#endif
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_p);
#ifdef SSH_DECRYPTION_SUPPORTED
        // g (Group generator)
        global_data->kex_gex_g = ssh_read_mpint(tvb, offset);
        dump_bignum(global_data->kex_gex_g, "ssh: JH recorded GEX g ");
#endif

        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_gex_g);
        break;

    case SSH_MSG_KEX_DH_GEX_INIT:
#ifdef SSH_DECRYPTION_SUPPORTED
        // e (Client public key)
        ssh_read_e(tvb, offset, global_data);
        print_hex(global_data->kex_e->data, global_data->kex_e->length, "ssh: JH recorded GEX e ");
#endif
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_e);
        break;

    case SSH_MSG_KEX_DH_GEX_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);
#ifdef SSH_DECRYPTION_SUPPORTED
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_read_f(tvb, offset, global_data);
            print_hex(global_data->kex_f->data, global_data->kex_f->length, "ssh: JH recorded GEX f ");
            // f (server ephemeral key public part), K_S (host key)
            ssh_keylog_hash_write_secret(tvb, offset, global_data);
        }
#endif
        offset += ssh_tree_add_mpint(tvb, offset, tree, hf_ssh_dh_f);
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kex_h_sig, hf_ssh_kex_h_sig_length);
        break;

    case SSH_MSG_KEX_DH_GEX_REQUEST:{

        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_min, tvb_get_ntohl(tvb, offset));
        }
        proto_tree_add_item(tree, hf_ssh_dh_gex_min, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_req, tvb_get_ntohl(tvb, offset));
        }
        proto_tree_add_item(tree, hf_ssh_dh_gex_nbits, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_hash_buffer_put_uint32(global_data->kex_gex_bits_max, tvb_get_ntohl(tvb, offset));
        }
        proto_tree_add_item(tree, hf_ssh_dh_gex_max, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;}
    }

    return offset;
}

static int
ssh_dissect_kex_ecdh(guint8 msg_code, tvbuff_t *tvb,
        packet_info *pinfo, int offset, proto_tree *tree,
        struct ssh_flow_data *global_data)
{
    proto_tree_add_item(tree, hf_ssh2_kex_ecdh_msg_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
        val_to_str(msg_code, ssh2_kex_ecdh_msg_vals, "Unknown (%u)"));

    switch (msg_code) {
    case SSH_MSG_KEX_ECDH_INIT:
#ifdef SSH_DECRYPTION_SUPPORTED
        ssh_read_e(tvb, offset, global_data);
#endif

        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_ecdh_q_c, hf_ssh_ecdh_q_c_length);
        break;

    case SSH_MSG_KEX_ECDH_REPLY:
        offset += ssh_tree_add_hostkey(tvb, offset, tree, "KEX host key",
                ett_key_exchange_host_key, global_data);

#ifdef SSH_DECRYPTION_SUPPORTED
        if (!PINFO_FD_VISITED(pinfo)) {
            ssh_read_f(tvb, offset, global_data);
            ssh_keylog_hash_write_secret(tvb, offset, global_data);
        }
#endif

        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_ecdh_q_s, hf_ssh_ecdh_q_s_length);
        offset += ssh_tree_add_string(tvb, offset, tree, hf_ssh_kex_h_sig, hf_ssh_kex_h_sig_length);
        break;
    }

    return offset;
}

static int
ssh_try_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree,
        gboolean *need_desegmentation)
{
#ifdef SSH_DECRYPTION_SUPPORTED
    gboolean can_decrypt = peer_data->cipher != NULL;

    if (can_decrypt) {
        return ssh_decrypt_packet(tvb, pinfo, peer_data, offset, tree, need_desegmentation);
    }
#endif

    return ssh_dissect_encrypted_packet(tvb, pinfo, peer_data, offset, tree);
}

static int
ssh_dissect_encrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data,
        int offset, proto_tree *tree)
{
    gint len;
    guint plen;

    len = tvb_reported_length_remaining(tvb, offset);
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", len);

    if (tree) {
        gint encrypted_len = len;

        if (len > 4 && peer_data->length_is_plaintext) {
            plen = tvb_get_ntohl(tvb, offset) ;
            proto_tree_add_uint(tree, hf_ssh_packet_length, tvb, offset, 4, plen);
            encrypted_len -= 4;
        }
        else if (len > 4) {
            proto_tree_add_item(tree, hf_ssh_packet_length_encrypted, tvb, offset, 4, ENC_NA);
            encrypted_len -= 4;
        }

        if (peer_data->mac_length>0)
            encrypted_len -= peer_data->mac_length;

        proto_tree_add_item(tree, hf_ssh_encrypted_packet,
                    tvb, offset+4, encrypted_len, ENC_NA);

        if (peer_data->mac_length>0)
            proto_tree_add_item(tree, hf_ssh_mac_string,
                tvb, offset+4+encrypted_len,
                peer_data->mac_length, ENC_NA);
    }
    offset += len;
    return offset;
}

static int
ssh_dissect_protocol(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_flow_data *global_data,
        int offset, proto_tree *tree, int is_response, guint * version,
        gboolean *need_desegmentation)
{
    guint   remain_length;
    gint    linelen, protolen;

    /*
     *  If the first packet do not contain the banner,
     *  it is dump in the middle of a flow or not a ssh at all
     */
    if (tvb_strncaseeql(tvb, offset, "SSH-", 4) != 0) {
        offset = ssh_dissect_encrypted_packet(tvb, pinfo,
            &global_data->peer_data[is_response], offset, tree);
        return offset;
    }

    if (!is_response) {
        if (tvb_strncaseeql(tvb, offset, "SSH-2.", 6) == 0) {
            *(version) = SSH_VERSION_2;
        } else if (tvb_strncaseeql(tvb, offset, "SSH-1.99-", 9) == 0) {
            *(version) = SSH_VERSION_2;
        } else if (tvb_strncaseeql(tvb, offset, "SSH-1.", 6) == 0) {
            *(version) = SSH_VERSION_1;
        }
    }

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(tvb, offset);
    /*linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
     */
    linelen = tvb_find_guint8(tvb, offset, -1, '\n');

    if (ssh_desegment && pinfo->can_desegment) {
        if (linelen == -1 || remain_length < (guint)linelen-offset) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = linelen-remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    if (linelen == -1) {
        /* XXX - reassemble across segment boundaries? */
        linelen = remain_length;
        protolen = linelen;
    } else {
        linelen = linelen - offset + 1;

        if (linelen > 1 && tvb_get_guint8(tvb, offset + linelen - 2) == '\r')
            protolen = linelen - 2;
        else
            protolen = linelen - 1;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Protocol (%s)",
            tvb_format_text(tvb, offset, protolen));

    // V_C / V_S (client and server identification strings) RFC4253 4.2
    // format: SSH-protoversion-softwareversion SP comments [CR LF not incl.]
#ifdef SSH_DECRYPTION_SUPPORTED
    if (!PINFO_FD_VISITED(pinfo)) {
        gchar *data = (gchar *)tvb_memdup(wmem_packet_scope(), tvb, offset, protolen);
        if(!is_response){
            ssh_hash_buffer_put_string(global_data->kex_client_version, data, protolen);
        }else{
            ssh_hash_buffer_put_string(global_data->kex_server_version, data, protolen);
        }
    }
#endif

    proto_tree_add_item(tree, hf_ssh_protocol,
                    tvb, offset, protolen, ENC_ASCII|ENC_NA);
    offset += linelen;
    return offset;
}

static void
ssh_set_mac_length(struct ssh_peer_data *peer_data)
{
    char *size_str;
    guint32 size = 0;
    char *mac_name = peer_data->mac;
    char *strip;

    if (!mac_name)
        return;

    /* wmem_strdup() never returns NULL */
    mac_name = wmem_strdup(NULL, (const gchar *)mac_name);

    /* strip trailing "-etm@openssh.com" or "@openssh.com" */
    strip = strstr(mac_name, "-etm@openssh.com");
    if (strip) {
        peer_data->length_is_plaintext = 1;
        *strip = '\0';
    }
    else {
        strip = strstr(mac_name, "@openssh.com");
        if (strip) *strip = '\0';
    }

    size_str = g_strrstr(mac_name, "-");
    if (size_str && ws_strtou32(size_str + 1, NULL, &size) && size > 0 && size % 8 == 0) {
        peer_data->mac_length = size / 8;
    }
    else if (strcmp(mac_name, "hmac-sha1") == 0) {
        peer_data->mac_length = 20;
    }
    else if (strcmp(mac_name, "hmac-md5") == 0) {
        peer_data->mac_length = 16;
    }
    else if (strcmp(mac_name, "hmac-ripemd160") == 0) {
        peer_data->mac_length = 20;
    }
    else if (strcmp(mac_name, "none") == 0) {
        peer_data->mac_length = 0;
    }

    wmem_free(NULL, mac_name);
}

static void ssh_set_kex_specific_dissector(struct ssh_flow_data *global_data)
{
    const char *kex_name = global_data->kex;

    if (!kex_name) return;

    if (strcmp(kex_name, "diffie-hellman-group-exchange-sha1") == 0 ||
        strcmp(kex_name, "diffie-hellman-group-exchange-sha256") == 0)
    {
        global_data->kex_specific_dissector = ssh_dissect_kex_dh_gex;
    }
    else if (g_str_has_prefix(kex_name, "ecdh-sha2-") ||
        strcmp(kex_name, "curve25519-sha256@libssh.org") == 0 ||
        strcmp(kex_name, "curve25519-sha256") == 0 ||
        strcmp(kex_name, "curve448-sha512") == 0)
    {
        global_data->kex_specific_dissector = ssh_dissect_kex_ecdh;
    }
}

static gint
ssh_gslist_compare_strings(gconstpointer a, gconstpointer b)
{
    if (a == NULL && b == NULL)
        return 0;
    if (a == NULL)
        return -1;
    if (b == NULL)
        return 1;
    return strcmp((const char*)a, (const char*)b);
}

/* expects that *result is NULL */
static void
ssh_choose_algo(gchar *client, gchar *server, gchar **result)
{
    gchar **server_strings = NULL;
    gchar **client_strings = NULL;
    gchar **step;
    GSList *server_list = NULL;

    if (!client || !server || !result || *result)
        return;

    server_strings = g_strsplit(server, ",", 0);
    for (step = server_strings; *step; step++) {
        server_list = g_slist_append(server_list, *step);
    }

    client_strings = g_strsplit(client, ",", 0);
    for (step = client_strings; *step; step++) {
        GSList *agreed;
        if ((agreed = g_slist_find_custom(server_list, *step, ssh_gslist_compare_strings))) {
            *result = wmem_strdup(wmem_file_scope(), (const gchar *)agreed->data);
            break;
        }
    }

    g_strfreev(client_strings);
    g_slist_free(server_list);
    g_strfreev(server_strings);
}

static int
ssh_dissect_key_init(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree,
        int is_response, struct ssh_flow_data *global_data)
{
    int start_offset = offset;
    int payload_length;

    proto_item *tf;
    proto_tree *key_init_tree;

    struct ssh_peer_data *peer_data = &global_data->peer_data[is_response];

    key_init_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_key_init, &tf, "Algorithms");
    peer_data->bn_cookie = ssh_kex_make_bignum(tvb_get_ptr(tvb, offset, 16), 16);
    proto_tree_add_item(key_init_tree, hf_ssh_cookie,
                    tvb, offset, 16, ENC_NA);
    offset += 16;

    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_kex_algorithms_length, hf_ssh_kex_algorithms,
        &peer_data->kex_proposal);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_server_host_key_algorithms_length,
        hf_ssh_server_host_key_algorithms, NULL);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_encryption_algorithms_client_to_server_length,
        hf_ssh_encryption_algorithms_client_to_server,
        &peer_data->enc_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_encryption_algorithms_server_to_client_length,
        hf_ssh_encryption_algorithms_server_to_client,
        &peer_data->enc_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_mac_algorithms_client_to_server_length,
        hf_ssh_mac_algorithms_client_to_server,
        &peer_data->mac_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_mac_algorithms_server_to_client_length,
        hf_ssh_mac_algorithms_server_to_client,
        &peer_data->mac_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_compression_algorithms_client_to_server_length,
        hf_ssh_compression_algorithms_client_to_server,
        &peer_data->comp_proposals[CLIENT_TO_SERVER_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_compression_algorithms_server_to_client_length,
        hf_ssh_compression_algorithms_server_to_client,
        &peer_data->comp_proposals[SERVER_TO_CLIENT_PROPOSAL]);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_languages_client_to_server_length,
        hf_ssh_languages_client_to_server, NULL);
    offset = ssh_dissect_proposal(tvb, offset, key_init_tree,
        hf_ssh_languages_server_to_client_length,
        hf_ssh_languages_server_to_client, NULL);

    proto_tree_add_item(key_init_tree, hf_ssh_first_kex_packet_follows,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    proto_tree_add_item(key_init_tree, hf_ssh_kex_reserved,
        tvb, offset, 4, ENC_NA);
    offset+=4;

    if (global_data->peer_data[CLIENT_PEER_DATA].kex_proposal &&
        global_data->peer_data[SERVER_PEER_DATA].kex_proposal &&
        !global_data->kex)
    {
        /* Note: we're ignoring first_kex_packet_follows. */
        ssh_choose_algo(
            global_data->peer_data[CLIENT_PEER_DATA].kex_proposal,
            global_data->peer_data[SERVER_PEER_DATA].kex_proposal,
            &global_data->kex);
        ssh_set_kex_specific_dissector(global_data);
    }

    payload_length = offset - start_offset;

    if (tf != NULL) {
        proto_item_set_len(tf, payload_length);
    }

#ifdef SSH_DECRYPTION_SUPPORTED
    // I_C / I_S (client and server SSH_MSG_KEXINIT payload) RFC4253 4.2
    if (!PINFO_FD_VISITED(pinfo)) {
        gchar *data = (gchar *)wmem_alloc(wmem_packet_scope(), payload_length + 1);
        tvb_memcpy(tvb, data + 1, start_offset, payload_length);
        data[0] = SSH_MSG_KEXINIT;
        if(is_response){
            ssh_hash_buffer_put_string(global_data->kex_server_key_exchange_init, data, payload_length + 1);
        }else{
            ssh_hash_buffer_put_string(global_data->kex_client_key_exchange_init, data, payload_length + 1);
        }
    }
#endif

    return offset;
}

static int
ssh_dissect_proposal(tvbuff_t *tvb, int offset, proto_tree *tree,
             int hf_index_length, int hf_index_value, gchar **store)
{
    guint32 len = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_index_length, tvb, offset, 4, len);
    offset += 4;

    proto_tree_add_item(tree, hf_index_value, tvb, offset, len,
                ENC_ASCII);
    if (store)
        *store = tvb_get_string_enc(wmem_file_scope(), tvb, offset, len, ENC_ASCII);
    offset += len;

    return offset;
}

#ifdef SSH_DECRYPTION_SUPPORTED
static void
ssh_keylog_read_file(void)
{
    if (!pref_keylog_file || !*pref_keylog_file) {
        g_debug("no keylog file preference set");
        return;
    }

    if (ssh_keylog_file && file_needs_reopen(ws_fileno(ssh_keylog_file),
                pref_keylog_file)) {
        ssh_keylog_reset();
    }

    if (!ssh_keylog_file) {
        ssh_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!ssh_keylog_file) {
            g_debug("ssh: failed to open key log file %s: %s",
                    pref_keylog_file, g_strerror(errno));
            return;
        }
    }

    /* File format: each line follows the format "<cookie> <key>".
     * <cookie> is the hex-encoded (client or server) 16 bytes cookie
     * (32 characters) found in the SSH_MSG_KEXINIT of the endpoint whose
     * private random is disclosed.
     * <key> is the private random number that is used to generate the DH
     * negotiation (length depends on algorithm). In RFC4253 it is called
     * x for the client and y for the server.
     * For openssh and DH group exchange, it can be retrieved using
     * DH_get0_key(kex->dh, NULL, &server_random)
     * for groupN in file kexdh.c function kex_dh_compute_key
     * for custom group in file kexgexs.c function input_kex_dh_gex_init
     * For openssh and curve25519, it can be found in function kex_c25519_enc
     * in variable server_key.
     *
     * Example:
     *  90d886612f9c35903db5bb30d11f23c2 DEF830C22F6C927E31972FFB20B46C96D0A5F2D5E7BE5A3A8804D6BFC431619ED10AF589EEDFF4750DEA00EFD7AFDB814B6F3528729692B1F2482041521AE9DC
     */
    for (;;) {
        char buf[512];
        buf[0] = 0;

        if (!fgets(buf, sizeof(buf), ssh_keylog_file)) {
            if (ferror(ssh_keylog_file)) {
                g_debug("Error while reading %s, closing it.", pref_keylog_file);
                ssh_keylog_reset();
            }
            break;
        }

        size_t len = strlen(buf);
        while(len>0 && (buf[len-1]=='\r' || buf[len-1]=='\n')){len-=1;buf[len]=0;}

        ssh_keylog_process_line(buf);
    }
}

static void
ssh_keylog_process_lines(const guint8 *data, guint datalen)
{
    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    while (next_line && next_line < line_end) {
        const char *line = next_line;
        next_line = (const char *)memchr(line, '\n', line_end - line);
        gssize linelen;

        if (next_line) {
            linelen = next_line - line;
            next_line++;    /* drop LF */
        } else {
            linelen = (gssize)(line_end - line);
        }
        if (linelen > 0 && line[linelen - 1] == '\r') {
            linelen--;      /* drop CR */
        }

        ssh_debug_printf("  checking keylog line: %.*s\n", (int)linelen, line);

        gchar * strippedline = g_strndup(line, linelen);
        ssh_keylog_process_line(strippedline);
        g_free(strippedline);
    }
}

static void
ssh_keylog_process_line(const char *line)
{
    g_debug("ssh: process line: %s", line);

    gchar **split = g_strsplit(line, " ", 2);
    gchar *cookie, *key;
    int cookie_len, key_len;

    if (g_strv_length(split) < 2) {
        g_debug("ssh keylog: invalid format");
        g_strfreev(split);
        return;
    }

// [cookie of corresponding key] [key]
    cookie = split[0];
    key = split[1];

    key_len = strlen(key);
    cookie_len = strlen(cookie);
dump_ssh_style(cookie, cookie_len, "cookie");
dump_ssh_style(key, key_len, "key");
    if(key_len & 1){
        g_debug("ssh keylog: invalid format (key could at least be even!)");
        g_strfreev(split);
        return;
    }
    if(cookie_len & 1){
        g_debug("ssh keylog: invalid format (cookie could at least be even!)");
        g_strfreev(split);
        return;
    }
    ssh_bignum * bn_cookie = ssh_kex_make_bignum(NULL, cookie_len/2);
    ssh_bignum * bn_priv   = ssh_kex_make_bignum(NULL, key_len/2);
    guint8 c;
    for (int i = 0; i < key_len/2; i ++) {
        gchar v0 = key[i * 2];
        gint8 h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        gchar v1 = key[i * 2 + 1];
        gint8 h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            g_debug("ssh: can't process key, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_priv->data[i] = c;
    }

    for (int i = 0; i < cookie_len/2; i ++) {
        gchar v0 = cookie[i * 2];
        gint8 h0 = (v0>='0' && v0<='9')?v0-'0':(v0>='a' && v0<='f')?v0-'a'+10:(v0>='A' && v0<='F')?v0-'A'+10:-1;
        gchar v1 = cookie[i * 2 + 1];
        gint8 h1 = (v1>='0' && v1<='9')?v1-'0':(v1>='a' && v1<='f')?v1-'a'+10:(v1>='A' && v1<='F')?v1-'A'+10:-1;

        if (h0==-1 || h1==-1) {
            g_debug("ssh: can't process cookie, invalid hex number: %c%c", v0, v1);
            g_strfreev(split);
            return;
        }

        c = (h0 << 4) | h1;

        bn_cookie->data[i] = c;
    }
    g_debug("ssh: JH key accepted");
    g_hash_table_insert(ssh_master_key_map, bn_cookie, bn_priv);
    g_strfreev(split);
}

static void
ssh_keylog_reset(void)
{
    if (ssh_keylog_file) {
        fclose(ssh_keylog_file);
        ssh_keylog_file = NULL;
    }
}

static guint
ssh_kex_type(gchar *type)
{
    if (g_str_has_prefix(type, "curve25519")) {
        return SSH_KEX_CURVE25519;
    }else if (g_str_has_prefix(type, "diffie-hellman-group-exchange")) {
        return SSH_KEX_DH_GEX;
    }else if (g_str_has_prefix(type, "diffie-hellman-group14")) {
        return SSH_KEX_DH_GROUP14;
    }else if (g_str_has_prefix(type, "diffie-hellman-group16")) {
        return SSH_KEX_DH_GROUP16;
    }else if (g_str_has_prefix(type, "diffie-hellman-group18")) {
        return SSH_KEX_DH_GROUP18;
    }else if (g_str_has_prefix(type, "diffie-hellman-group1")) {
        return SSH_KEX_DH_GROUP1;
    }

    return 0;
}

static guint
ssh_kex_hash_type(gchar *type)
{
    if (g_str_has_suffix(type, "sha1")) {
        return SSH_KEX_HASH_SHA1;
    }else if (g_str_has_suffix(type, "sha256")) {
        return SSH_KEX_HASH_SHA256;
    }else if (g_str_has_suffix(type, "sha512")) {
        return SSH_KEX_HASH_SHA512;
    }

    return 0;
}

static ssh_bignum *
ssh_kex_make_bignum(const guint8 *data, guint length)
{
    ssh_bignum *bn = wmem_new0(wmem_file_scope(), ssh_bignum);
    bn->data = (guint8 *)wmem_alloc0(wmem_file_scope(), length);

    if (data) {
        memcpy(bn->data, data, length);
    }

    bn->length = length;
    return bn;
}

static void
ssh_read_e(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the client's public part (e) for later usage
    int length = tvb_get_ntohl(tvb, offset);
    global_data->kex_e = ssh_kex_make_bignum(NULL, length);
    tvb_memcpy(tvb, global_data->kex_e->data, offset + 4, length);
}

static void
ssh_read_f(tvbuff_t *tvb, int offset, struct ssh_flow_data *global_data)
{
    // store the server's public part (f) for later usage
    int length = tvb_get_ntohl(tvb, offset);
    global_data->kex_f = ssh_kex_make_bignum(NULL, length);
    tvb_memcpy(tvb, global_data->kex_f->data, offset + 4, length);
}

static ssh_bignum *
ssh_read_mpint(tvbuff_t *tvb, int offset)
{
    // store the DH group modulo (p) for later usage
    int length = tvb_get_ntohl(tvb, offset);
    ssh_bignum * bn = ssh_kex_make_bignum(NULL, length);
    tvb_memcpy(tvb, bn->data, offset + 4, length);
    return bn;
}

static void
ssh_keylog_hash_write_secret(tvbuff_t *tvb, int offset,
        struct ssh_flow_data *global_data)
{
    /*
     * This computation is defined differently for each key exchange method:
     * https://tools.ietf.org/html/rfc4253#page-23
     * https://tools.ietf.org/html/rfc5656#page-8
     * https://tools.ietf.org/html/rfc4419#page-4
     * All key exchange methods:
     * https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-16
     */

    gcry_md_hd_t hd;
    ssh_bignum *secret = NULL, *priv;
    int length;

    ssh_keylog_read_file();

    length = tvb_get_ntohl(tvb, offset);
    guint kex_type = ssh_kex_type(global_data->kex);
    guint kex_hash_type = ssh_kex_hash_type(global_data->kex);

    priv = (ssh_bignum *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[SERVER_PEER_DATA].bn_cookie);
    if(priv){
        secret = ssh_kex_shared_secret(kex_type, global_data->kex_e, priv, global_data->kex_gex_p);
    }else{
        priv = (ssh_bignum *)g_hash_table_lookup(ssh_master_key_map, global_data->peer_data[CLIENT_PEER_DATA].bn_cookie);
        if(priv){
            secret = ssh_kex_shared_secret(kex_type, global_data->kex_f, priv, global_data->kex_gex_p);
        }
    }

    if (!secret) {
        g_debug("ssh decryption: no private key for this session");
        global_data->do_decrypt = FALSE;
        return;
    }

char a2h[] = "0123456789ABCDEF";
gchar *sbuf = (gchar *)wmem_alloc0(wmem_packet_scope(), 1024*1024);
size_t cnts;
for(cnts=0;cnts<secret->length;cnts++){
    sbuf[2*cnts+0] = a2h[(secret->data[cnts] >> 4) & 0xF];
    sbuf[2*cnts+1] = a2h[(secret->data[cnts] >> 0) & 0xF];
}
sbuf[2*cnts+0] = 0;
g_debug("%s l=%d\n%s", "secret", secret->length, sbuf);

    // shared secret data needs to be written as an mpint, and we need it later
    if (secret->data[0] & 0x80) {         // Stored in Big endian?
//    if (secret->data[secret->length-1] & 0x80) {         // Stored in Little endian?
        length = secret->length + 1;
        gchar *tmp = (gchar *)wmem_alloc0(wmem_packet_scope(), length);
        memcpy(tmp + 1, secret->data, secret->length);
        tmp[0] = 0;
        secret->data = tmp;
        secret->length = length;
    } else {
    }
    ssh_hash_buffer_put_string(global_data->kex_shared_secret, secret->data, secret->length);

//    ssh_hash_buffer_put_string(global_data->kex_shared_secret, secret->data, secret->length);
//    dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_hash_buffer), wmem_array_get_count(global_data->kex_hash_buffer), "exchange");

    wmem_array_t    * kex_gex_p = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_gex_p){ssh_hash_buffer_put_string(kex_gex_p, global_data->kex_gex_p->data, global_data->kex_gex_p->length);}
    wmem_array_t    * kex_gex_g = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_gex_g){ssh_hash_buffer_put_string(kex_gex_g, global_data->kex_gex_g->data, global_data->kex_gex_g->length);}
    wmem_array_t    * kex_e = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_e){ssh_hash_buffer_put_string(kex_e, global_data->kex_e->data, global_data->kex_e->length);}
    wmem_array_t    * kex_f = wmem_array_new(wmem_packet_scope(), 1);
    if(global_data->kex_f){ssh_hash_buffer_put_string(kex_f, global_data->kex_f->data, global_data->kex_f->length);}

dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version), "client_version");
dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version), "server_version");
dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init), "client_key_exchange_init");
dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init), "server_key_exchange_init");
dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob), "kex_server_host_key_blob");
if(kex_type==SSH_KEX_DH_GEX){
    dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_gex_bits_min), wmem_array_get_count(global_data->kex_gex_bits_min), "kex_gex_bits_min");
    dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_gex_bits_req), wmem_array_get_count(global_data->kex_gex_bits_req), "kex_gex_bits_req");
    dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_gex_bits_max), wmem_array_get_count(global_data->kex_gex_bits_max), "kex_gex_bits_max");
    dump_ssh_style((char *)wmem_array_get_raw(kex_gex_p), wmem_array_get_count(kex_gex_p), "key modulo  (p)");
    dump_ssh_style((char *)wmem_array_get_raw(kex_gex_g), wmem_array_get_count(kex_gex_g), "key base    (g)");
    dump_ssh_style((char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e), "key client  (e)");
    dump_ssh_style((char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f), "key serveur (f)");
}
if(kex_type==SSH_KEX_DH_GROUP1 || kex_type==SSH_KEX_DH_GROUP14 || kex_type==SSH_KEX_DH_GROUP16 || kex_type==SSH_KEX_DH_GROUP18){
    dump_ssh_style((char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e), "key client  (e)");
    dump_ssh_style((char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f), "key serveur (f)");
}
if(kex_type==SSH_KEX_CURVE25519){
    dump_ssh_style((char *)wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e), "key client  (Q_C)");
    dump_ssh_style((char *)wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f), "key serveur (Q_S)");
}
dump_ssh_style((char *)wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret), "shared secret");

    wmem_array_t    * kex_hash_buffer = wmem_array_new(wmem_packet_scope(), 1);
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_server_host_key_blob), wmem_array_get_count(global_data->kex_server_host_key_blob));
    if(kex_type==SSH_KEX_DH_GEX){
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_min), wmem_array_get_count(global_data->kex_gex_bits_min));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_req), wmem_array_get_count(global_data->kex_gex_bits_req));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_gex_bits_max), wmem_array_get_count(global_data->kex_gex_bits_max));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_gex_p), wmem_array_get_count(kex_gex_p));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_gex_g), wmem_array_get_count(kex_gex_g));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    if(kex_type==SSH_KEX_DH_GROUP1 || kex_type==SSH_KEX_DH_GROUP14 || kex_type==SSH_KEX_DH_GROUP16 || kex_type==SSH_KEX_DH_GROUP18){
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    if(kex_type==SSH_KEX_CURVE25519){
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_e), wmem_array_get_count(kex_e));
        wmem_array_append(kex_hash_buffer, wmem_array_get_raw(kex_f), wmem_array_get_count(kex_f));
    }
    wmem_array_append(kex_hash_buffer, wmem_array_get_raw(global_data->kex_shared_secret), wmem_array_get_count(global_data->kex_shared_secret));

    dump_ssh_style((char *)wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer), "exchange");

    guint hash_len = 32;
    if(kex_hash_type==SSH_KEX_HASH_SHA1){
        gcry_md_open(&hd, GCRY_MD_SHA1, 0);
        hash_len = 20;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA256){
        gcry_md_open(&hd, GCRY_MD_SHA256, 0);
        hash_len = 32;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA512){
        gcry_md_open(&hd, GCRY_MD_SHA512, 0);
        hash_len = 64;
    }
    gchar *exchange_hash = (gchar *)wmem_alloc0(wmem_file_scope(), hash_len);
/*    gcry_md_write(hd, wmem_array_get_raw(global_data->kex_client_version), wmem_array_get_count(global_data->kex_client_version));
    gcry_md_write(hd, wmem_array_get_raw(global_data->kex_server_version), wmem_array_get_count(global_data->kex_server_version));
    gcry_md_write(hd, wmem_array_get_raw(global_data->kex_client_key_exchange_init), wmem_array_get_count(global_data->kex_client_key_exchange_init));
    gcry_md_write(hd, wmem_array_get_raw(global_data->kex_server_key_exchange_init), wmem_array_get_count(global_data->kex_server_key_exchange_init));
    gcry_md_write(hd, wmem_array_get_raw(global_data->kex_hash_buffer), wmem_array_get_count(global_data->kex_hash_buffer));*/
    gcry_md_write(hd, wmem_array_get_raw(kex_hash_buffer), wmem_array_get_count(kex_hash_buffer));
    memcpy(exchange_hash, gcry_md_read(hd, 0), hash_len);
    gcry_md_close(hd);
    dump_ssh_style(exchange_hash, hash_len, "hash");
    global_data->secret = secret;
    ssh_derive_symmetric_keys(secret, exchange_hash, hash_len, global_data);
}

// the purpose of this function is to deal with all different kex methods
static ssh_bignum *
ssh_kex_shared_secret(gint kex_type, ssh_bignum *pub, ssh_bignum *priv, ssh_bignum *modulo)
{
    g_debug("JH: ssh_kex_shared_secret");
    ssh_bignum *secret = ssh_kex_make_bignum(NULL, pub->length);
    if (!secret) {
        g_debug("invalid key length %u", pub->length);
        return NULL;
    }

    if(kex_type==SSH_KEX_DH_GEX){
        gcry_mpi_t b = NULL;
        gcry_mpi_scan(&b, GCRYMPI_FMT_USG, pub->data, pub->length, NULL);
        gcry_mpi_t d = NULL, e = NULL, m = NULL;
        size_t result_len = 0;
        d = gcry_mpi_new(pub->length*8);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, priv->data, priv->length, NULL);
        gcry_mpi_scan(&m, GCRYMPI_FMT_USG, modulo->data, modulo->length, NULL);
        gcry_mpi_powm(d, b, e, m);                 // gcry_mpi_powm(d, b, e, m)    => d = b^e % m
        gcry_mpi_print(GCRYMPI_FMT_USG, secret->data, secret->length, &result_len, d);
        secret->length = (guint)result_len;        // Should not be larger than what fits in a 32-bit unsigned integer...
        gcry_mpi_release(d);
        gcry_mpi_release(b);
        gcry_mpi_release(e);
        gcry_mpi_release(m);
//        dump_bignum(secret, "shared secret");
//        print_hex(secret->data, secret->length, "ssh: JH shared secret");
//        dump_ssh_style(secret->data, secret->length, "shared secret");
    }else if(kex_type==SSH_KEX_DH_GROUP1 || kex_type==SSH_KEX_DH_GROUP14 || kex_type==SSH_KEX_DH_GROUP16 || kex_type==SSH_KEX_DH_GROUP18){
        gcry_mpi_t m = NULL;
// diffie-hellman-group14-sha1
        if(kex_type==SSH_KEX_DH_GROUP1){
            static const guint8 p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP14){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            static const guint8 p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP16){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
            static const guint8 p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 
                    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 
                    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 
                    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 
                    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 
                    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 
                    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 
                    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 
                    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 
                    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 
                    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 
                    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 
                    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 
                    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 
                    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9, 
                    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F, 
                    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }else if(kex_type==SSH_KEX_DH_GROUP18){
//p:FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
            static const guint8 p[] = {
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 
                    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 
                    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 
                    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 
                    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 
                    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 
                    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 
                    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 
                    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 
                    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 
                    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 
                    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 
                    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 
                    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 
                    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 
                    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 
                    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 
                    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 
                    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 
                    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 
                    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 
                    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 
                    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 
                    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7, 
                    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C, 
                    0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 
                    0xDB, 0xBB, 0xC2, 0xDB, 0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 
                    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 
                    0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 
                    0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9, 
                    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F, 
                    0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92, 0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 
                    0xC1, 0xD4, 0xDC, 0xB2, 0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD, 
                    0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F, 0x41, 0x30, 0x01, 0xAE, 
                    0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31, 0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 
                    0xDA, 0x3E, 0xDB, 0xEB, 0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B, 
                    0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51, 0x2B, 0xD7, 0xAF, 0x42, 
                    0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF, 0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 
                    0xF0, 0x32, 0xEA, 0x15, 0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6, 
                    0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31, 0x90, 0x0B, 0x1C, 0x9E, 
                    0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3, 0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 
                    0x0F, 0x1D, 0x45, 0xB7, 0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA, 
                    0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2, 0x0F, 0x80, 0x37, 0xE0, 
                    0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28, 0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 
                    0xF5, 0x50, 0xAA, 0x3D, 0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C, 
                    0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7, 0x6E, 0x3C, 0x04, 0x68, 
                    0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE, 0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 
                    0xE6, 0x94, 0xF9, 0x1E, 0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4, 
                    0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0, 0x73, 0xB9, 0x31, 0xBA, 
                    0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00, 0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED, 
                    0x25, 0x76, 0xF6, 0x93, 0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68, 
                    0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB, 0xE3, 0x9D, 0x65, 0x2D, 
                    0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9, 0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 
                    0x13, 0xEB, 0x57, 0xA8, 0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B, 
                    0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F, 0xA2, 0xC0, 0x87, 0xE8, 
                    0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A, 0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 
                    0x6D, 0x2A, 0x13, 0xF8, 0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36, 
                    0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5, 0x08, 0x46, 0x85, 0x1D, 
                    0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1, 0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 
                    0xFA, 0xF3, 0x6B, 0xC3, 0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92, 
                    0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E, 0xD5, 0xEE, 0x38, 0x2B, 
                    0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47, 0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA, 
                    0x9E, 0x30, 0x50, 0xE2, 0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71, 
                    0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,};
            gcry_mpi_scan(&m, GCRYMPI_FMT_USG, p, sizeof(p), NULL);
        }

        gcry_mpi_t b = NULL;
        gcry_mpi_scan(&b, GCRYMPI_FMT_USG, pub->data, pub->length, NULL);
        gcry_mpi_t d = NULL, e = NULL;
        size_t result_len = 0;
        d = gcry_mpi_new(pub->length*8);
        gcry_mpi_scan(&e, GCRYMPI_FMT_USG, priv->data, priv->length, NULL);
        gcry_mpi_powm(d, b, e, m);                 // gcry_mpi_powm(d, b, e, m)    => d = b^e % m
        gcry_mpi_print(GCRYMPI_FMT_USG, secret->data, secret->length, &result_len, d);
        secret->length = (guint)result_len;        // Should not be larger than what fits in a 32-bit unsigned integer...
        gcry_mpi_release(d);
        gcry_mpi_release(b);
        gcry_mpi_release(e);
        gcry_mpi_release(m);
    }else if(kex_type==SSH_KEX_CURVE25519){
        if (crypto_scalarmult_curve25519(secret->data, priv->data, pub->data)) {
            g_debug("curve25519: can't compute shared secret");
            return NULL;
        }
    }

    print_hex(secret->data, secret->length, "ssh: JH shared secret");
    dump_ssh_style(secret->data, secret->length, "shared secret");

    return secret;
}

static gchar *
ssh_string(const gchar *string, guint length)
{
    gchar *ssh_string = (gchar *)wmem_alloc(wmem_packet_scope(), length + 4);
    ssh_string[0] = (length >> 24) & 0xff;
    ssh_string[1] = (length >> 16) & 0xff;
    ssh_string[2] = (length >> 8) & 0xff;
    ssh_string[3] = length & 0xff;
    memcpy(ssh_string + 4, string, length);
    return ssh_string;
}

static void
ssh_hash_buffer_put_string(wmem_array_t *buffer, const gchar *string,
        guint length)
{
    if (!buffer) {
        return;
    }

    gchar *string_with_length = ssh_string(string, length);
    wmem_array_append(buffer, string_with_length, length + 4);
}

static void
ssh_hash_buffer_put_uint32(wmem_array_t *buffer, guint val)
{
    if (!buffer) {
        return;
    }

    gchar buf[4];
    buf[0] = (val >> 24); buf[1] = (val >> 16); buf[2] = (val >>  8); buf[3] = (val >>  0);
    wmem_array_append(buffer, buf, 4);
}

static void ssh_derive_symmetric_keys(ssh_bignum *secret, gchar *exchange_hash,
        guint hash_length, struct ssh_flow_data *global_data)
{
    if (!global_data->session_id) {
        global_data->session_id = exchange_hash;
        global_data->session_id_length = hash_length;
    }

    for (int i = 0; i < 6; i ++) {
        ssh_derive_symmetric_key(secret, exchange_hash, hash_length,
                'A' + i, &global_data->new_keys[i], global_data);
        if(i==0){       dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Initial IV client to server");
        }else if(i==1){ dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Initial IV server to client");
        }else if(i==2){ dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Encryption key client to server");
        }else if(i==3){ dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Encryption key server to client");
        }else if(i==4){ dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Integrity key client to server");
        }else if(i==5){ dump_ssh_style(global_data->new_keys[i].data, global_data->new_keys[i].length, "Integrity key server to client");
        }
    }

/*    ssh_decryption_setup_cipher(&global_data->peer_data[CLIENT_PEER_DATA],
            &keys[0], &keys[2]);
    ssh_decryption_setup_cipher(&global_data->peer_data[SERVER_PEER_DATA],
            &keys[1], &keys[3]);*/
}

static void ssh_derive_symmetric_key(ssh_bignum *secret, gchar *exchange_hash,
        guint hash_length, gchar id, ssh_bignum *result_key,
        struct ssh_flow_data *global_data)
{
    gcry_md_hd_t hd;
    guint len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

    guint kex_hash_type = ssh_kex_hash_type(global_data->kex);
    int algo = GCRY_MD_SHA256;
    if(kex_hash_type==SSH_KEX_HASH_SHA1){
        algo = GCRY_MD_SHA1;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA256){
        algo = GCRY_MD_SHA256;
    }else if(kex_hash_type==SSH_KEX_HASH_SHA512){
        algo = GCRY_MD_SHA512;
    }

    // required size of key depends on cipher used. chacha20 wants 64 bytes
    // TODO this should be something like
    // MAX(hash_smallest_output, required_size_for_cipher)
    // so if we only need 16 bytes, we shouldn't expand it, 32 bytes is enough
    // and we'd get the wrong result after expanding
    guint need = 64;
    
    result_key->data = (guchar *)wmem_alloc(wmem_file_scope(), need);

    gchar *secret_with_length = ssh_string(secret->data, secret->length);

    if (gcry_md_open(&hd, algo, 0) == 0) {
        gcry_md_write(hd, secret_with_length, secret->length + 4);
        gcry_md_write(hd, exchange_hash, hash_length);
        gcry_md_putc(hd, id);
        gcry_md_write(hd, global_data->session_id, hash_length);
        memcpy(result_key->data, gcry_md_read(hd, 0), len);
        gcry_md_close(hd);
    }

    // expand key
    for (guint have = len; have < need; have += len) {
        if (gcry_md_open(&hd, algo, 0) == 0) {
            gcry_md_write(hd, secret_with_length, secret->length + 4);
            gcry_md_write(hd, exchange_hash, hash_length);
            gcry_md_write(hd, result_key->data, len);
            guint add_length = MIN(len, need - have);
            memcpy(result_key->data+have, gcry_md_read(hd, 0), add_length);
            gcry_md_close(hd);
        }
    }

    result_key->length = need;
    print_hex(result_key->data, result_key->length, "key");
}

static void
ssh_decryption_set_cipher_id(struct ssh_peer_data *peer)
{
    gchar *cipher_name = peer->enc;

    if (0 == strcmp(cipher_name, "chacha20-poly1305@openssh.com")) {
        peer->cipher_id = GCRY_CIPHER_CHACHA20;
    } else if (0 == strcmp(cipher_name, "aes128-gcm@openssh.com")) {
        peer->cipher_id = CIPHER_AES128_GCM;
    } else if (0 == strcmp(cipher_name, "aes128-gcm")) {
        peer->cipher_id = CIPHER_AES128_GCM;
    } else if (0 == strcmp(cipher_name, "aes256-gcm@openssh.com")) {
        peer->cipher_id = CIPHER_AES256_GCM;
    } else if (0 == strcmp(cipher_name, "aes256-gcm")) {
        peer->cipher_id = CIPHER_AES256_GCM;
    } else if (0 == strcmp(cipher_name, "aes128-cbc")) {
        peer->cipher_id = CIPHER_AES128_CBC;
    } else if (0 == strcmp(cipher_name, "aes192-cbc")) {
        peer->cipher_id = CIPHER_AES192_CBC;
    } else if (0 == strcmp(cipher_name, "aes256-cbc")) {
        peer->cipher_id = CIPHER_AES256_CBC;
    } else if (0 == strcmp(cipher_name, "aes128-ctr")) {
        peer->cipher_id = CIPHER_AES128_CTR;
    } else if (0 == strcmp(cipher_name, "aes192-ctr")) {
        peer->cipher_id = CIPHER_AES192_CTR;
    } else if (0 == strcmp(cipher_name, "aes256-ctr")) {
        peer->cipher_id = CIPHER_AES256_CTR;
    } else {
        peer->cipher = NULL;
        g_debug("decryption not supported: %s", cipher_name);
    }
}

static void
ssh_decryption_setup_cipher(struct ssh_peer_data *peer_data,
        ssh_bignum *iv, ssh_bignum *key)
{
    gcry_error_t err;
    gcry_cipher_hd_t *hd1, *hd2;

    hd1 = &peer_data->cipher;
    hd2 = &peer_data->cipher_2;

    if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
        if (gcry_cipher_open(hd1, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0) ||
            gcry_cipher_open(hd2, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM, 0)) {
            gcry_cipher_close(*hd1);
            gcry_cipher_close(*hd2);
            g_debug("ssh: can't open chacha20 cipher handles");
            return;
        }

        gchar k1[32];
        gchar k2[32];
        memcpy(k1, key->data, 32);
        memcpy(k2, key->data + 32, 32);

        g_debug("ssh: cipher is chacha20");
        print_hex(key->data, 64, "key");


        if ((err = gcry_cipher_setkey(*hd1, k1, 32))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set chacha20 cipher key");
            return;
        }

        if ((err = gcry_cipher_setkey(*hd2, k2, 32))) {
            gcry_cipher_close(*hd1);
            gcry_cipher_close(*hd2);
            g_debug("ssh: can't set chacha20 cipher key");
            return;
        }
    } else if (CIPHER_AES128_CBC == peer_data->cipher_id  || CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES256_CBC == peer_data->cipher_id) {
        gint iKeyLen = CIPHER_AES128_CBC == peer_data->cipher_id?16:CIPHER_AES192_CBC == peer_data->cipher_id?24:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_CBC == peer_data->cipher_id?GCRY_CIPHER_AES128:CIPHER_AES192_CBC == peer_data->cipher_id?GCRY_CIPHER_AES192:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS)) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }
        gchar k1[32], iv1[16];
        if(key->data){
            memcpy(k1, key->data, iKeyLen);
        }else{
            memset(k1, 0, iKeyLen);
        }
        if(iv->data){
            memcpy(iv1, iv->data, 16);
        }else{
            memset(iv1, 0, 16);
        }

        g_debug("ssh: cipher is aes%d-cbc", iKeyLen*8);
        print_hex(k1, iKeyLen, "key");
        print_hex(iv1, 16, "iv");

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            return;
        }

        if ((err = gcry_cipher_setiv(*hd1, iv1, 16))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher iv", iKeyLen*8);
            g_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }

    } else if (CIPHER_AES128_CTR == peer_data->cipher_id  || CIPHER_AES192_CTR == peer_data->cipher_id || CIPHER_AES256_CTR == peer_data->cipher_id) {
        gint iKeyLen = CIPHER_AES128_CTR == peer_data->cipher_id?16:CIPHER_AES192_CTR == peer_data->cipher_id?24:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_CTR == peer_data->cipher_id?GCRY_CIPHER_AES128:CIPHER_AES192_CTR == peer_data->cipher_id?GCRY_CIPHER_AES192:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 0)) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }
        gchar k1[32], iv1[16];
        if(key->data){
            memcpy(k1, key->data, iKeyLen);
        }else{
            memset(k1, 0, iKeyLen);
        }
        if(iv->data){
            memcpy(iv1, iv->data, 16);
        }else{
            memset(iv1, 0, 16);
        }

        g_debug("ssh: cipher is aes%d-ctr", iKeyLen*8);
        print_hex(k1, iKeyLen, "key");
        print_hex(iv1, 16, "iv");

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            return;
        }

        if ((err = gcry_cipher_setctr(*hd1, iv1, 16))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher iv", iKeyLen*8);
            g_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
            return;
        }


    } else if (CIPHER_AES128_GCM == peer_data->cipher_id  || CIPHER_AES256_GCM == peer_data->cipher_id) {
        gint iKeyLen = CIPHER_AES128_GCM == peer_data->cipher_id?16:32;
        if (gcry_cipher_open(hd1, CIPHER_AES128_GCM == peer_data->cipher_id?GCRY_CIPHER_AES128:GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0)) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't open aes%d cipher handle", iKeyLen*8);
            return;
        }

        gchar k1[32], iv2[12];
        if(key->data){
            memcpy(k1, key->data, iKeyLen);
        }else{
            memset(k1, 0, iKeyLen);
        }
        if(iv->data){
            memcpy(peer_data->iv, iv->data, 12);
        }else{
            memset(iv2, 0, 12);
        }

        print_hex(k1, iKeyLen, "key");
        print_hex(peer_data->iv, 12, "iv");

        if ((err = gcry_cipher_setkey(*hd1, k1, iKeyLen))) {
            gcry_cipher_close(*hd1);
            g_debug("ssh: can't set aes%d cipher key", iKeyLen*8);
            return;
        }

    }
}

static void
ssh_increment_message_number(packet_info *pinfo, struct ssh_flow_data *global_data,
        gboolean is_response)
{
    if (!PINFO_FD_VISITED(pinfo)) {
        ssh_packet_info_t * packet = (ssh_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0);
        if(!packet){
            packet = wmem_new0(wmem_file_scope(), ssh_packet_info_t);
            packet->from_server = is_response;
            packet->messages = NULL;
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0, packet);
        }

        global_data->peer_data[!is_response].sequence_number ++;

g_debug("~~~~: ssh_increment_message_number %s > %d", is_response?"serveur":"client", global_data->peer_data[!is_response].sequence_number);
    FILE * oufx = fopen("/tmp/wireshark-ssh.log", "a");
    if(oufx){fprintf(oufx, "~~~~: ssh_increment_message_number %s > %d\n", is_response?"serveur":"client", global_data->peer_data[!is_response].sequence_number);fclose(oufx);}

    }
}

static guint
ssh_decrypt_packet(tvbuff_t *tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_tree *tree, gboolean *need_desegmentation)
{
    gboolean    is_response = (pinfo->destport != pinfo->match_uint);
    ssh_packet_info_t *packet = (ssh_packet_info_t *)p_get_proto_data(
            wmem_file_scope(), pinfo, proto_ssh, 0);
    if(!packet){
        packet = wmem_new0(wmem_file_scope(), ssh_packet_info_t);
        packet->from_server = is_response;
        packet->messages = NULL;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ssh, 0, packet);
    }

    gint record_id = tvb_raw_offset(tvb)+offset;
    ssh_message_info_t *message = NULL;
    ssh_message_info_t **pmessage = &packet->messages;
    while(*pmessage){
//        g_debug("looking for message %d now %d", record_id, (*pmessage)->id);
        if ((*pmessage)->id == record_id) {
            message = *pmessage;
            break;
        }
        pmessage = &(*pmessage)->next;
    }
    if(!message){
        message = wmem_new(wmem_file_scope(), ssh_message_info_t);
        message->plain_data = NULL;
        message->data_len = 0;
        message->id = record_id;
        message->is_fragment = 0;
        message->next = NULL;
        message->sequence_number = peer_data->sequence_number;
        peer_data->sequence_number++;
g_debug("~~~~: %s->sequence_number++ > %d", is_response?"serveur":"client", peer_data->sequence_number);
    FILE * oufx = fopen("/tmp/wireshark-ssh.log", "a");
    if(oufx){fprintf(oufx, "~~~~: %s->sequence_number++ > %d\n", is_response?"serveur":"client", peer_data->sequence_number);fclose(oufx);}

        *pmessage = message;
    }

//g_debug("~~~~: packet=%p pinfo=%p proto_ssh=%d record_id=%d", packet, pinfo, proto_ssh, record_id);

    guint message_length = 0, seqnr;
    gchar *plain = NULL, *mac;
    guint mac_len;

    if(message->is_fragment){
        return tvb_captured_length(tvb);
    }

    seqnr = message->sequence_number;

    if (GCRY_CIPHER_CHACHA20 == peer_data->cipher_id) {
        const gchar *ctext = (const gchar *)tvb_get_ptr(tvb, offset, 4);
        guint8 plain_length_buf[4];

        if (!ssh_decrypt_chacha20(peer_data->cipher_2, seqnr, 0, ctext, 4,
                    plain_length_buf, 4)) {
            g_debug("ERROR: could not decrypt packet len");
            return tvb_captured_length(tvb);
        }

            dump_ssh_style(plain_length_buf, 4, "plain for len seq = %d %s", seqnr, is_response?"s2c":"c2s");

        message_length = pntoh32(plain_length_buf);
//if(message_length>32768){*(int*)0=0;}
if(message_length>32768){return tvb_captured_length(tvb);}

        plain = (gchar *)wmem_alloc0(pinfo->pool, message_length+4);
        plain[0] = plain_length_buf[0]; plain[1] = plain_length_buf[1]; plain[2] = plain_length_buf[2]; plain[3] = plain_length_buf[3];
        const gchar *ctext2 = (const gchar *)tvb_get_ptr(tvb, offset+4,
                message_length);

        if (!ssh_decrypt_chacha20(peer_data->cipher, seqnr, 1, ctext2,
                    message_length, plain+4, message_length)) {
            g_debug("ERROR: could not decrypt packet payload");
            return tvb_captured_length(tvb);
        }

        mac_len = 16;
        mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);
        gchar poly_key[32], iv[16];

        memset(poly_key, 0, 32);
        memset(iv, 0, 8);
        phton64(iv+8, (guint64)seqnr);
        gcry_cipher_setiv(peer_data->cipher, iv, mac_len);
        gcry_cipher_encrypt(peer_data->cipher, poly_key, 32, poly_key, 32);

        gcry_mac_hd_t mac_hd;
        gcry_mac_open(&mac_hd, GCRY_MAC_POLY1305, 0, NULL);
        gcry_mac_setkey(mac_hd, poly_key, 32);
        gcry_mac_write(mac_hd, ctext, 4);
        gcry_mac_write(mac_hd, ctext2, message_length);
        if (gcry_mac_verify(mac_hd, mac, mac_len)) {
            g_debug("ssh: MAC does not match");
        }

        message->plain_data = plain;
        message->data_len   = message_length + 4;

            dump_ssh_style(ctext2, message_length+4+mac_len, is_response?"s2c encrypted":"c2s encrypted");
            dump_ssh_style(plain, message_length+4, "plain text seq=%d", seqnr);

    } else if (CIPHER_AES128_GCM == peer_data->cipher_id || CIPHER_AES256_GCM == peer_data->cipher_id) {

        mac_len = peer_data->mac_length;
        message_length = tvb_reported_length_remaining(tvb, offset) - 4 - mac_len;

        const gchar *plain_buf = (const gchar *)tvb_get_ptr(tvb, offset, 4);
        message_length = pntoh32(plain_buf);
        guint remaining = tvb_reported_length_remaining(tvb, offset);
        g_debug("[[[aes128]]] length: %d. remaining: %d",
                message_length, remaining);

        if(message->plain_data && message->data_len){
            message_length = message->data_len - 4;
        }else{

//          const gchar *ctext = (const gchar *)tvb_get_ptr(tvb, offset+4,
//                    message_length);
            const gchar *ctl = (const gchar *)tvb_get_ptr(tvb, offset,
                    message_length+4);
            const gchar *ctext = ctl + 4;
            plain = (gchar *)wmem_alloc(wmem_file_scope(), message_length+4);
            plain[0] = message_length >> 24; plain[1] = message_length >> 16; plain[2] = message_length >>  8; plain[3] = message_length >>  0;

            /* gchar seqbuf[8]; */
            /* memset(iv, 0, 12); */
            /* phton64(seqbuf, seqnr); */

            gcry_error_t err;
            /* gcry_cipher_setiv(peer_data->cipher, iv, 12); */
            if ((err = gcry_cipher_setiv(peer_data->cipher, peer_data->iv, 12))) {
                gcry_cipher_close(peer_data->cipher);
                g_debug("ssh: can't set aes128 cipher iv");
                g_debug("libgcrypt: %d %s %s", gcry_err_code(err), gcry_strsource(err), gcry_strerror(err));
                return offset;
            }
            int idx = 12;
            do{
                idx -= 1;
                peer_data->iv[idx] += 1;
            }while(idx>4 && peer_data->iv[idx]==0);

            if ((err = gcry_cipher_authenticate(peer_data->cipher, plain, 4))) {
                g_debug ("can't authenticate using aes128-gcm: %s\n", gpg_strerror(err));
                return offset;
            }

            guint offs = 0;
            if(remaining>message_length+4){remaining=message_length;}
            g_debug("***  remaining[%d] = %d", __LINE__, remaining);
            while(offs<remaining){
                if (gcry_cipher_decrypt(peer_data->cipher, plain+4+offs, 16,
                        ctext+offs, 16))
                {
                    g_debug("can\'t decrypt aes128");
                    return offset;
                }
                offs += 16;
            }

            guint8 gu8CalcMAC[16];
            if (gcry_cipher_gettag (peer_data->cipher, gu8CalcMAC, 16)) {
                g_debug ("aes128-gcm, gcry_cipher_gettag() failed\n");
                return offset;
            }


            if ((err = gcry_cipher_reset(peer_data->cipher))) {
                g_debug ("aes-gcm, gcry_cipher_reset failed: %s\n",
                    gpg_strerror (err));
                return offset;
            }

//          printf("aes128-gcm decrypt\n");
//          for (guint i = 0; i < message_length; i ++)
//              printf("%02X", (guint8)plain[i]);
//          printf("\n");

            message->plain_data = plain;
            message->data_len   = message_length + 4;

            dump_ssh_style(ctl, message_length+4+mac_len, is_response?"s2c encrypted":"c2s encrypted");
            dump_ssh_style(plain, message_length+4, "plain text seq=%d", peer_data->counter-1);
    }

    plain = message->plain_data;
    message_length = message->data_len - 4;
    mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);

/*
        ssh_dissect_decrypted_packet_aes(plain, message_length, NULL,
                tree, tvb, pinfo);
*/

    } else if (CIPHER_AES128_CBC == peer_data->cipher_id || CIPHER_AES128_CTR == peer_data->cipher_id || 
        CIPHER_AES192_CBC == peer_data->cipher_id || CIPHER_AES192_CTR == peer_data->cipher_id || 
        CIPHER_AES256_CBC == peer_data->cipher_id || CIPHER_AES256_CTR == peer_data->cipher_id) {

        mac_len = peer_data->mac_length;
        message_length = tvb_reported_length_remaining(tvb, offset) - 4 - mac_len;
//        proto_tree_add_item(tree, hf_ssh_message_length_encrypted, tvb, offset, 4, ENC_NA);
//        proto_tree_add_item(tree, hf_ssh_encrypted_packet, tvb, offset+4, message_length, ENC_NA);
//        proto_tree_add_item(tree, hf_ssh_mac_string, tvb, offset+4+message_length, mac_len, ENC_NA);

//        SshRecordInfo  *record = NULL;
//        tvbuff_t       *decrypted = ssh_get_record_info(tvb, proto_ssh, pinfo, tvb_raw_offset(tvb)+offset, 0, &record);
        if(message->plain_data && message->data_len){
            message_length = message->data_len - 4;
        }else{
// TODO: see how to handle fragmentation...
//          const gchar *cypher_buf0 = (const gchar *)tvb_get_ptr(tvb, offset, 16);
            const gchar *ctext = NULL;
//            if(!message->plain_data){
            if(!peer_data->in_fragment){
                g_debug("Getting raw bytes of length %d", tvb_reported_length_remaining(tvb, offset));
                const gchar *cypher_buf0 = (const gchar *)tvb_get_ptr(tvb, offset, tvb_reported_length_remaining(tvb, offset));

                if (gcry_cipher_decrypt(peer_data->cipher, peer_data->fragment_plain0, 16, cypher_buf0, 16))
                {
                    g_debug("can\'t decrypt aes128");
                    return offset;
                }
//                message->plain_data = (gchar *)wmem_alloc(wmem_file_scope(), message_length+4);
//                memcpy(message->plain_data, plain0, 16);
                ctext = cypher_buf0;
//                dump_ssh_style(ctext, 64, "cypher_buf0");
            }else{
                ctext = ((const gchar *)tvb_get_ptr(tvb, offset, tvb_reported_length_remaining(tvb, offset))) - 16;
            }
            plain = peer_data->fragment_plain0;
            guint message_length_decrypted = pntoh32(peer_data->fragment_plain0);
            guint remaining = tvb_reported_length_remaining(tvb, offset);
            g_debug("[[[aes128]]] length: %u. remaining: %u", message_length_decrypted, remaining);

//          const gchar *ctext = (const gchar *)tvb_get_ptr(tvb, offset, message_length+4);

//(void)ctext;
#if 1
            if(message_length_decrypted>32768){
//            if(message_length_decrypted>remaining){
#if 0
                if(message_length_decrypted<32768){
                    // Need desegmentation
                    g_debug("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                                    offset, tvb_reported_length_remaining(tvb, offset));
                    /* Make data available to ssh_follow_tap_listener */
//                    tap_queue_packet(ssh_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_ssh, curr_layer_num_ssl));
                    return tvb_captured_length(tvb);
                }
#endif
                g_debug("[[[aes128]]] !!!! length: %u. remaining: %u", message_length_decrypted, remaining);
                dump_ssh_style(ctext, 16, is_response?"s2c encrypted":"c2s encrypted");
                dump_ssh_style(message->plain_data, 16, is_response?"s2c wrong pln":"c2s wrong pln");
                offset += remaining;
                return tvb_captured_length(tvb);
            }else{

                if (ssh_desegment && pinfo->can_desegment) {
                    /*
                     * Yes - would an SSH header starting at this offset
                     * be split across segment boundaries?
                     */
                    if (remaining < message_length_decrypted) {
                        // Need desegmentation
                        g_debug("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                                        offset, tvb_reported_length_remaining(tvb, offset));
                        /*
                         * Yes.  Tell the TCP dissector where the data for
                         * this message starts in the data it handed us and
                         * that we need "some more data."  Don't tell it
                         * exactly how many bytes we need because if/when we
                         * ask for even more (after the header) that will
                         * break reassembly.
                         */
                        pinfo->desegment_offset = offset;
                        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                        message->is_fragment = 1;
                        peer_data->in_fragment = 1;
                        *need_desegmentation = TRUE;
                        return offset;
                    }
                }


                message_length = message_length_decrypted;
                message->plain_data = (gchar *)wmem_alloc(wmem_file_scope(), message_length+4);
                memcpy(message->plain_data, peer_data->fragment_plain0, 16);
                plain = message->plain_data;

/*                if (gcry_cipher_decrypt(peer_data->cipher, plain+16, message_length-16+4, ctext+16, message_length-16+4))
                {
                    g_debug("can\'t decrypt aes128");
                    return offset;
                }*/
                guint offs = 16;
                if(remaining>message_length+4){remaining=message_length+4;}
                g_debug("***  remaining[%d] = %d", __LINE__, remaining);
                while(offs<remaining){
                    gchar *ct = (gchar *)tvb_get_ptr(tvb, offset+offs, 16);
//                    if(offs<64){dump_ssh_style(ct, 16, "ct%d", offs);}
//                    if (gcry_cipher_decrypt(peer_data->cipher, plain+offs, 16, ctext+offs, 16))
                    if (gcry_cipher_decrypt(peer_data->cipher, plain+offs, 16, ct, 16))
                    {
                        g_debug("can\'t decrypt aes128");
                        return offset;
                    }
                    offs += 16;
                }

                if(message_length_decrypted>remaining){
                    // Need desegmentation
                    g_debug("  need_desegmentation: offset = %d, reported_length_remaining = %d\n",
                                    offset, tvb_reported_length_remaining(tvb, offset));
                    /* Make data available to ssh_follow_tap_listener */
//                    tap_queue_packet(ssh_tap, pinfo, p_get_proto_data(wmem_file_scope(), pinfo, proto_ssh, curr_layer_num_ssl));
                    return tvb_captured_length(tvb);
                }

//              dump_ssh_style(ctext, message_length+4, "cipher text");
                dump_ssh_style(ctext, message_length+4+mac_len, is_response?"s2c encrypted":"c2s encrypted");
                dump_ssh_style(plain, message_length+4, "plain text seq=%d", peer_data->counter-1);

                peer_data->in_fragment = 0;

// TODO: process fragments
//              ssh_add_record_info(proto_ssh, pinfo, data, datalen, record_id, allow_fragments ? decoder->flow : NULL, (ContentType)content_type, curr_layer_num_ssl);
//              ssh_add_record_info(proto_ssh, pinfo, plain, message_length + 4, tvb_raw_offset(tvb)+offset, NULL, (ContentType)0, 0);
                message->plain_data = plain;
                message->data_len   = message_length + 4;

g_debug("record_id=%d", record_id);
g_debug("message_length=%d mac_length=%d", message_length, peer_data->mac_length);
g_debug("Remlen %d %d", tvb_reported_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset+message_length + peer_data->mac_length + 4));
            }
#endif

        }
        plain = message->plain_data;
        message_length = message->data_len - 4;
        mac = (gchar *)tvb_get_ptr(tvb, offset + 4 + message_length, mac_len);
    }

    if(plain){
        ssh_dissect_decrypted_packet(tvb, pinfo, peer_data, tree, plain, message_length+4, mac, mac_len, need_desegmentation);
    }

    offset += message_length + peer_data->mac_length + 4;
    return offset;
}

static gboolean
ssh_decrypt_chacha20(gcry_cipher_hd_t hd,
        guint32 seqnr, guint32 counter, const guchar *ctext, guint ctext_len,
        guchar *plain, guint plain_len)
{
    guchar seq[8];
    guchar iv[16];

    phton64(seq, (guint64)seqnr);

    // chacha20 uses a different cipher handle for the packet payload & length
    // the payload uses a block counter
    if (counter) {
        guchar ctr[8] = {1,0,0,0,0,0,0,0};
        memcpy(iv, ctr, 8);
        memcpy(iv+8, seq, 8);
    }

    return ((!counter && gcry_cipher_setiv(hd, seq, 8) == 0) ||
            (counter && gcry_cipher_setiv(hd, iv, 16) == 0)) &&
            gcry_cipher_decrypt(hd, plain, plain_len, ctext, ctext_len) == 0;
}
#if 0
static void
ssh_dissect_decrypted_packet(gchar *plaintext, guint plaintext_len,
        gchar *mac, guint mac_len, proto_tree *tree, tvbuff_t *tvb,
        packet_info *pinfo)
{
    guint padding_len = plaintext[4];
    guint packet_len = pntoh32(plaintext) - padding_len - 1;
    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    tvbuff_t *mac_tvb = tvb_new_child_real_data(tvb, mac, mac_len, mac_len);
    add_new_data_source(pinfo, packet_tvb, "Decrypted Packet");
    add_new_data_source(pinfo, mac_tvb, "Packet Mac");
    proto_tree_add_item(tree, hf_ssh_packet_length, packet_tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_padding_length, packet_tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_padding_length, packet_tvb, 4, 1, ENC_BIG_ENDIAN);xyz
//    proto_tree_add_item(tree, hf_ssh_payload, packet_tvb, 5, packet_len, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_padding_string, packet_tvb, packet_len + 5, padding_len, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_mac_string, mac_tvb, 0, mac_len, ENC_BIG_ENDIAN);
#if 0
    guint packet_len  = pntoh32(plaintext);
    guint padding_len = plaintext[4];
    guint payload_len = packet_len - padding_len - 1;
    g_debug("packet len=%d padding len=%d payload len=%d", packet_len, padding_len, payload_len);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Encrypted packet (len=%d)", packet_len);
/*
    int offset = 0;
    if (tree) {
//        proto_tree_add_uint(tree, hf_ssh_packet_length, tvb, offset, 4, packet_len);
        proto_tree_add_item(tree, hf_ssh_packet_length_encrypted, tvb, offset, 4, ENC_NA);
        proto_tree_add_item(tree, hf_ssh_encrypted_packet, tvb, offset+4, packet_len, ENC_NA);
        proto_tree_add_item(tree, hf_ssh_mac_string, tvb, offset+4+packet_len, mac_len, ENC_NA);
    }
*/
//    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, packet_len, packet_len);
//(void)packet_tvb;
(void)mac;
(void)mac_len;
(void)tree;
(void)pinfo;
(void)plaintext_len;
(void)tvb;
    add_new_data_source(pinfo, packet_tvb, "Decrypted Packet");
//    proto_tree_add_item(tree, hf_ssh_packet_length, packet_tvb, 0, 4, ENC_BIG_ENDIAN);
/*    tvbuff_t *mac_tvb = tvb_new_child_real_data(tvb, mac, mac_len, mac_len);
    add_new_data_source(pinfo, mac_tvb, "Packet Mac");
    proto_tree_add_item(tree, hf_ssh_padding_length, packet_tvb, 4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_payload, packet_tvb, 5, payload_len, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_padding_string, packet_tvb, payload_len + 5, padding_len, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ssh_mac_string, mac_tvb, 0, mac_len, ENC_BIG_ENDIAN);*/
#endif
}
#endif // 0

static int
//ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo,
//        struct ssh_flow_data *global_data,
//        int offset, proto_tree *tree, int is_response,
//        gboolean *need_desegmentation)
ssh_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo, 
        struct ssh_peer_data *peer_data, proto_tree *tree, 
        gchar *plaintext, guint plaintext_len,
        gchar *mac, guint mac_len, 
        gboolean *need_desegmentation)
{
    int offset = 0;      // TODO:

    tvbuff_t *packet_tvb = tvb_new_child_real_data(tvb, plaintext, plaintext_len, plaintext_len);
    tvbuff_t *mac_tvb = tvb_new_child_real_data(tvb, mac, mac_len, mac_len);
    add_new_data_source(pinfo, packet_tvb, "Decrypted Packet");
    add_new_data_source(pinfo, mac_tvb, "Packet Mac");

    guint   plen, len;
    guint8  padding_length;
    guint   remain_length;
    int     last_offset=offset;
    guint   msg_code;

    proto_item *ti;
    proto_item *msg_type_tree = NULL;

    /*
     * We use "tvb_ensure_captured_length_remaining()" to make sure there
     * actually *is* data remaining.
     *
     * This means we're guaranteed that "remain_length" is positive.
     */
    remain_length = tvb_ensure_captured_length_remaining(packet_tvb, offset);
    /*
     * Can we do reassembly?
     */
    if (ssh_desegment && pinfo->can_desegment) {
        /*
         * Yes - would an SSH header starting at this offset
         * be split across segment boundaries?
         */
        if (remain_length < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    plen = tvb_get_ntohl(packet_tvb, offset) ;

    if (ssh_desegment && pinfo->can_desegment) {
        if (plen +4 >  remain_length) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = plen+4 - remain_length;
            *need_desegmentation = TRUE;
            return offset;
        }
    }
    /*
     * Need to check plen > 0x80000000 here
     */

    ti = proto_tree_add_uint(tree, hf_ssh_packet_length, packet_tvb,
                    offset, 4, plen);
    if (plen >= 0xffff) {
        expert_add_info_format(pinfo, ti, &ei_ssh_packet_length, "Overly large number %d", plen);
        plen = remain_length-4;
    }
    offset+=4;

    /* padding length */
    padding_length = tvb_get_guint8(packet_tvb, offset);
    proto_tree_add_uint(tree, hf_ssh_padding_length, packet_tvb, offset, 1, padding_length);
    offset += 1;

    /* msg_code */
    msg_code = tvb_get_guint8(packet_tvb, offset);

    /* Transport layer protocol */
    /* Generic (1-19) */
    if(msg_code >= 1 && msg_code <= 19) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        ssh_dissect_transport_generic(packet_tvb, pinfo, offset, msg_type_tree, msg_code);
        // offset = ssh_dissect_transport_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* Algorithm negotiation (20-29) */
    else if(msg_code >=20 && msg_code <= 29) {
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (algorithm negotiation)");
//TODO: See if the complete dissector should be refactored to always got through here first        offset = ssh_dissect_transport_algorithm_negotiation(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* Key exchange method specific (reusable) (30-49) */
    else if (msg_code >=30 && msg_code <= 49) {
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Transport (key exchange method specific)");
//TODO: See if the complete dissector should be refactored to always got through here first                offset = global_data->kex_specific_dissector(msg_code, packet_tvb, pinfo, offset, msg_type_tree);
    }

    /* User authentication protocol */
    /* Generic (50-59) */
    else if (msg_code >= 50 && msg_code <= 59) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: User Authentication (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        ssh_dissect_userauth_generic(packet_tvb, pinfo, offset, msg_type_tree, msg_code);
        // TODO: offset = ssh_dissect_userauth_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }
    /* User authentication method specific (reusable) (60-79) */
    else if (msg_code >= 60 && msg_code <= 79) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: User Authentication: (method specific)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_userauth_specific(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        ssh_dissect_userauth_specific(packet_tvb, pinfo, offset, msg_type_tree, msg_code);
    }

    /* Connection protocol */
    /* Generic (80-89) */
    else if (msg_code >= 80 && msg_code <= 89) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Connection (generic)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_connection_generic(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        ssh_dissect_connection_generic(packet_tvb, pinfo, offset, msg_type_tree, msg_code);
    }
    /* Channel related messages (90-127) */
    else if (msg_code >= 90 && msg_code <= 127) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Connection: (channel related message)");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_connection_channel(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
        ssh_dissect_connection_specific(packet_tvb, pinfo, peer_data, offset, msg_type_tree, msg_code);
    }

    /* Reserved for client protocols (128-191) */
    else if (msg_code >= 128 && msg_code <= 191) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Client protocol");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_client(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }

    /* Local extensions (192-255) */
    else if (msg_code >= 192 && msg_code <= 255) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, val_to_str(msg_code, ssh2_msg_vals, "Unknown (%u)"));
        msg_type_tree = proto_tree_add_subtree(tree, packet_tvb, offset, plen-1, ett_key_exchange, NULL, "Message: Local extension");
        proto_tree_add_item(msg_type_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;
        // TODO: offset = ssh_dissect_local_extention(packet_tvb, pinfo, global_data, offset, msg_type_tree, is_response, msg_code);
    }

    len = plen+4-padding_length-(offset-last_offset);
    if (len > 0) {
        proto_tree_add_item(msg_type_tree, hf_ssh_payload, packet_tvb, offset, len, ENC_NA);
    }
    offset +=len;

    /* padding */
    proto_tree_add_item(tree, hf_ssh_padding_string, packet_tvb, offset, padding_length, ENC_NA);
    offset+= padding_length;

    /* mac */
    proto_tree_add_item(tree, hf_ssh_mac_string, mac_tvb, 0, mac_len, ENC_BIG_ENDIAN);

    return offset;
}

static void
ssh_dissect_transport_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree,
        /*int is_response,*/ guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_DISCONNECT){
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_reason, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_description_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_disconnect_description, packet_tvb, offset, nlen, ENC_BIG_ENDIAN);
                offset += nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_lang_tag, packet_tvb, offset, nlen, ENC_BIG_ENDIAN);
                offset += nlen;
        }else if(msg_code==SSH_MSG_SERVICE_REQUEST){
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_BIG_ENDIAN);
        }else if(msg_code==SSH_MSG_SERVICE_ACCEPT){
                guint   nlen;
                nlen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_service_name, packet_tvb, offset, nlen, ENC_BIG_ENDIAN);
        }
}

static void
ssh_dissect_userauth_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree,
        /*int is_response,*/ guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_USERAUTH_REQUEST){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_user_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_user_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_service_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_service_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_method_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_method_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);

                guint8* key_type;
                key_type = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                offset += slen;
                if (0 == strcmp(key_type, "none")) {
                }else if (0 == strcmp(key_type, "publickey")) {
                        guint8 bHaveSignature = tvb_get_guint8(packet_tvb, offset);
                        offset += 1;
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                        offset += slen;
                        proto_item *blob_tree = NULL;
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_blob_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_blob, NULL, "Public key blob");
//        proto_tree_add_item(blob_tree, hf_ssh2_msg_code, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                        ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree);
                        offset += slen;
                        if(bHaveSignature){
                                slen = tvb_get_ntohl(packet_tvb, offset) ;
                                proto_tree_add_item(msg_type_tree, hf_ssh_signature_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                                offset += 4;
                                proto_item *signature_tree = NULL;
                                signature_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_signautre, NULL, "Public key signature");
                                ssh_dissect_public_key_signature(packet_tvb, pinfo, offset, signature_tree);
                                offset += slen;
                        }
                }else{
                }

        }else if(msg_code==SSH_MSG_USERAUTH_FAILURE){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_auth_failure_list_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_auth_failure_list, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
        }
}

static void
ssh_dissect_userauth_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree,
        /*int is_response,*/ guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_USERAUTH_PK_OK){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_userauth_pka_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                proto_item *blob_tree = NULL;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_blob_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                blob_tree = proto_tree_add_subtree(msg_type_tree, packet_tvb, offset, slen, ett_userauth_pk_blob, NULL, "Public key blob");
                ssh_dissect_public_key_blob(packet_tvb, pinfo, offset, blob_tree);
        }
}

static void
ssh_dissect_connection_specific(tvbuff_t *packet_tvb, packet_info *pinfo,
        struct ssh_peer_data *peer_data, int offset, proto_item *msg_type_tree,
        /*int is_response,*/ guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_CHANNEL_OPEN){
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_type_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_type_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_sender_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_initial_window, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_maximum_packet_size, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_OPEN_CONFIRMATION){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_sender_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_initial_window, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_maximum_packet_size, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_WINDOW_ADJUST){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_window_adjust, packet_tvb, offset, 4, ENC_BIG_ENDIAN);         // TODO: maintain count of transfered bytes and window size
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_DATA){
                guint   uiNumChannel;
                uiNumChannel = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
// TODO: process according to the type of channel
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_data_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                tvbuff_t *next_tvb = tvb_new_subset_remaining(packet_tvb, offset);
                dissector_handle_t subdissector_handle = get_subdissector_for_channel(peer_data, uiNumChannel);
                if(subdissector_handle){
                        call_dissector(subdissector_handle, next_tvb, pinfo, msg_type_tree);
                }
                offset += slen;
        }else if(msg_code==SSH_MSG_CHANNEL_EOF){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_CLOSE){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }else if(msg_code==SSH_MSG_CHANNEL_REQUEST){
                guint   uiNumChannel;
                uiNumChannel = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                guint8* request_name;
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                request_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_channel_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (0 == strcmp(request_name, "subsystem")) {
                        slen = tvb_get_ntohl(packet_tvb, offset) ;
                        proto_tree_add_item(msg_type_tree, hf_ssh_subsystem_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                        guint8* subsystem_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                        set_subdissector_for_channel(peer_data, uiNumChannel, subsystem_name);
                        proto_tree_add_item(msg_type_tree, hf_ssh_subsystem_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                        offset += slen;
                }else if (0 == strcmp(request_name, "exit-status")) {
                        proto_tree_add_item(msg_type_tree, hf_ssh_exit_status, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                        offset += 4;
                }
        }else if(msg_code==SSH_MSG_CHANNEL_SUCCESS){
                proto_tree_add_item(msg_type_tree, hf_ssh_connection_recipient_channel, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
        }
}

static dissector_handle_t
get_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel)
{
        ssh_channel_info_t *ci = peer_data->channel_info;
        while(ci){
            if(ci->channel_number==uiNumChannel){return ci->subdissector_handle;}
            ci = ci->next;
        }
        g_debug("Error lookin up channel %d", uiNumChannel);
        return NULL;
}

static void
set_subdissector_for_channel(struct ssh_peer_data *peer_data, guint uiNumChannel, guint8* subsystem_name)
{
        ssh_channel_info_t *ci = NULL;
        ssh_channel_info_t **pci = &peer_data->channel_info;
        while(*pci){
            if ((*pci)->channel_number == uiNumChannel) {
                ci = *pci;
                break;
            }
            pci = &(*pci)->next;
        }
        if(!ci){
            ci = wmem_new(wmem_file_scope(), ssh_channel_info_t);
            *pci = ci;
        }
        if(0 == strcmp(subsystem_name, "sftp")) {
            ci->subdissector_handle = sftp_handle;
        } else {
            ci->subdissector_handle = NULL;
        }
}

static void
ssh_dissect_connection_generic(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree,
        /*int is_response,*/ guint msg_code)
{
        (void)pinfo;
        if(msg_code==SSH_MSG_GLOBAL_REQUEST){
                guint8* request_name;
                guint   slen;
                slen = tvb_get_ntohl(packet_tvb, offset) ;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name_len, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                request_name = tvb_get_string_enc(wmem_packet_scope(), packet_tvb, offset, slen, ENC_ASCII|ENC_NA);
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
                offset += slen;
                proto_tree_add_item(msg_type_tree, hf_ssh_global_request_want_reply, packet_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (0 == strcmp(request_name, "hostkeys-00@openssh.com")) {
                }
        }
}

static void
ssh_dissect_public_key_blob(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree
        /*int is_response*/)
{
        (void)pinfo;
        guint   slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_blob_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_blob_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
        offset += slen;
        offset += ssh_tree_add_mpint(packet_tvb, offset, msg_type_tree, hf_ssh_blob_e);
        offset += ssh_tree_add_mpint(packet_tvb, offset, msg_type_tree, hf_ssh_blob_p);
}

static void
ssh_dissect_public_key_signature(tvbuff_t *packet_tvb, packet_info *pinfo,
        /*struct ssh_flow_data *global_data,*/ int offset, proto_item *msg_type_tree
        /*int is_response*/)
{
        (void)pinfo;
        guint   slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_blob_name_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_blob_name, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
        offset += slen;
        slen = tvb_get_ntohl(packet_tvb, offset) ;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_s_length, packet_tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(msg_type_tree, hf_ssh_pk_sig_s, packet_tvb, offset, slen, ENC_BIG_ENDIAN);
        offset += slen;
}

/* Links SSH packet with the real packet data. {{{ */
#if 0
SshPacketInfo *
ssh_add_packet_info(gint proto, packet_info *pinfo, guint8 key)
{
    SshPacketInfo *pi = (SshPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, key);
    if (!pi) {
        pi = wmem_new0(wmem_file_scope(), SshPacketInfo);
        pi->srcport = pinfo->srcport;
        pi->destport = pinfo->destport;
        pi->messages = NULL;
        p_add_proto_data(wmem_file_scope(), pinfo, proto, key, pi);
    }

    return pi;
}

/**
 * Remembers the decrypted TLS record fragment (TLSInnerPlaintext in TLS 1.3) to
 * avoid the need for a decoder in the second pass. Additionally, it remembers
 * sequence numbers (for reassembly and Follow TLS Stream).
 *
 * @param proto The protocol identifier (proto_ssl or proto_dtls).
 * @param pinfo The packet where the record originates from.
 * @param data Decrypted data to store in the record.
 * @param data_len Length of decrypted record data.
 * @param record_id The identifier for this record within the current packet.
 * @param flow Information about sequence numbers, etc.
 * @param type TLS Content Type (such as handshake or application_data).
 * @param curr_layer_num_ssl The layer identifier for this TLS session.
 */
void
ssh_add_record_info(gint proto, packet_info *pinfo, const guchar *data, gint data_len, gint record_id, SshFlow *flow, ContentType type, guint8 key)
{
    SshRecordInfo* rec, **prec;
    SshPacketInfo *pi = ssh_add_packet_info(proto, pinfo, key);

    rec = wmem_new(wmem_file_scope(), SshRecordInfo);
    rec->plain_data = (guchar *)wmem_memdup(wmem_file_scope(), data, data_len);
    rec->data_len = data_len;
    rec->id = record_id;
    rec->type = type;
    rec->next = NULL;

//    if (flow && type == SSL_ID_APP_DATA) {
    if (flow) {
        rec->seq = flow->byte_seq;
        rec->flow = flow;
        flow->byte_seq += data_len;
        ssh_debug_printf("%s stored decrypted record seq=%d nxtseq=%d flow=%p\n",
                         G_STRFUNC, rec->seq, rec->seq + data_len, (void*)flow);
    }

    /* Remember decrypted records. */
    prec = &pi->records;
    while (*prec) prec = &(*prec)->next;
    *prec = rec;
}

/* search in packet data for the specified id; return a newly created tvb for the associated data */
tvbuff_t*
ssh_get_record_info(tvbuff_t *parent_tvb, int proto, packet_info *pinfo, gint record_id, guint8 key, SshRecordInfo **matched_record)
{
    SshRecordInfo* rec;
    SshPacketInfo* pi;
    pi = (SshPacketInfo *)p_get_proto_data(wmem_file_scope(), pinfo, proto, key);

    if (!pi)
        return NULL;

    for (rec = pi->records; rec; rec = rec->next)
        if (rec->id == record_id) {
            *matched_record = rec;
            /* link new real_data_tvb with a parent tvb so it is freed when frame dissection is complete */
            return tvb_new_child_real_data(parent_tvb, rec->plain_data, rec->data_len, rec->data_len);
        }

    return NULL;
}
#endif
/* Links SSH packet with the real packet data. }}} */

#ifdef SSH_DECRYPT_DEBUG /* {{{ */

static FILE* ssh_debug_file=NULL;

void
ssh_set_debug(const gchar* name)
{
    static gint debug_file_must_be_closed;
    gint        use_stderr;

    use_stderr                = name?(strcmp(name, SSH_DEBUG_USE_STDERR) == 0):0;

    if (debug_file_must_be_closed)
        fclose(ssh_debug_file);

    if (use_stderr)
        ssh_debug_file = stderr;
    else if (!name || (strcmp(name, "") ==0))
        ssh_debug_file = NULL;
    else
        ssh_debug_file = ws_fopen(name, "w");

    if (!use_stderr && ssh_debug_file)
        debug_file_must_be_closed = 1;
    else
        debug_file_must_be_closed = 0;

    ssh_debug_printf("Wireshark SSH debug log \n\n");
    ssh_debug_printf("Wireshark version: %s\n", get_ws_vcs_version_info());
#ifdef HAVE_LIBGNUTLS
    ssh_debug_printf("GnuTLS version:    %s\n", gnutls_check_version(NULL));
#endif
    ssh_debug_printf("Libgcrypt version: %s\n", gcry_check_version(NULL));
    ssh_debug_printf("\n");
}

void
ssh_debug_flush(void)
{
    if (ssh_debug_file)
        fflush(ssh_debug_file);
}

void
ssh_debug_printf(const gchar* fmt, ...)
{
    va_list ap;

    if (!ssh_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssh_debug_file, fmt, ap);
    va_end(ap);
}

void
ssh_print_data(const gchar* name, const guchar* data, size_t len)
{
    size_t i, j, k;
    if (!ssh_debug_file)
        return;
    fprintf(ssh_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssh_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssh_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssh_debug_file,"   ");
        fputc('|', ssh_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssh_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssh_debug_file);
        fprintf(ssh_debug_file,"|\n");
    }
}

#endif /* SSH_DECRYPT_DEBUG }}} */

static void
ssh_secrets_block_callback(const void *secrets, guint size)
{
//    ssh_keylog_process_lines(&ssh_master_key_map, (const guint8 *)secrets, size);
//    ssh_keylog_process_line(&ssh_master_key_map, (const guint8 *)secrets);
    ssh_keylog_process_lines(/*&ssh_master_key_map,*/ (const guint8 *)secrets, size);
}

/* Functions for SSH random hashtables. {{{ */
static gint
ssl_equal (gconstpointer v, gconstpointer v2)
{
    const ssh_bignum *val1;
    const ssh_bignum *val2;
    val1 = (const ssh_bignum *)v;
    val2 = (const ssh_bignum *)v2;

    if (val1->length == val2->length &&
        !memcmp(val1->data, val2->data, val2->length)) {
        return 1;
    }
    return 0;
}

static guint
ssl_hash  (gconstpointer v)
{
    guint l,hash;
    const ssh_bignum* id;
    const guint* cur;
    hash = 0;
    id = (const ssh_bignum*) v;

    /*  id and id->data are mallocated in ssl_save_master_key().  As such 'data'
     *  should be aligned for any kind of access (for example as a guint as
     *  is done below).  The intermediate void* cast is to prevent "cast
     *  increases required alignment of target type" warnings on CPUs (such
     *  as SPARCs) that do not allow misaligned memory accesses.
     */
    cur = (const guint*)(void*) id->data;

    for (l=4; (l < id->length); l+=4, cur++)
        hash = hash ^ (*cur);

    return hash;
}
/* Functions for SSH random hashtables. }}} */

#endif /* SSH_DECRYPTION_SUPPORTED */

void
proto_register_ssh(void)
{
    static hf_register_info hf[] = {
        { &hf_ssh_protocol,
          { "Protocol",  "ssh.protocol",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_packet_length,
          { "Packet Length",      "ssh.packet_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            NULL, HFILL }},

        { &hf_ssh_packet_length_encrypted,
          { "Packet Length (encrypted)",      "ssh.packet_length_encrypted",
            FT_BYTES, BASE_NONE, NULL,  0x0,
            NULL, HFILL }},

        { &hf_ssh_padding_length,
          { "Padding Length",  "ssh.padding_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_payload,
          { "Payload",  "ssh.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encrypted_packet,
          { "Encrypted Packet",  "ssh.encrypted_packet",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_padding_string,
          { "Padding String",  "ssh.padding_string",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_string,
          { "MAC",  "ssh.mac",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Message authentication code", HFILL }},

        { &hf_ssh_direction,
          { "Direction", "ssh.direction",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Message direction", HFILL }},

        { &hf_ssh_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh1_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_dh_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_dh_gex_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_dh_gex_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh2_kex_ecdh_msg_code,
          { "Message Code",  "ssh.message_code",
            FT_UINT8, BASE_DEC, VALS(ssh2_kex_ecdh_msg_vals), 0x0,
            NULL, HFILL }},

        { &hf_ssh_cookie,
          { "Cookie",  "ssh.cookie",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_algorithms,
          { "kex_algorithms string",         "ssh.kex_algorithms",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_server_host_key_algorithms,
          { "server_host_key_algorithms string",         "ssh.server_host_key_algorithms",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server,
          { "encryption_algorithms_client_to_server string",         "ssh.encryption_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client,
          { "encryption_algorithms_server_to_client string",         "ssh.encryption_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server,
          { "mac_algorithms_client_to_server string",         "ssh.mac_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client,
          { "mac_algorithms_server_to_client string",         "ssh.mac_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server,
          { "compression_algorithms_client_to_server string",         "ssh.compression_algorithms_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client,
          { "compression_algorithms_server_to_client string",         "ssh.compression_algorithms_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_client_to_server,
          { "languages_client_to_server string",         "ssh.languages_client_to_server",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_server_to_client,
          { "languages_server_to_client string",         "ssh.languages_server_to_client",
            FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_algorithms_length,
          { "kex_algorithms length",         "ssh.kex_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_server_host_key_algorithms_length,
          { "server_host_key_algorithms length",         "ssh.server_host_key_algorithms_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_client_to_server_length,
          { "encryption_algorithms_client_to_server length",         "ssh.encryption_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_encryption_algorithms_server_to_client_length,
          { "encryption_algorithms_server_to_client length",         "ssh.encryption_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_client_to_server_length,
          { "mac_algorithms_client_to_server length",         "ssh.mac_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_mac_algorithms_server_to_client_length,
          { "mac_algorithms_server_to_client length",         "ssh.mac_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_client_to_server_length,
          { "compression_algorithms_client_to_server length",         "ssh.compression_algorithms_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_compression_algorithms_server_to_client_length,
          { "compression_algorithms_server_to_client length",         "ssh.compression_algorithms_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_client_to_server_length,
          { "languages_client_to_server length",         "ssh.languages_client_to_server_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_languages_server_to_client_length,
          { "languages_server_to_client length",         "ssh.languages_server_to_client_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_first_kex_packet_follows,
          { "First KEX Packet Follows",      "ssh.first_kex_packet_follows",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_reserved,
          { "Reserved",  "ssh.kex.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_length,
          { "Host key length",         "ssh.host_key.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_type_length,
          { "Host key type length",         "ssh.host_key.type_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_type,
          { "Host key type",         "ssh.host_key.type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_data,
          { "Host key data",         "ssh.host_key.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_n,
          { "RSA modulus (N)",         "ssh.host_key.rsa.n",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_rsa_e,
          { "RSA public exponent (e)",         "ssh.host_key.rsa.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_p,
          { "DSA prime modulus (p)",  "ssh.host_key.dsa.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_q,
          { "DSA prime divisor (q)",  "ssh.host_key.dsa.q",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_g,
          { "DSA subgroup generator (g)",  "ssh.host_key.dsa.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_dsa_y,
          { "DSA public key (y)",  "ssh.host_key.dsa.y",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_curve_id,
          { "ECDSA elliptic curve identifier",  "ssh.host_key.ecdsa.id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_curve_id_length,
          { "ECDSA elliptic curve identifier length",  "ssh.host_key.ecdsa.id_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_q,
          { "ECDSA public key (Q)",  "ssh.host_key.ecdsa.q",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_ecdsa_q_length,
          { "ECDSA public key length",  "ssh.host_key.ecdsa.q_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_eddsa_key,
          { "EdDSA public key",  "ssh.host_key.eddsa.key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_hostkey_eddsa_key_length,
          { "EdDSA public key length",  "ssh.host_key.eddsa.key_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_h_sig,
          { "KEX H signature",         "ssh.kex.h_sig",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_kex_h_sig_length,
          { "KEX H signature length",         "ssh.kex.h_sig_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_e,
          { "DH client e",  "ssh.dh.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_f,
          { "DH server f",  "ssh.dh.f",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_gex_min,
          { "DH GEX Min",  "ssh.dh_gex.min",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Minimal acceptable group size", HFILL }},

        { &hf_ssh_dh_gex_nbits,
          { "DH GEX Number of Bits",  "ssh.dh_gex.nbits",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Preferred group size", HFILL }},

        { &hf_ssh_dh_gex_max,
          { "DH GEX Max",  "ssh.dh_gex.max",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Maximal acceptable group size", HFILL }},

        { &hf_ssh_dh_gex_p,
          { "DH GEX modulus (P)",  "ssh.dh_gex.p",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_dh_gex_g,
          { "DH GEX base (G)",  "ssh.dh_gex.g",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_c,
          { "ECDH client's ephemeral public key (Q_C)",  "ssh.ecdh.q_c",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_c_length,
          { "ECDH client's ephemeral public key length",  "ssh.ecdh.q_c_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_s,
          { "ECDH server's ephemeral public key (Q_S)",  "ssh.ecdh.q_s",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_ecdh_q_s_length,
          { "ECDH server's ephemeral public key length",  "ssh.ecdh.q_s_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            NULL, HFILL }},

        { &hf_ssh_mpint_length,
          { "Multi Precision Integer Length",      "ssh.mpint_length",
            FT_UINT32, BASE_DEC, NULL,  0x0,
            NULL, HFILL }},

        { &hf_ssh_service_name_length,
          { "Service Name length",  "ssh.service_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_service_name,
          { "Service Name",  "ssh.service_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_reason,
          { "Disconnect reason",  "ssh.disconnect_reason",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_description_length,
          { "Disconnect description length",  "ssh.disconnect_description_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_disconnect_description,
          { "Disconnect description",  "ssh.disconnect_description",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag_length,
          { "Language tag length",  "ssh.lang_tag_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_lang_tag,
          { "Language tag",  "ssh.lang_tag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_user_name_length,
          { "Service Name length",  "ssh.userauth_user_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_user_name,
          { "User Name",  "ssh.userauth_user_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_service_name_length,
          { "User Name length",  "ssh.userauth_service_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_service_name,
          { "Service Name",  "ssh.userauth_service_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_method_name_length,
          { "Method Name length",  "ssh.userauth_method_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_method_name,
          { "Method Name",  "ssh.userauth_method_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_auth_failure_list_length,
          { "Authentications that can continue list len",  "ssh.auth_failure_cont_list_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_auth_failure_list,
          { "Authentications that can continue list",  "ssh.auth_failure_cont_list",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_pka_name_len,
          { "Public key algorithm name length",  "ssh.userauth_pka_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_userauth_pka_name,
          { "Public key algorithm name",  "ssh.userauth_pka_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_blob_name_length,
          { "Public key blob algorithm name length",  "ssh.pk_blob_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_blob_name,
          { "Public key blob algorithm name",  "ssh.pk_blob_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_length,
          { "Public key blob length",  "ssh.pk_blob_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_p,
          { "ssh-rsa modulus (n)",  "ssh.blob.ssh-rsa.n",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_blob_e,
          { "ssh-rsa public exponent (e)",  "ssh.blob.ssh-rsa.e",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_signature_length,
          { "Public key signature blob length",  "ssh.pk_sig_blob_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_blob_name_length,
          { "Public key signature blob algorithm name length",  "ssh.pk_sig_blob_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_blob_name,
          { "Public key signature blob algorithm name",  "ssh.pk_sig_blob_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_s_length,
          { "ssh-rsa signature length",  "ssh.sig.ssh-rsa.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_pk_sig_s,
          { "ssh-rsa signature (s)",  "ssh.sig.ssh-rsa.s",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_type_name_len,
          { "Channel type name length",  "ssh.connection_type_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_type_name,
          { "Channel type name",  "ssh.connection_type_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_sender_channel,
          { "Sender channel",  "ssh.connection_sender_channel",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_recipient_channel,
          { "Recipient channel",  "ssh.connection_recipient_channel",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_initial_window,
          { "Initial window size",  "ssh.connection_initial_window_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_connection_maximum_packet_size,
          { "Maximum packet size",  "ssh.userauth_maximum_packet_size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_name_len,
          { "Global request name length",  "ssh.global_request_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_name,
          { "Global request name length",  "ssh.global_request_name_length",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_global_request_want_reply,
          { "Global request want reply",  "ssh.global_request_want_reply",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_name_len,
          { "Channel request name length",  "ssh.global_request_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_name,
          { "Channel request name",  "ssh.global_request_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_request_want_reply,
          { "Channel request want reply",  "ssh.channel_request_want_reply",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_subsystem_name_len,
          { "Subsystem name length",  "ssh.subsystem_name_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_subsystem_name,
          { "Subsystem name",  "ssh.subsystem_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_exit_status,
          { "Exit status",  "ssh.exit_status",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_window_adjust,
          { "Bytes to add",  "ssh.channel_window_adjust",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ssh_channel_data_len,
          { "Data length",  "ssh.channel_data_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

    };

    static gint *ett[] = {
        &ett_ssh,
        &ett_key_exchange,
        &ett_key_exchange_host_key,
        &ett_userauth_pk_blob,
        &ett_userauth_pk_signautre,
        &ett_ssh1,
        &ett_ssh2,
        &ett_key_init
    };

    static ei_register_info ei[] = {
        { &ei_ssh_packet_length, { "ssh.packet_length.error", PI_PROTOCOL, PI_WARN, "Overly large number", EXPFILL }},
    };

    module_t *ssh_module;
    expert_module_t *expert_ssh;

    proto_ssh = proto_register_protocol("SSH Protocol", "SSH", "ssh");
    proto_register_field_array(proto_ssh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ssh = expert_register_protocol(proto_ssh);
    expert_register_field_array(expert_ssh, ei, array_length(ei));

    ssh_module = prefs_register_protocol(proto_ssh, NULL);
    prefs_register_bool_preference(ssh_module, "desegment_buffers",
                       "Reassemble SSH buffers spanning multiple TCP segments",
                       "Whether the SSH dissector should reassemble SSH buffers spanning multiple TCP segments. "
                       "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                       &ssh_desegment);

#ifdef SSH_DECRYPTION_SUPPORTED
    ssh_master_key_map = g_hash_table_new(ssl_hash, ssl_equal);
    prefs_register_filename_preference(ssh_module, "keylog_file", "Key log filename",
            "The path to the file which contains a list of key exchange secrets in the following format:\n"
            "\"<hex-encoded-cookie> <hex-encoded-key>\" (without quotes or leading spaces).\n",
            &pref_keylog_file, FALSE);

    secrets_register_type(SECRETS_TYPE_SSH, ssh_secrets_block_callback);
#endif

    ssh_handle = register_dissector("ssh", dissect_ssh, proto_ssh);
}

void
proto_reg_handoff_ssh(void)
{
    dissector_add_uint_range_with_preference("tcp.port", TCP_RANGE_SSH, ssh_handle);
    dissector_add_uint("sctp.port", SCTP_PORT_SSH, ssh_handle);
    dissector_add_uint("sctp.ppi", SSH_PAYLOAD_PROTOCOL_ID, ssh_handle);
    sftp_handle = find_dissector("sftp");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
