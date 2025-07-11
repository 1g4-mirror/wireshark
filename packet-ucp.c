/* packet-ucp.c
 * Routines for Universal Computer Protocol dissection
 * Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
 *
 * $Id: packet-ucp.c,v 1.13 2002/02/15 11:24:45 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * ----------
 *
 * Dissector of a UCP (Universal Computer Protocol) PDU, as defined for the
 * ERMES paging system in ETS 300 133-3 (2nd final draft, September 1997,
 * www.etsi.org).
 * Includes the extension of EMI-UCP interface (V4.0, May 2001, www.cmgwds.com)
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
/* #include "packet-ucp.h" */			/* We autoregister	*/

/* Prototypes	*/
static void dissect_ucp(tvbuff_t *, packet_info *, proto_tree *);

/*
 * Convert ASCII-hex character to binary equivalent. No checks, assume
 * is valid hex character.
 */
#define AHex2Bin(n)	(((n) & 0x40) ? ((n) & 0x0F) + 9 : ((n) & 0x0F))

#define UCP_STX		0x02			/* Start of UCP PDU	*/
#define UCP_ETX		0x03			/* End of UCP PDU	*/

#define UCP_MALFORMED	-1			/* Not a valid PDU	*/
#define UCP_SHORTENED	-2			/* May be valid but short */
#define UCP_INV_CHK	-3			/* Checksum doesn't add up */

#define	UCP_O_R_OFFSET 10			/* Location of O/R field*/
#define UCP_OT_OFFSET  12			/* Location of OT field	*/

#define UCP_TRN_LEN	2			/* Length of TRN-field	*/
#define UCP_LEN_LEN	5			/* Length of LEN-field	*/
#define UCP_O_R_LEN	1			/* Length of O/R-field	*/
#define UCP_OT_LEN	2			/* Length of OT-field	*/

/*
 * Initialize the protocol and registered fields
 *
 * Header (fixed) section
 */
static int proto_ucp = -1;

static int hf_ucp_hdr_TRN	= -1;
static int hf_ucp_hdr_LEN	= -1;
static int hf_ucp_hdr_O_R	= -1;
static int hf_ucp_hdr_OT	= -1;

/*
 * Data (variable) section
 */
static int hf_ucp_oper_section	= -1;
static int hf_ucp_parm_AdC	= -1;
static int hf_ucp_parm_OAdC	= -1;
static int hf_ucp_parm_DAdC	= -1;
static int hf_ucp_parm_AC	= -1;
static int hf_ucp_parm_OAC	= -1;
static int hf_ucp_parm_BAS	= -1;
static int hf_ucp_parm_LAR	= -1;
static int hf_ucp_parm_LAC	= -1;
static int hf_ucp_parm_L1R	= -1;
static int hf_ucp_parm_L1P	= -1;
static int hf_ucp_parm_L3R	= -1;
static int hf_ucp_parm_L3P	= -1;
static int hf_ucp_parm_LCR	= -1;
static int hf_ucp_parm_LUR	= -1;
static int hf_ucp_parm_LRR	= -1;
static int hf_ucp_parm_RT	= -1;
static int hf_ucp_parm_NoN	= -1;
static int hf_ucp_parm_NoA	= -1;
static int hf_ucp_parm_NoB	= -1;
static int hf_ucp_parm_NAC	= -1;
static int hf_ucp_parm_PNC	= -1;
static int hf_ucp_parm_LNo	= -1;
static int hf_ucp_parm_LST	= -1;
static int hf_ucp_parm_TNo	= -1;
static int hf_ucp_parm_CS	= -1;
static int hf_ucp_parm_PID	= -1;
static int hf_ucp_parm_NPL	= -1;
static int hf_ucp_parm_GA	= -1;
static int hf_ucp_parm_RP	= -1;
static int hf_ucp_parm_LRP	= -1;
static int hf_ucp_parm_PR	= -1;
static int hf_ucp_parm_LPR	= -1;
static int hf_ucp_parm_UM	= -1;
static int hf_ucp_parm_LUM	= -1;
static int hf_ucp_parm_RC	= -1;
static int hf_ucp_parm_LRC	= -1;
static int hf_ucp_parm_NRq	= -1;
static int hf_ucp_parm_GAdC	= -1;
static int hf_ucp_parm_A_D	= -1;
static int hf_ucp_parm_CT	= -1;
static int hf_ucp_parm_AAC	= -1;
static int hf_ucp_parm_MNo	= -1;
static int hf_ucp_parm_R_T	= -1;
static int hf_ucp_parm_IVR5x	= -1;
static int hf_ucp_parm_REQ_OT	= -1;
static int hf_ucp_parm_SSTAT	= -1;
static int hf_ucp_parm_LMN	= -1;
static int hf_ucp_parm_NMESS	= -1;
static int hf_ucp_parm_NMESS_str= -1;
static int hf_ucp_parm_NAdC	= -1;
static int hf_ucp_parm_NT	= -1;
static int hf_ucp_parm_NPID	= -1;
static int hf_ucp_parm_LRq	= -1;
static int hf_ucp_parm_LRAd	= -1;
static int hf_ucp_parm_LPID	= -1;
static int hf_ucp_parm_DD	= -1;
static int hf_ucp_parm_DDT	= -1;
static int hf_ucp_parm_STx	= -1;
static int hf_ucp_parm_ST	= -1;
static int hf_ucp_parm_SP	= -1;
static int hf_ucp_parm_VP	= -1;
static int hf_ucp_parm_RPID	= -1;
static int hf_ucp_parm_SCTS	= -1;
static int hf_ucp_parm_Dst	= -1;
static int hf_ucp_parm_Rsn	= -1;
static int hf_ucp_parm_DSCTS	= -1;
static int hf_ucp_parm_MT	= -1;
static int hf_ucp_parm_NB	= -1;
static int hf_ucp_data_section	= -1;
static int hf_ucp_parm_MMS	= -1;
static int hf_ucp_parm_DCs	= -1;
static int hf_ucp_parm_MCLs	= -1;
static int hf_ucp_parm_RPI	= -1;
static int hf_ucp_parm_CPg	= -1;
static int hf_ucp_parm_RPLy	= -1;
static int hf_ucp_parm_OTOA	= -1;
static int hf_ucp_parm_HPLMN	= -1;
static int hf_ucp_parm_RES4	= -1;
static int hf_ucp_parm_RES5	= -1;
static int hf_ucp_parm_OTON	= -1;
static int hf_ucp_parm_ONPI	= -1;
static int hf_ucp_parm_STYP0	= -1;
static int hf_ucp_parm_STYP1	= -1;
static int hf_ucp_parm_ACK	= -1;
static int hf_ucp_parm_PWD	= -1;
static int hf_ucp_parm_NPWD	= -1;
static int hf_ucp_parm_VERS	= -1;
static int hf_ucp_parm_LAdC	= -1;
static int hf_ucp_parm_LTON	= -1;
static int hf_ucp_parm_LNPI	= -1;
static int hf_ucp_parm_OPID	= -1;
static int hf_ucp_parm_RES1	= -1;
static int hf_ucp_parm_RES2	= -1;
static int hf_ucp_parm_MVP	= -1;
static int hf_ucp_parm_EC	= -1;
static int hf_ucp_parm_SM	= -1;

static int hf_ucp_parm_XSer	= -1;
static int hf_xser_service	= -1;

/* Initialize the subtree pointers */
static gint ett_ucp  = -1;
static gint ett_XSer = -1;

/*
 * Value-arrays for certain field-contents
 */
static const value_string vals_hdr_O_R[] = {
    {  'O', "Operation" },
    {  'R', "Result" },
    {  0, NULL }
};

static const value_string vals_hdr_OT[] = {	/* Operation type	*/
    {  0, "Enquiry" },
    {  1, "Call input" },
    {  2, "Call input (multiple address)" },
    {  3, "Call input (supplementary services included)" },
    {  4, "Address list information" },
    {  5, "Change address list" },
    {  6, "Advice of accumulated charges" },
    {  7, "Password management" },
    {  8, "Legitimisation code management" },
    {  9, "Standard text information" },
    { 10, "Change standard text" },
    { 11, "Request roaming information" },
    { 12, "Change roaming information" },
    { 13, "Roaming reset" },
    { 14, "Message retrieval" },
    { 15, "Request call barring" },
    { 16, "Cancel call barring" },
    { 17, "Request call diversion" },
    { 18, "Cancel call diversion" },
    { 19, "Request deferred delivery" },
    { 20, "Cancel deferred delivery" },
    { 21, "All features reset" },
    { 22, "Call input (with specific character set)" },
    { 23, "UCP version status request" },
    { 24, "Mobile subscriber feature status request" },
    { 30, "SMS message transfer" },
    { 31, "SMT alert" },
    { 32, "(proprietary)" },
    { 34, "(proprietary)" },
    { 36, "(proprietary)" },
    { 38, "(proprietary)" },
    { 40, "(proprietary)" },
    { 41, "(proprietary)" },
    { 42, "(proprietary)" },
    { 43, "(proprietary)" },
    { 44, "(proprietary)" },
    { 45, "(proprietary)" },
    { 51, "Submit short message" },
    { 52, "Deliver short message" },
    { 53, "Deliver notification" },
    { 54, "Modify message" },
    { 55, "Inquiry message" },
    { 56, "Delete message" },
    { 57, "Inquiry response message" },
    { 58, "Delete response message" },
    { 60, "Session management" },
    { 61, "List management" },
    { 95, "(proprietary)" },
    { 96, "(proprietary)" },
    { 97, "(proprietary)" },
    { 98, "(proprietary)" },
    { 99, "(proprietary)" },
    {  0, NULL }
};

static const value_string vals_parm_EC[] = {	/* Error code	*/
    {  1, "Checksum error" },
    {  2, "Syntax error" },
    {  3, "Operation not supported by system" },
    {  4, "Operation not allowed" },
    {  5, "Call barring active" },
    {  6, "AdC invalid" },
    {  7, "Authentication failure" },
    {  8, "Legitimisation code for all calls, failure" },
    {  9, "GA not valid" },
    { 10, "Repetition not allowed" },
    { 11, "Legitimisation code for repetition, failure" },
    { 12, "Priority call not allowed" },
    { 13, "Legitimisation code for priority call, failure" },
    { 14, "Urgent message not allowed" },
    { 15, "Legitimisation code for urgent message, failure" },
    { 16, "Reverse charging not alllowed" },
    { 17, "Legitimisation code for rev. charging, failure" },
    { 18, "Deferred delivery not allowed" },
    { 19, "New AC not valid" },
    { 20, "New legitimisation code not valid" },
    { 21, "Standard text not valid" },
    { 22, "Time period not valid" },
    { 23, "Message type not supported by system" },
    { 24, "Message too long" },
    { 25, "Requested standard text not valid" },
    { 26, "Message type not valid for the pager type" },
    { 27, "Message not found in SMSC" },
    { 28, "Invalid character set" },
    { 30, "Subscriber hang-up" },
    { 31, "Fax group not supported" },
    { 32, "Fax message type not supported" },
    { 33, "Address already in list (60-series)" },
    { 34, "Address not in list (60-series)" },
    { 35, "List full, cannot add address to list (60-series)" },
    { 36, "RPID already in use" },
    { 37, "Delivery in progress" },
    { 38, "Message forwarded" },
    { 50, "Low network status" },
    { 51, "Legitimisation code for standard text, failure" },
    { 53, "Operation partially successfull" },
    { 54, "Operation not successfull" },
    { 55, "System error" },
    { 57, "AdC already a member of GAdC address list" },
    { 58, "AdC not a member of GAdC address list" },
    { 59, "Requested standard text list invalid" },
    { 61, "Not controller of GAdC address list" },
    { 62, "Standard text too large" },
    { 63, "Not owner of standard text list" },
    { 64, "Address list full" },
    { 65, "GAdC invalid" },
    { 66, "Operation restricted to mobile subscribers" },
    { 68, "Invalid AdC type" },
    { 69, "Cannot add AdC to GAdC address list" },
    { 90, "(proprietary error code)" },
    { 91, "(proprietary error code)" },
    { 92, "(proprietary error code)" },
    { 93, "(proprietary error code)" },
    { 94, "(proprietary error code)" },
    { 95, "(proprietary error code)" },
    { 96, "(proprietary error code)" },
    { 97, "(proprietary error code)" },
    { 98, "(proprietary error code)" },
    { 99, "(proprietary error code)" },
    {  0, NULL },
};

static const value_string vals_parm_NRq[] = {
    {  '0', "NAdC not used" },
    {  '1', "NAdC used" },
    {  0, NULL },
};

static const value_string vals_parm_NT[] = {
    {  '0', "Default value" },
    {  '1', "Delivery notification" },
    {  '2', "Non-delivery notification" },
    {  '3', "Delivery and Non-delivery notification" },
    {  '4', "Buffered message notification" },
    {  '5', "Buffered and Delivery notification" },
    {  '6', "Buffered and Non-delivery notification" },
    {  '7', "All notifications" },
    {  0, NULL },
};

static const value_string vals_parm_PID[] = {
    {  100, "Mobile station" },
    {  122, "Fax Group 3" },
    {  131, "X.400" },
    {  138, "Menu over PSTN" },
    {  139, "PC appl. over PSTN (E.164)" },
    {  339, "PC appl. over X.25 (X.121)" },
    {  439, "PC appl. over ISDN (E.164)" },
    {  539, "PC appl. over TCP/IP" },
    {  0, NULL },
};

static const value_string vals_parm_LRq[] = {
    {  '0', "LRAd not used" },
    {  '1', "LRAd used" },
    {  0, NULL },
};

static const value_string vals_parm_DD[] = {
    {  '0', "DDT not used" },
    {  '1', "DDT used" },
    {  0, NULL },
};

static const value_string vals_parm_Dst[] = {
    {  '0', "delivered" },
    {  '1', "buffered (see Rsn)" },
    {  '2', "not delivered (see Rsn)" },
    {  0, NULL },
};

static const value_string vals_parm_Rsn[] = {
    {    0, "Unknown subscriber" },
    {    1, "Service temporary not available" },
    {    2, "Service temporary not available" },
    {    3, "Service temporary not available" },
    {    4, "Service temporary not available" },
    {    5, "Service temporary not available" },
    {    6, "Service temporary not available" },
    {    7, "Service temporary not available" },
    {    8, "Service temporary not available" },
    {    9, "Illegal error code" },
    {   10, "Network time-out" },
    {  100, "Facility not supported" },
    {  101, "Unknown subscriber" },
    {  102, "Facility not provided" },
    {  103, "Call barred" },
    {  104, "Operation barred" },
    {  105, "SC congestion" },
    {  106, "Facility not supported" },
    {  107, "Absent subscriber" },
    {  108, "Delivery fail" },
    {  109, "Sc congestion" },
    {  110, "Protocol error" },
    {  111, "MS not equiped" },
    {  112, "Unknown SC" },
    {  113, "SC congestion" },
    {  114, "Illegal MS" },
    {  115, "MS nota subscriber" },
    {  116, "Error in MS" },
    {  117, "SMS lower layer not provisioned" },
    {  118, "System fail" },
    {  119, "PLMN system failure" },
    {  120, "HLR system failure" },
    {  121, "VLR system failure" },
    {  122, "Previous VLR system failure" },
    {  123, "Controlling MSC system failure" },
    {  124, "VMSC system failure" },
    {  125, "EIR system failure" },
    {  126, "System failure" },
    {  127, "Unexpected data value" },
    {  200, "Error in address service centre" },
    {  201, "Invalid absolute validity period" },
    {  202, "Short message exceeds maximum" },
    {  203, "Unable to unpack GSM message" },
    {  204, "Unable to convert to IRA alphabet" },
    {  205, "Invalid validity period format" },
    {  206, "Invalid destination address" },
    {  207, "Duplicate message submit" },
    {  208, "Invalid message type indicator" },
    {  0, NULL },
};

static const value_string vals_parm_MT[] = {
    {  '2', "Numeric message" },
    {  '3', "Alphanumeric message" },
    {  '4', "Transparent data" },
    {  0, NULL },
};

static const value_string vals_parm_DCs[] = {
    {  '0', "default alphabet" },
    {  '1', "User defined data (8 bit)" },
    {  0, NULL },
};

static const value_string vals_parm_MCLs[] = {
    {  '0', "message class 0" },
    {  '1', "message class 1" },
    {  '2', "message class 2" },
    {  '3', "message class 3" },
    {  0, NULL },
};

static const value_string vals_parm_RPI[] = {
    {  '1', "Request" },
    {  '2', "Response" },
    {  0, NULL },
};

static const value_string vals_parm_ACK[] = {
    {  'A', "Ack" },
    {  'N', "Nack" },
    {  0, NULL },
};

static const value_string vals_parm_RP[] = {
    {  '1', "Repetition requested" },
    {  0, NULL },
};

static const value_string vals_parm_UM[] = {
    {  '1', "Urgent message" },
    {  0, NULL },
};

static const value_string vals_parm_RC[] = {
    {  '1', "Reverse charging request" },
    {  0, NULL },
};

static const value_string vals_parm_OTON[] = {
    {  '1', "International number" },
    {  '2', "National number" },
    {  '6', "Abbreviated number (short number alias)" },
    {  0, NULL },
};

static const value_string vals_parm_ONPI[] = {
    {  '1', "E.164 address" },
    {  '3', "X.121 address" },
    {  '5', "Private -TCP/IP or abbreviated number- address" },
    {  0, NULL },
};

static const value_string vals_parm_STYP0[] = {
    {  '1', "open session" },
    {  '2', "reserved" },
    {  '3', "change password" },
    {  '4', "open provisioning session" },
    {  '5', "reserved" },
    {  '6', "change provisioning password" },
    {  0, NULL },
};

static const value_string vals_parm_STYP1[] = {
    {  '1', "add item to mo-list" },
    {  '2', "remove item from mo-list" },
    {  '3', "verify item mo-list" },
    {  '4', "add item to mt-list" },
    {  '5', "remove item from mt-list" },
    {  '6', "verify item mt-list" },
    {  0, NULL },
};

static const value_string vals_parm_OPID[] = {
    {  0, "Mobile station" },
    {  39, "PC application" },
    {  0, NULL },
};

static const value_string vals_parm_BAS[] = {
    {  '1', "Barred" },
    {  0, NULL },
};

static const value_string vals_parm_LAR[] = {
    {  '1', "Leg. code for all calls requested" },
    {  0, NULL },
};

static const value_string vals_parm_L1R[] = {
    {  '1', "Leg. code for priority 1 requested" },
    {  0, NULL },
};

static const value_string vals_parm_L3R[] = {
    {  '1', "Leg. code for priority 3 requested" },
    {  0, NULL },
};

static const value_string vals_parm_LCR[] = {
    {  '1', "Leg. code for reverse charging requested" },
    {  0, NULL },
};

static const value_string vals_parm_LUR[] = {
    {  '1', "Leg. code for urgent message requested" },
    {  0, NULL },
};

static const value_string vals_parm_LRR[] = {
    {  '1', "Leg. code for repitition requested" },
    {  0, NULL },
};

static const value_string vals_parm_RT[] = {
    {  '1', "Tone only" },
    {  '2', "Numeric" },
    {  '3', "Alphanumeric" },
    {  '4', "Transparent data" },
    {  0, NULL },
};

static const value_string vals_parm_PNC[] = {
    {  'H', "Home PNC" },
    {  'I', "Input PNC" },
    {  0, NULL },
};

static const value_string vals_parm_A_D[] = {
    {  'A', "Add" },
    {  'D', "Delete" },
    {  0, NULL },
};

static const value_string vals_parm_R_T[] = {
    {  'R', "Retrieval Ok" },
    {  'T', "Retransmit on radio channel" },
    {  0, NULL },
};

static const value_string vals_parm_REQ_OT[] = {
    {  'S', "Send used operation types" },
    {  'N', "Don't send used operation types" },
    {  0, NULL },
};

static const value_string vals_parm_SSTAT[] = {
    {  '0', "All services" },
    {  '1', "All in the moment active servics" },
    {  '2', "Call diversion" },
    {  '3', "Roaming information status" },
    {  '4', "Call barring status" },
    {  '5', "Deferred delivery status" },
    {  '6', "Number of stored messages" },
    {  0, NULL },
};

static const value_string vals_xser_service[] = {
    {  1, "GSM UDH information" },
    {  2, "GSM DCS information" },
    {  3, "[Message Type]            TDMA information exchange" },
    {  4, "[Message Reference]       TDMA information exchange" },
    {  5, "[Privacy Indicator]       TDMA information exchange" },
    {  6, "[Urgency Indicator]       TDMA information exchange" },
    {  7, "[Acknowledgement Request] TDMA information exchange" },
    {  8, "[Messsage Updating]       TDMA information exchange" },
    {  9, "[Call Back Number]        TDMA information exchange" },
    { 10, "[Response Code]           TDMA information exchange" },
    { 11, "[Teleservice ID]          TDMA information exchange" },
    { 12, "Billing identifier" },
    { 13, "Single shot indicator" },
    {  0, NULL },
};

/*!
 * Checks whether the PDU looks a bit like UCP and checks the checksum
 *
 * \param	tvb	The buffer with PDU-data
 * \param	endpkt	Returns pointer, indicating the end of the PDU
 *
 * \return		The state of this PDU
 * \retval	0		Definitely UCP
 * \retval	UCP_SHORTENED	Packet may be there, but not complete
 * \retval	UCP_MALFORMED	Hmmmm, not UCP after all...
 * \retval	UCP_INV_CHK	Nice packet, but checksum doesn't add up...
 */
static int
check_ucp(tvbuff_t *tvb, int *endpkt)
{
    guint	 offset = 1;
    guint	 checksum = 0;
    int		 pkt_check, tmp;
    int		 length;

    length = tvb_find_guint8(tvb, offset, -1, UCP_ETX);
    if (length == -1) {
	*endpkt = tvb_reported_length_remaining(tvb, offset);
	return UCP_SHORTENED;
    }
    if (length > (int) tvb_reported_length(tvb)) {
	*endpkt = 0;
	return UCP_MALFORMED;
    }
    for (; offset < (guint) (length - 2); offset++)
	checksum += tvb_get_guint8(tvb, offset);
    checksum &= 0xFF;
    tmp = tvb_get_guint8(tvb, offset++);
    pkt_check = AHex2Bin(tmp);
    tmp = tvb_get_guint8(tvb, offset++);
    pkt_check = 16 * pkt_check + AHex2Bin(tmp);
    *endpkt = offset + 1;
    if (checksum == (guint) pkt_check)
	return 0;
    else
	return UCP_INV_CHK;
}

/*!
 * UCP equivalent of mktime() (3). Convert date to standard 'time_t' format
 *
 * \param	datestr	The UCP-formatted date to convert
 *
 * \return 		The date in standard 'time_t' format.
 */
static time_t
ucp_mktime(char *datestr)
{
    struct tm	 r_time;

    r_time.tm_mday = 10 * (datestr[0] - '0') + (datestr[1] - '0');
    r_time.tm_mon  = (10 * (datestr[2] - '0') + (datestr[3] - '0')) - 1;
    r_time.tm_year = 10 * (datestr[4] - '0') + (datestr[5] - '0');
    if (r_time.tm_year < 90) 
	r_time.tm_year += 100;
    r_time.tm_hour = 10 * (datestr[6] - '0') + (datestr[7] - '0');
    r_time.tm_min  = 10 * (datestr[8] - '0') + (datestr[9] - '0');
    if (datestr[10])
	r_time.tm_sec  = 10 * (datestr[10] - '0') + (datestr[11] - '0');
    return mktime(&r_time);
}

/*!
 * Scanning routines to add standard types (byte, int, string, data)
 * to the protocol-tree. Each field is seperated with a slash ('/').
 *
 * \param	tree	The protocol tree to add to
 * \param	tvb	Buffer containing the data
 * \param	field	The actual field, whose value needs displaying
 * \param	offset	Location of field within the buffer, returns location
 * 			of next field.
 *
 * \return		For 'int'-types, the value of the field.
 */
static void
ucp_handle_string(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    char	 strval[BUFSIZ];
    int		 idx = 0;
    int		 tmpoff = *offset;

    idx = 0;
    while ((strval[idx++] = tvb_get_guint8(tvb, tmpoff++)) != '/')
	;
    if (idx > 1) {
	strval[--idx] = '\0';
	proto_tree_add_string(tree, field, tvb, *offset, idx, strval);
    }
    *offset = tmpoff;
}

static guint
ucp_handle_byte(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    guint	 intval = 0;

    if ((intval = tvb_get_guint8(tvb, (*offset)++)) != '/') {
	proto_tree_add_uint(tree, field, tvb, *offset - 1, 1, intval);
	(*offset)++;
    }
    return intval;
}

static guint
ucp_handle_int(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    char	 strval[BUFSIZ];
    guint	 intval = 0;
    int		 tmpoff = *offset;
    int		 idx = 0;
 
    while ((strval[idx++] = tvb_get_guint8(tvb, tmpoff++)) != '/')
	;
    if (idx > 1) {
	strval[--idx] = '\0';
	intval = atoi(strval);
	proto_tree_add_uint(tree, field, tvb, *offset, idx, intval);
    }
    *offset = tmpoff;
    return intval;
}

static void
ucp_handle_time(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    char	 strval[BUFSIZ];
    time_t	 tval;
    nstime_t	 tmptime;
    int		 tmpoff = *offset;
    int		 idx = 0;

    while ((strval[idx++] = tvb_get_guint8(tvb, tmpoff++)) != '/')
	;
    if (idx > 1) {
	strval[--idx] = '\0';
	tval = ucp_mktime(strval);
	tmptime.secs  = tval;
	tmptime.nsecs = 0;
	proto_tree_add_time(tree, field, tvb, *offset, idx, &tmptime);
    }
    *offset = tmpoff;
}

static void
ucp_handle_data(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    int		 tmpoff = *offset;

    while (tvb_get_guint8(tvb, tmpoff++) != '/')
	;
    if ((tmpoff - *offset) > 1)	
	proto_tree_add_item(tree, field, tvb, *offset,
			    tmpoff - *offset - 1, FALSE);
    *offset = tmpoff;
}

/*!
 * Handle the data-field within the UCP-message, according the Message Type
 * 	- 1	Tone only
 * 	- 2	Numeric message
 * 	- 3	Alphanumeric message
 * 	- 4	Transparent (binary) data
 * 	- 5	Standard text handling
 * 	- 6	Alphanumeric message in specified character set
 *
 * \param	tree	The protocol tree to add to
 * \param	tvb	Buffer containing the data
 * \param	field	The actual field, whose value needs displaying
 * \param	offset	Location of field within the buffer, returns location
 * 			of next field.
 */
static void
ucp_handle_mt(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    char		 strval[BUFSIZ];
    guint		 intval;
    int			 idx;

    intval = ucp_handle_byte(tree, tvb, hf_ucp_parm_MT, offset);
    switch (intval) {
	case '1':				/* Tone only, no data	*/
	    break;
	case '4':				/* TMsg, no of bits	*/
	    ucp_handle_string(tree, tvb, hf_ucp_parm_NB, offset);
	    /* fall through here for the data piece	*/
	case '2':
	case '3':
	    ucp_handle_data(tree, tvb, hf_ucp_data_section, offset);
	    break;
	case '5':
	    ucp_handle_byte(tree, tvb, hf_ucp_parm_PNC, offset);
	    ucp_handle_string(tree, tvb, hf_ucp_parm_LNo, offset);
	    ucp_handle_string(tree, tvb, hf_ucp_parm_LST, offset);
	    ucp_handle_string(tree, tvb, hf_ucp_parm_TNo, offset);
	    break;
	case '6':
	    ucp_handle_data(tree, tvb, hf_ucp_data_section, offset);
	    ucp_handle_int(tree, tvb, hf_ucp_parm_CS, offset);
	    break;
	default:
	    break;		/* No data so ?	*/
    }
}

/*!
 * Handle the data within the 'Extended services' field. Each field having the
 * format TTLLDD..., TT being the type of service, LL giving the length of the
 * field, DD... containing the actual data
 *
 * \param	tree	The protocol tree to add to
 * \param	tvb	Buffer containing the extended services data
 */
static void
ucp_handle_XSer(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 0;
    guint	 intval;
    int		 service;
    int		 len;

    while ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	service = AHex2Bin(intval);
	intval = tvb_get_guint8(tvb, offset++);
	service = service * 16 + AHex2Bin(intval);
	intval = tvb_get_guint8(tvb, offset++);
	len = AHex2Bin(intval);
	intval = tvb_get_guint8(tvb, offset++);
	len = len * 16 + AHex2Bin(intval);
	proto_tree_add_uint(tree, hf_xser_service, tvb, offset,
		    	    2 * len, service);
	offset += (2 * len);
    }
}

/* Next definitions are just a convenient shorthand to make the coding a
 * bit more readable instead of summing up all these parameters.
 */
#define UcpHandleString(field)	ucp_handle_string(tree, tvb, (field), &offset)

#define UcpHandleByte(field)	ucp_handle_byte(tree, tvb, (field), &offset)

#define	UcpHandleInt(field)	ucp_handle_int(tree, tvb, (field), &offset)

#define	UcpHandleTime(field)	ucp_handle_time(tree, tvb, (field), &offset)

#define	UcpHandleData(field)	ucp_handle_data(tree, tvb, (field), &offset)

/*!
 * The next set of routines handle the different operation types,
 * associated with UCP.
 */
static void
add_00O(proto_tree *tree, tvbuff_t *tvb)
{						/* Enquiry	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
}

static void
add_00R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A')
    {
	UcpHandleByte(hf_ucp_parm_BAS);
	UcpHandleByte(hf_ucp_parm_LAR);
	UcpHandleByte(hf_ucp_parm_L1R);
	UcpHandleByte(hf_ucp_parm_L3R);
	UcpHandleByte(hf_ucp_parm_LCR);
	UcpHandleByte(hf_ucp_parm_LUR);
	UcpHandleByte(hf_ucp_parm_LRR);
	UcpHandleByte(hf_ucp_parm_RT);
	UcpHandleInt(hf_ucp_parm_NoN);
	UcpHandleInt(hf_ucp_parm_NoA);
	UcpHandleInt(hf_ucp_parm_NoB);
    } else {
	UcpHandleInt(hf_ucp_parm_EC);
	UcpHandleString(hf_ucp_parm_SM);
    }
}

static void
add_01O(proto_tree *tree, tvbuff_t *tvb)
{						/* Call input	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    ucp_handle_mt(tree, tvb, &offset);
}

static void
add_01R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'N')
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_02O(proto_tree *tree, tvbuff_t *tvb)
{						/* Multiple address call input*/
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
	UcpHandleString(hf_ucp_parm_AdC);

    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    ucp_handle_mt(tree, tvb, &offset);
}

#define add_02R(a, b) add_01R(a,b)

static void
add_03O(proto_tree *tree, tvbuff_t *tvb)
{						/* Call input with SS	*/
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
	UcpHandleString(hf_ucp_parm_GA);

    UcpHandleByte(hf_ucp_parm_RP);
    UcpHandleString(hf_ucp_parm_LRP);
    UcpHandleByte(hf_ucp_parm_PR);
    UcpHandleString(hf_ucp_parm_LPR);
    UcpHandleByte(hf_ucp_parm_UM);
    UcpHandleString(hf_ucp_parm_LUM);
    UcpHandleByte(hf_ucp_parm_RC);
    UcpHandleString(hf_ucp_parm_LRC);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);
    ucp_handle_mt(tree, tvb, &offset);
}

#define add_03R(a, b) add_01R(a,b)

static void
add_04O(proto_tree *tree, tvbuff_t *tvb)
{						/* Address list information */
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_GAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
}

static void
add_04R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	intval = UcpHandleInt(hf_ucp_parm_NPL);
	for (idx = 0; idx < intval; idx++)
	    UcpHandleString(hf_ucp_parm_AdC);
	UcpHandleString(hf_ucp_parm_GAdC);
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_05O(proto_tree *tree, tvbuff_t *tvb)
{						/* Change address list */
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    UcpHandleString(hf_ucp_parm_GAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
	UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleByte(hf_ucp_parm_A_D);
}

#define add_05R(a, b) add_01R(a, b)

static void
add_06O(proto_tree *tree, tvbuff_t *tvb)
{						/* Advice of accum. charges */
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
}

static void
add_06R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	UcpHandleTime(hf_ucp_parm_CT);
	UcpHandleString(hf_ucp_parm_AAC);
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_07O(proto_tree *tree, tvbuff_t *tvb)
{						/* Password management	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_NAC);
}

#define add_07R(a, b) add_01R(a, b)

static void
add_08O(proto_tree *tree, tvbuff_t *tvb)
{						/* Leg. code management	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_LAC);
    UcpHandleString(hf_ucp_parm_L1P);
    UcpHandleString(hf_ucp_parm_L3P);
    UcpHandleString(hf_ucp_parm_LRC);
    UcpHandleString(hf_ucp_parm_LUM);
    UcpHandleString(hf_ucp_parm_LRP);
    UcpHandleString(hf_ucp_parm_LST);
}

#define add_08R(a, b) add_01R(a, b)

static void
add_09O(proto_tree *tree, tvbuff_t *tvb)
{						/* Standard text information */
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_LNo);
    UcpHandleString(hf_ucp_parm_LST);
}

static void
add_09R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	intval = UcpHandleInt(hf_ucp_parm_NPL);
	for (idx = 0; idx < intval; idx++)
	    UcpHandleString(hf_ucp_parm_LST);
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_10O(proto_tree *tree, tvbuff_t *tvb)
{						/* Change standard text	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_LNo);
    UcpHandleString(hf_ucp_parm_TNo);
    UcpHandleData(hf_ucp_parm_STx);
    UcpHandleInt(hf_ucp_parm_CS);
}

#define add_10R(a, b) add_01R(a, b)

#define add_11O(a, b) add_06O(a, b)		/* Request roaming info	*/

static void
add_11R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	intval = UcpHandleInt(hf_ucp_parm_NPL);
	for (idx = 0; idx < intval; idx++)
	    UcpHandleString(hf_ucp_parm_GA);
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_12O(proto_tree *tree, tvbuff_t *tvb)
{						/* Change roaming	*/
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    intval = UcpHandleInt(hf_ucp_parm_NPL);
    for (idx = 0; idx < intval; idx++)
	UcpHandleString(hf_ucp_parm_GA);
}

#define add_12R(a, b) add_01R(a, b)

#define add_13O(a, b) add_06O(a, b)		/* Roaming reset	*/

#define add_13R(a, b) add_01R(a, b)

static void
add_14O(proto_tree *tree, tvbuff_t *tvb)
{						/* Message retrieval	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_MNo);
    UcpHandleByte(hf_ucp_parm_R_T);
}

static void
add_14R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	intval = UcpHandleInt(hf_ucp_parm_NPL);
	/*
	 * Spec is unclear here. Is 'SM' part of the Msg:s field or not?
	 * For now, assume it is part of it...
	 */
	for (idx = 0; idx < intval; idx++)
	    UcpHandleData(hf_ucp_data_section);
    } else {
	UcpHandleInt(hf_ucp_parm_EC);
	UcpHandleString(hf_ucp_parm_SM);
    }
}

static void
add_15O(proto_tree *tree, tvbuff_t *tvb)
{						/* Request call barring	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_15R(a, b) add_01R(a, b)

#define add_16O(a, b) add_06O(a, b)		/* Cancel call barring	*/

#define add_16R(a, b) add_01R(a, b)

static void
add_17O(proto_tree *tree, tvbuff_t *tvb)
{						/* Request call diversion */
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleString(hf_ucp_parm_DAdC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_17R(a, b) add_01R(a, b)

#define add_18O(a, b) add_06O(a, b)		/* Cancel call diversion */

#define add_18R(a, b) add_01R(a, b)

static void
add_19O(proto_tree *tree, tvbuff_t *tvb)
{						/* Request deferred delivery*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleTime(hf_ucp_parm_ST);
    UcpHandleTime(hf_ucp_parm_SP);
}

#define add_19R(a, b) add_01R(a, b)

#define add_20O(a, b) add_06O(a, b)		/* Cancel deferred delivery */

#define add_20R(a, b) add_01R(a, b)

#define add_21O(a, b) add_06O(a, b)		/* All features reset	*/

#define add_21R(a, b) add_01R(a, b)

static void
add_22O(proto_tree *tree, tvbuff_t *tvb)
{						/* Call input w. add. CS */
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_OAC);
    UcpHandleData(hf_ucp_data_section);
    UcpHandleInt(hf_ucp_parm_CS);
}

#define add_22R(a, b) add_01R(a, b)

static void
add_23O(proto_tree *tree, tvbuff_t *tvb)
{						/* UCP version status	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_IVR5x);
    UcpHandleByte(hf_ucp_parm_REQ_OT);
}

static void
add_23R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	UcpHandleByte(hf_ucp_parm_IVR5x);
	intval = UcpHandleInt(hf_ucp_parm_NPL);
	for (idx = 0; idx < intval; idx++)
	    UcpHandleInt(hf_ucp_hdr_OT);
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_24O(proto_tree *tree, tvbuff_t *tvb)
{						/* Mobile subs. feature stat*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_SSTAT);
}

static void
add_24R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;
    guint	 idx;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A') {
	if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	    proto_tree_add_text(tree, tvb, offset - 1, 1,
				"GA roaming definitions");
	    if (intval == 'N') {
		proto_tree_add_text(tree, tvb, offset -1, 1,
				"Not subscribed/not allowed");
		offset++;
	    } else {
		--offset;
		intval = UcpHandleInt(hf_ucp_parm_NPL);
		for (idx = 0; idx < intval; idx++)
		    UcpHandleData(hf_ucp_data_section);
	    }
	}
	if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	    proto_tree_add_text(tree, tvb, offset - 1, 1,
				"Call barring definitions");
	    if (intval == 'N') {
		proto_tree_add_text(tree, tvb, offset -1, 1,
				"Not subscribed/not allowed");
		offset++;
	    } else {
		--offset;
		intval = UcpHandleInt(hf_ucp_parm_NPL);
		for (idx = 0; idx < intval; idx++)
		    UcpHandleData(hf_ucp_data_section);
	    }
	}
	if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	    proto_tree_add_text(tree, tvb, offset - 1, 1,
				"Deferred delivery definitions");
	    if (intval == 'N') {
		proto_tree_add_text(tree, tvb, offset -1, 1,
				"Not subscribed/not allowed");
		offset++;
	    } else {
		--offset;
		intval = UcpHandleInt(hf_ucp_parm_NPL);
		for (idx = 0; idx < intval; idx++)
		    UcpHandleData(hf_ucp_data_section);
	    }
	}
	if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	    proto_tree_add_text(tree, tvb, offset - 1, 1,
				"Diversion definitions");
	    if (intval == 'N') {
		proto_tree_add_text(tree, tvb, offset -1, 1,
				"Not subscribed/not allowed");
		offset++;
	    } else {
		--offset;
		intval = UcpHandleInt(hf_ucp_parm_NPL);
		for (idx = 0; idx < intval; idx++)
		    UcpHandleData(hf_ucp_data_section);
	    }
	}
	UcpHandleInt(hf_ucp_parm_LMN);
	if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	    if (intval == 'N') {
		proto_tree_add_string(tree, hf_ucp_parm_NMESS_str, tvb,
				offset -1, 1, "Not subscribed/not allowed");
		offset++;
	    } else {
		--offset;
		intval = UcpHandleInt(hf_ucp_parm_NMESS);
	    }
	}
    } else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_30O(proto_tree *tree, tvbuff_t *tvb)
{						/* SMS message transfer	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_NRq);
    UcpHandleString(hf_ucp_parm_NAdC);
    UcpHandleInt(hf_ucp_parm_NPID);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);
    UcpHandleTime(hf_ucp_parm_VP);
    UcpHandleData(hf_ucp_data_section);
}

static void
add_30R(proto_tree *tree, tvbuff_t *tvb)
{
    int		 offset = 1;
    guint	 intval;

    intval = UcpHandleByte(hf_ucp_parm_ACK);
    if (intval == 'A')
	UcpHandleTime(hf_ucp_parm_MVP);
    else
	UcpHandleInt(hf_ucp_parm_EC);
    UcpHandleString(hf_ucp_parm_SM);
}

static void
add_31O(proto_tree *tree, tvbuff_t *tvb)
{						/* SMT alert		*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleInt(hf_ucp_parm_PID);
}

#define add_31R(a, b) add_01R(a, b)

static void
add_5xO(proto_tree *tree, tvbuff_t *tvb)
{						/* 50-series operations	*/
    guint	 intval;
    int		 offset = 1;
    int		 tmpoff;
    proto_item	*ti;
    tvbuff_t	*tmptvb;

    UcpHandleString(hf_ucp_parm_AdC);
    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleString(hf_ucp_parm_AC);
    UcpHandleByte(hf_ucp_parm_NRq);
    UcpHandleString(hf_ucp_parm_NAdC);
    UcpHandleByte(hf_ucp_parm_NT);
    UcpHandleInt(hf_ucp_parm_NPID);
    UcpHandleByte(hf_ucp_parm_LRq);
    UcpHandleString(hf_ucp_parm_LRAd);
    UcpHandleInt(hf_ucp_parm_LPID);
    UcpHandleByte(hf_ucp_parm_DD);
    UcpHandleTime(hf_ucp_parm_DDT);
    UcpHandleTime(hf_ucp_parm_VP);
    UcpHandleString(hf_ucp_parm_RPID);
    UcpHandleTime(hf_ucp_parm_SCTS);
    UcpHandleByte(hf_ucp_parm_Dst);
    UcpHandleInt(hf_ucp_parm_Rsn);
    UcpHandleTime(hf_ucp_parm_DSCTS);
    UcpHandleByte(hf_ucp_parm_MT);
    UcpHandleString(hf_ucp_parm_NB);
    UcpHandleData(hf_ucp_data_section);
    UcpHandleByte(hf_ucp_parm_MMS);
    UcpHandleByte(hf_ucp_parm_PR);
    UcpHandleByte(hf_ucp_parm_DCs);
    UcpHandleByte(hf_ucp_parm_MCLs);
    UcpHandleByte(hf_ucp_parm_RPI);
    if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	proto_tree_add_string(tree, hf_ucp_parm_CPg, tvb, offset - 1,1,
			      "(reserved for Code Page)");
	offset++;
    }
    if ((intval = tvb_get_guint8(tvb, offset++)) != '/') {
	proto_tree_add_string(tree, hf_ucp_parm_RPLy, tvb, offset - 1,1,
			      "(reserved for Reply type)");
	offset++;
    }
    UcpHandleString(hf_ucp_parm_OTOA);
    UcpHandleString(hf_ucp_parm_HPLMN);
    tmpoff = offset;				/* Extra services	*/
    while (tvb_get_guint8(tvb, tmpoff++) != '/')
	;
    if ((tmpoff - offset) > 1) {
	int	 len = tmpoff - offset - 1;

	ti = proto_tree_add_item(tree, hf_ucp_parm_XSer,tvb,offset,len,FALSE);
	tmptvb = tvb_new_subset(tvb, offset, len + 1, len + 1);
	proto_item_add_subtree(ti, ett_XSer);
	ucp_handle_XSer(ti, tmptvb);
    }
    offset = tmpoff;
    UcpHandleData(hf_ucp_parm_RES4);
    UcpHandleData(hf_ucp_parm_RES5);
}

#define add_5xR(a, b) add_30R(a, b)

static void
add_6xO(proto_tree *tree, tvbuff_t *tvb, guint8 OT)
{						/* 60-series operations	*/
    int		 offset = 1;

    UcpHandleString(hf_ucp_parm_OAdC);
    UcpHandleByte(hf_ucp_parm_OTON);
    UcpHandleByte(hf_ucp_parm_ONPI);
    if (OT == 60) {
	UcpHandleByte(hf_ucp_parm_STYP0);
    } else {
	UcpHandleByte(hf_ucp_parm_STYP1);
    }
    UcpHandleData(hf_ucp_parm_PWD);
    UcpHandleData(hf_ucp_parm_NPWD);
    UcpHandleString(hf_ucp_parm_VERS);
    UcpHandleString(hf_ucp_parm_LAdC);
    UcpHandleByte(hf_ucp_parm_LTON);
    UcpHandleByte(hf_ucp_parm_LNPI);
    UcpHandleInt(hf_ucp_parm_OPID);
    UcpHandleData(hf_ucp_parm_RES1);
    UcpHandleData(hf_ucp_parm_RES2);
}

#define add_6xR(a, b) add_01R(a, b)

/*
 * End of convenient shorthands
 */
#undef UcpHandleString
#undef UcpHandleByte
#undef UcpHandleInt
#undef UcpHandleTime
#undef UcpHandleData

/* Code to actually dissect the packets */
/*
 * Overlapping data for these functions
 */
static int	 result, endpkt;

/*
 * The heuristic dissector
 */
static gboolean
dissect_ucp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8	 O_R;		/* Request or response			*/

    /* This runs atop TCP, so we are guaranteed that there is at least one
       byte in the tvbuff. */
    if (tvb_get_guint8(tvb, 0) != UCP_STX)
	return FALSE;

    result = check_ucp(tvb, &endpkt);

    if (result == UCP_MALFORMED)
	return FALSE;
    if (endpkt < UCP_OT_OFFSET + 1)
	/*
	 * Might be shortened packet but don't handle anyway.
	 */
	return FALSE;

    /*
     * Try getting the operation-type and whether it's a request/response 
     */
    O_R = tvb_get_guint8(tvb, UCP_O_R_OFFSET);
    if (match_strval(O_R, vals_hdr_O_R) == NULL)
	return FALSE;
    /*
     * Ok, looks like a valid packet, go dissect.
     */
    dissect_ucp(tvb, pinfo, tree);
    return TRUE;
}

/*
 * The actual dissector
 */
static void
dissect_ucp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int		 offset = 0;	/* Offset in packet within tvbuff	*/
    int		 tmpoff;	/* Local offset value (per field)	*/
    guint8	 O_R;		/* Request or response			*/
    guint8	 OT;		/* Operation type			*/
    guint	 intval;
    int		 i;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item	*ti;
    proto_item	*sub_ti;
    proto_tree	*ucp_tree;
    tvbuff_t	*tmp_tvb;

    O_R = tvb_get_guint8(tvb, UCP_O_R_OFFSET);
    /*
     * So do an atoi() on the operation type
     */
    OT  = tvb_get_guint8(tvb, UCP_OT_OFFSET) - '0';
    OT  = 10 * OT + (tvb_get_guint8(tvb, UCP_OT_OFFSET + 1) - '0');

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UCP");

    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_clear(pinfo->cinfo, COL_INFO);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
		     val_to_str(OT,  vals_hdr_OT,  "unknown operation"),
		     match_strval(O_R, vals_hdr_O_R));
	if (result == UCP_SHORTENED)
	    col_append_str(pinfo->cinfo, COL_INFO, " [short packet]");
	else if (result == UCP_INV_CHK)
	    col_append_str(pinfo->cinfo, COL_INFO, " [checksum invalid]");
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_ucp, tvb, 0, -1, FALSE);

	ucp_tree = proto_item_add_subtree(ti, ett_ucp);
	/*
	 * Process the packet here.
	 * Transaction number
	 */
	offset++;				/* Skip <stx>	*/
	tmpoff = offset;
	intval = tvb_get_guint8(tvb, tmpoff++) - '0';
	intval = 10 * intval + (tvb_get_guint8(tvb, tmpoff++) - '0');
	proto_tree_add_uint(ucp_tree, hf_ucp_hdr_TRN, tvb, offset,
			    UCP_TRN_LEN, intval);
	offset = tmpoff;

	offset++;				/* Skip '/'	*/
	intval = 0;
	tmpoff = offset;
	for (i = 0; i < UCP_LEN_LEN; i++) {	/* Length	*/
	    intval = 10 * intval +
			(tvb_get_guint8(tvb, tmpoff++) - '0');
	}
	proto_tree_add_uint(ucp_tree, hf_ucp_hdr_LEN, tvb, offset,
			    UCP_LEN_LEN, intval);
	offset = tmpoff;

	offset++;				/* Operation/Response	*/
	proto_tree_add_uint(ucp_tree, hf_ucp_hdr_O_R, tvb, offset++,
			    UCP_O_R_LEN, O_R);

	offset++;				/* Operation type */
	proto_tree_add_uint(ucp_tree, hf_ucp_hdr_OT, tvb, offset,
			    UCP_OT_LEN, OT);
	offset += UCP_OT_LEN;
	/*
	 * Variable part starts here. Don't dissect if not complete.
	 */
	if (result == UCP_SHORTENED)
	    return;
	tmp_tvb = tvb_new_subset(tvb, offset, -1, -1);
	sub_ti = proto_tree_add_item(ucp_tree, hf_ucp_oper_section, tvb,
				     offset, endpkt - offset, FALSE);

	switch (OT) {
	    case  1:
		O_R == 'O' ? add_01O(sub_ti,tmp_tvb) : add_01R(sub_ti,tmp_tvb);
		break;
	    case  2:
		O_R == 'O' ? add_02O(sub_ti,tmp_tvb) : add_02R(sub_ti,tmp_tvb);
		break;
	    case  3:
		O_R == 'O' ? add_03O(sub_ti,tmp_tvb) : add_03R(sub_ti,tmp_tvb);
		break;
	    case  4:
		O_R == 'O' ? add_04O(sub_ti,tmp_tvb) : add_04R(sub_ti,tmp_tvb);
		break;
	    case  5:
		O_R == 'O' ? add_05O(sub_ti,tmp_tvb) : add_05R(sub_ti,tmp_tvb);
		break;
	    case  6:
		O_R == 'O' ? add_06O(sub_ti,tmp_tvb) : add_06R(sub_ti,tmp_tvb);
		break;
	    case  7:
		O_R == 'O' ? add_07O(sub_ti,tmp_tvb) : add_07R(sub_ti,tmp_tvb);
		break;
	    case  8:
		O_R == 'O' ? add_08O(sub_ti,tmp_tvb) : add_08R(sub_ti,tmp_tvb);
		break;
	    case  9:
		O_R == 'O' ? add_09O(sub_ti,tmp_tvb) : add_09R(sub_ti,tmp_tvb);
		break;
	    case 10:
		O_R == 'O' ? add_10O(sub_ti,tmp_tvb) : add_10R(sub_ti,tmp_tvb);
		break;
	    case 11:
		O_R == 'O' ? add_11O(sub_ti,tmp_tvb) : add_11R(sub_ti,tmp_tvb);
		break;
	    case 12:
		O_R == 'O' ? add_12O(sub_ti,tmp_tvb) : add_12R(sub_ti,tmp_tvb);
		break;
	    case 13:
		O_R == 'O' ? add_13O(sub_ti,tmp_tvb) : add_13R(sub_ti,tmp_tvb);
		break;
	    case 14:
		O_R == 'O' ? add_14O(sub_ti,tmp_tvb) : add_14R(sub_ti,tmp_tvb);
		break;
	    case 15:
		O_R == 'O' ? add_15O(sub_ti,tmp_tvb) : add_15R(sub_ti,tmp_tvb);
		break;
	    case 16:
		O_R == 'O' ? add_16O(sub_ti,tmp_tvb) : add_16R(sub_ti,tmp_tvb);
		break;
	    case 17:
		O_R == 'O' ? add_17O(sub_ti,tmp_tvb) : add_17R(sub_ti,tmp_tvb);
		break;
	    case 18:
		O_R == 'O' ? add_18O(sub_ti,tmp_tvb) : add_18R(sub_ti,tmp_tvb);
		break;
	    case 19:
		O_R == 'O' ? add_19O(sub_ti,tmp_tvb) : add_19R(sub_ti,tmp_tvb);
		break;
	    case 20:
		O_R == 'O' ? add_20O(sub_ti,tmp_tvb) : add_20R(sub_ti,tmp_tvb);
		break;
	    case 21:
		O_R == 'O' ? add_21O(sub_ti,tmp_tvb) : add_21R(sub_ti,tmp_tvb);
		break;
	    case 22:
		O_R == 'O' ? add_22O(sub_ti,tmp_tvb) : add_22R(sub_ti,tmp_tvb);
		break;
	    case 23:
		O_R == 'O' ? add_23O(sub_ti,tmp_tvb) : add_23R(sub_ti,tmp_tvb);
		break;
	    case 24:
		O_R == 'O' ? add_24O(sub_ti,tmp_tvb) : add_24R(sub_ti,tmp_tvb);
		break;
	    case 30:
		O_R == 'O' ? add_30O(sub_ti,tmp_tvb) : add_30R(sub_ti,tmp_tvb);
		break;
	    case 31:
		O_R == 'O' ? add_31O(sub_ti,tmp_tvb) : add_31R(sub_ti,tmp_tvb);
		break;
	    case 51: case 52: case 53: case 54: case 55: case 56: case 57:
	    case 58:
		O_R == 'O' ? add_5xO(sub_ti,tmp_tvb) : add_5xR(sub_ti,tmp_tvb);
		break;
	    case 60: case 61:
		O_R == 'O' ? add_6xO(sub_ti,tmp_tvb,OT) : add_6xR(sub_ti,tmp_tvb);
		break;
	    default:
		break;
	}
    }
    return;
}

/* Register the protocol with Ethereal */
void
proto_register_ucp(void)
{

    /* Setup list of fields	*/
    static hf_register_info hf[] = {
	{ &hf_ucp_hdr_TRN,
	    { "Transaction Reference Number", "ucp.hdr.TRN",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Transaction number for this command, used in windowing.",
	      HFILL
	    }
	},
	{ &hf_ucp_hdr_LEN,
	    { "Length", "ucp.hdr.LEN",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      "Total number of characters between <stx>...<etx>.",
	      HFILL
	    }
	},
	{ &hf_ucp_hdr_O_R,
	    { "Type", "ucp.hdr.O_R",
	      FT_UINT8, BASE_DEC, VALS(vals_hdr_O_R), 0x00,
	      "Your basic 'is a request or response'.",
	      HFILL
	    }
	},
	{ &hf_ucp_hdr_OT,
	    { "Operation", "ucp.hdr.OT",
	      FT_UINT8, BASE_DEC, VALS(vals_hdr_OT), 0x00,
	      "The operation that is requested with this message.",
	      HFILL
	    }
	},
	{ &hf_ucp_oper_section,
	    { "Data", "ucp.parm",
	      FT_NONE, BASE_DEC, NULL, 0x00,
	      "The actual content of the operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_AdC,
	    { "AdC", "ucp.parm.AdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Address code recipient.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_OAdC,
	    { "OAdC", "ucp.parm.OAdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Address code originator.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_DAdC,
	    { "DAdC", "ucp.parm.DAdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Diverted address code.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_AC,
	    { "AC", "ucp.parm.AC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Authentication code.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_OAC,
	    { "OAC", "ucp.parm.OAC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Authentication code, originator.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NAC,
	    { "NAC", "ucp.parm.NAC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "New authentication code.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_BAS,
	    { "BAS", "ucp.parm.BAS",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_BAS), 0x00,
	      "Barring status flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LAR,
	    { "LAR", "ucp.parm.LAR",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_LAR), 0x00,
	      "Leg. code for all calls flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LAC,
	    { "LAC", "ucp.parm.LAC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "New leg. code for all calls.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_L1R,
	    { "L1R", "ucp.parm.L1R",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_L1R), 0x00,
	      "Leg. code for priority 1 flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_L1P,
	    { "L1P", "ucp.parm.L1P",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "New leg. code for level 1 priority.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_L3R,
	    { "L3R", "ucp.parm.L3R",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_L3R), 0x00,
	      "Leg. code for priority 3 flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_L3P,
	    { "L3P", "ucp.parm.L3P",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "New leg. code for level 3 priority.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LCR,
	    { "LCR", "ucp.parm.LCR",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_LCR), 0x00,
	      "Leg. code for reverse charging flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LUR,
	    { "LUR", "ucp.parm.LUR",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_LUR), 0x00,
	      "Leg. code for urgent message flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LRR,
	    { "LRR", "ucp.parm.LRR",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_LRR), 0x00,
	      "Leg. code for repitition flag.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RT,
	    { "RT", "ucp.parm.RT",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_RT), 0x00,
	      "Receiver type.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NoN,
	    { "NoN", "ucp.parm.NoN",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      "Maximum number of numerical characters accepted.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NoA,
	    { "NoA", "ucp.parm.NoA",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      "Maximum number of alphanumerical characters accepted.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NoB,
	    { "NoB", "ucp.parm.NoB",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      "Maximum number of data bits accepted.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_PNC,
	    { "PNC", "ucp.parm.PNC",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_PNC), 0x00,
	      "Paging network controller.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LNo,
	    { "LNo", "ucp.parm.LNo",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Standard text list number requested by calling party.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LST,
	    { "LST", "ucp.parm.LST",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Legitimisation code for standard text.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_TNo,
	    { "TNo", "ucp.parm.TNo",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Standard text number requested by calling party.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_CS,
	    { "CS", "ucp.parm.CS",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Additional character set number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_PID,
	    { "PID", "ucp.parm.PID",
	      FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
	      "SMT PID value.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NPL,
	    { "NPL", "ucp.parm.NPL",
	      FT_UINT16, BASE_DEC, NULL, 0x00,
	      "Number of parameters in the following list.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_GA,
	    { "GA", "ucp.parm.GA",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "GA?? haven't got a clue.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RP,
	    { "RP", "ucp.parm.RP",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_RP), 0x00,
	      "Repitition requested.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LRP,
	    { "LRP", "ucp.parm.LRP",
	      FT_STRING, BASE_DEC, NULL, 0x00,
	      "Legitimisation code for repitition.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_PR,
	    { "PR", "ucp.parm.PR",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Priority requested.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LPR,
	    { "LPR", "ucp.parm.LPR",
	      FT_STRING, BASE_DEC, NULL, 0x00,
	      "Legitimisation code for priority requested.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_UM,
	    { "UM", "ucp.parm.UM",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_UM), 0x00,
	      "Urgent message indicator.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LUM,
	    { "LUM", "ucp.parm.LUM",
	      FT_STRING, BASE_DEC, NULL, 0x00,
	      "Legitimisation code for urgent message.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RC,
	    { "RC", "ucp.parm.RC",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_RC), 0x00,
	      "Reverse charging request.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LRC,
	    { "LRC", "ucp.parm.LRC",
	      FT_STRING, BASE_DEC, NULL, 0x00,
	      "Legitimisation code for reverse charging.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NRq,
	    { "NRq", "ucp.parm.NRq",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_NRq), 0x00,
	      "Notification request.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_GAdC,
	    { "GAdC", "ucp.parm.GAdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Group address code.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_A_D,
	    { "A_D", "ucp.parm.A_D",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_A_D), 0x00,
	      "Add to/delete from fixed subscriber address list record.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_CT,
	    { "CT", "ucp.parm.CT",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Accumulated charges timestamp.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_AAC,
	    { "AAC", "ucp.parm.AAC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Accumulated charges.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_MNo,
	    { "MNo", "ucp.parm.MNo",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Message number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_R_T,
	    { "R_T", "ucp.parm.R_T",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Message number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NAdC,
	    { "NAdC", "ucp.parm.NAdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Notification address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NT,
	    { "NT", "ucp.parm.NT",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_NT), 0x00,
	      "Notification type.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_IVR5x,
	    { "IVR5x", "ucp.parm.IVR5x",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "UCP release number supported/accepted.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_REQ_OT,
	    { "REQ_OT", "ucp.parm.REQ_OT",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_REQ_OT), 0x00,
	      "UCP release number supported/accepted.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_SSTAT,
	    { "SSTAT", "ucp.parm.SSTAT",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_SSTAT), 0x00,
	      "Supplementary services for which status is requested.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LMN,
	    { "LMN", "ucp.parm.LMN",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Last message number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NMESS,
	    { "NMESS", "ucp.parm.NMESS",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Number of stored messages.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NMESS_str,
	    { "NMESS_str", "ucp.parm.NMESS_str",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Number of stored messages.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NPID,
	    { "NPID", "ucp.parm.NPID",
	      FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
	      "Notification PID value.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LRq,
	    { "LRq", "ucp.parm.LRq",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_LRq), 0x00,
	      "Last resort address request.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LRAd,
	    { "LRAd", "ucp.parm.LRAd",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Last resort address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LPID,
	    { "LPID", "ucp.parm.LPID",
	      FT_UINT16, BASE_DEC, VALS(vals_parm_PID), 0x00,
	      "Last resort PID value.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_DD,
	    { "DD", "ucp.parm.DD",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_DD), 0x00,
	      "Deferred delivery requested.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_DDT,
	    { "DDT", "ucp.parm.DDT",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Deferred delivery time.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_STx,
	    { "STx", "ucp.parm.STx",
	      FT_NONE, BASE_NONE, NULL, 0x00,
	      "Standard text.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_ST,
	    { "ST", "ucp.parm.ST",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Start time.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_SP,
	    { "SP", "ucp.parm.SP",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Stop time.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_VP,
	    { "VP", "ucp.parm.VP",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Validity period.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RPID,
	    { "RPID", "ucp.parm.RPID",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Replace PID",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_SCTS,
	    { "SCTS", "ucp.parm.SCTS",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Service Centre timestamp.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_Dst,
	    { "Dst", "ucp.parm.Dst",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_Dst), 0x00,
	      "Delivery status.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_Rsn,
	    { "Rsn", "ucp.parm.Rsn",
	      FT_UINT16, BASE_DEC, VALS(vals_parm_Rsn), 0x00,
	      "Reason code.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_DSCTS,
	    { "DSCTS", "ucp.parm.DSCTS",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Delivery timestamp.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_MT,
	    { "MT", "ucp.parm.MT",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_MT), 0x00,
	      "Message type.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NB,
	    { "  NB", "ucp.parm.NB",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "No. of bits in Transparent Data (TD) message.",
	      HFILL
	    }
	},
	{ &hf_ucp_data_section,
	    { "  Data", "ucp.message",
	      FT_NONE, BASE_NONE, NULL, 0x00,
	      "The actual message or data.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_MMS,
	    { "MMS", "ucp.parm.MMS",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "More messages to send.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_DCs,
	    { "DCs", "ucp.parm.DCs",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_DCs), 0x00,
	      "Data coding scheme (deprecated).",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_MCLs,
	    { "MCLs", "ucp.parm.MCLs",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_MCLs), 0x00,
	      "Message class.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RPI,
	    { "RPI", "ucp.parm.RPI",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_RPI), 0x00,
	      "Reply path.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_CPg,
	    { "CPg", "ucp.parm.CPg",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for Code Page.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RPLy,
	    { "RPLy", "ucp.parm.RPLy",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for Reply type.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_OTOA,
	    { "OTOA", "ucp.parm.OTOA",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Originator Type Of Address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_HPLMN,
	    { "HPLMN", "ucp.parm.HPLMN",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Home PLMN address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_XSer,
	    { "Extra services:", "ucp.parm.XSer",
	      FT_NONE, BASE_DEC, NULL, 0x00,
	      "Extra services.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RES4,
	    { "RES4", "ucp.parm.RES4",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for future use.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RES5,
	    { "RES5", "ucp.parm.RES5",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for future use.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_OTON,
	    { "OTON", "ucp.parm.OTON",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_OTON), 0x00,
	      "Originator type of number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_ONPI,
	    { "ONPI", "ucp.parm.ONPI",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_ONPI), 0x00,
	      "Originator numbering plan id.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_STYP0,
	    { "STYP0", "ucp.parm.STYP0",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_STYP0), 0x00,
	      "Subtype of operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_STYP1,
	    { "STYP1", "ucp.parm.STYP1",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_STYP1), 0x00,
	      "Subtype of operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_PWD,
	    { "PWD", "ucp.parm.PWD",
	      FT_NONE, BASE_DEC, NULL, 0x00,
	      "Current password.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_NPWD,
	    { "NPWD", "ucp.parm.NPWD",
	      FT_NONE, BASE_DEC, NULL, 0x00,
	      "New password.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_VERS,
	    { "VERS", "ucp.parm.VERS",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Version number.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LAdC,
	    { "LAdC", "ucp.parm.LAdC",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Address for VSMSC list operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LTON,
	    { "LTON", "ucp.parm.LTON",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Type of number list address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_LNPI,
	    { "LNPI", "ucp.parm.LNPI",
	      FT_UINT8, BASE_DEC, NULL, 0x00,
	      "Numbering plan id. list address.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_OPID,
	    { "OPID", "ucp.parm.OPID",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_OPID), 0x00,
	      "Originator protocol identifier.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RES1,
	    { "RES1", "ucp.parm.RES1",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for future use.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_RES2,
	    { "RES2", "ucp.parm.RES2",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "Reserved for future use.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_ACK,
	    { "(N)Ack", "ucp.parm.ACK",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_ACK), 0x00,
	      "Positive or negative acknowledge of the operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_MVP,
	    { "MVP", "ucp.parm.MVP",
	      FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x00,
	      "Mofified validity period.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_EC,
	    { "Error code", "ucp.parm.EC",
	      FT_UINT8, BASE_DEC, VALS(vals_parm_EC), 0x00,
	      "The result of the requested operation.",
	      HFILL
	    }
	},
	{ &hf_ucp_parm_SM,
	    { "SM", "ucp.parm.SM",
	      FT_STRING, BASE_NONE, NULL, 0x00,
	      "System message.",
	      HFILL
	    }
	},
	{ &hf_xser_service,
	    { "Type of service", "ucp.xser.service",
	      FT_UINT8, BASE_HEX, VALS(vals_xser_service), 0x00,
	      "The type of service specified.",
	      HFILL
	    }
	},
    };
    /* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_ucp,
	&ett_XSer
    };
    /* Register the protocol name and description */
    proto_ucp = proto_register_protocol("Universal Computer Protocol",
					"UCP", "ucp");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_ucp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

/*
 * If dissector uses sub-dissector registration add a registration routine.
 * This format is required because a script is used to find these routines and
 * create the code that calls these routines.
 */
void
proto_reg_handoff_ucp(void)
{
    dissector_handle_t ucp_handle;

    /*
     * UCP can be spoken on any port so, when not on a specific port, try this
     * one whenever TCP is spoken.
     */
    heur_dissector_add("tcp", dissect_ucp_heur, proto_ucp);

    /*
     * Also register as one that can be selected by a TCP port number.
     */
    ucp_handle = create_dissector_handle(dissect_ucp, proto_ucp);
    dissector_add_handle("tcp.port", ucp_handle);
}
