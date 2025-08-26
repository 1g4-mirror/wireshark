/* eaf1-helpers.cc
 *
 * Copyright 2025, Andy Hawkins <andy@gently.org.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "eaf1-helpers.h"

#include <epan/conversation.h>

#include "F1Telemetry.h"

const char *lookup_driver_name(int proto, uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index)
{
	const char *ret = NULL;

	if (vehicle_index != 255)
	{
		auto conversation = find_conversation(packet_number, &src_addr, NULL, CONVERSATION_UDP, src_port, 0, NO_ADDR_B | NO_PORT_B);
		if (conversation)
		{
			F125::PacketParticipantsData *Participants = (F125::PacketParticipantsData *)conversation_get_proto_data(conversation, proto);
			if (Participants)
			{
				ret = Participants->m_participants[vehicle_index].m_name;
			}
		}
	}

	return ret;
}

proto_item *add_vehicle_index_and_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	uint32_t vehicle_index;
	auto ti_vehicle_index = proto_tree_add_item_ret_uint(tree, header_field, tvb, offset, sizeof(uint8), ENC_LITTLE_ENDIAN, &vehicle_index);

	const char *driver_name = lookup_driver_name(proto, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index);
	if (driver_name)
	{
		proto_item_append_text(ti_vehicle_index, " (%s)", driver_name);
	}

	return ti_vehicle_index;
}

proto_item *add_driver_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, uint8_t participant_index)
{
	auto ti_driver_name = proto_tree_add_item(tree, header_field, tvb, 0, 0, ENC_UTF_8);

	const char *driver_name = lookup_driver_name(proto, pinfo->num, pinfo->src, pinfo->srcport, participant_index);
	if (driver_name)
	{
		proto_item_set_text(ti_driver_name, "%d - '%s'", participant_index, driver_name);
	}

	return ti_driver_name;
}

void add_sector_time(proto_tree *tree, int header_field_time, int header_field_timems, int header_field_timemin, int ett, packet_info *pinfo, tvbuff_t *tvb, int msoffset, int minoffset)
{
	uint8 mins = tvb_get_uint8(tvb, minoffset);
	uint16 ms = tvb_get_uint16(tvb, msoffset, ENC_LITTLE_ENDIAN);

	auto sector_ti = proto_tree_add_string(tree,
										   header_field_time,
										   tvb,
										   msoffset,
										   sizeof(F125::LapHistoryData::m_sector1TimeMSPart) + sizeof(F125::LapHistoryData::m_sector1TimeMinutesPart),
										   wmem_strdup_printf(pinfo->pool, "%01d:%02d.%03d",
															  mins,
															  ms / 1000,
															  ms % 1000));
	auto sector_tree = proto_item_add_subtree(sector_ti, ett);

	proto_tree_add_item(sector_tree, header_field_timems, tvb, msoffset, sizeof(F125::LapHistoryData::m_sector1TimeMSPart), ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sector_tree, header_field_timemin, tvb, minoffset, sizeof(F125::LapHistoryData::m_sector1TimeMinutesPart), ENC_LITTLE_ENDIAN);
}
