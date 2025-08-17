#include "eaf1-helpers.h"

#include <epan/conversation.h>

#include "F1Telemetry.h"

static const char *lookup_driver_name(int proto, uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index)
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
