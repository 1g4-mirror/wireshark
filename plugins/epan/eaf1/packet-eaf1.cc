#include "config.h"

#define WS_LOG_DOMAIN "adheaf1"

#include <epan/conversation.h>
#include <epan/packet.h>

#include "F1Telemetry.h"

#define EAF1_PORT 20777

static int proto_eaf1;
static dissector_handle_t eaf1_handle;

static dissector_table_t eaf1_packet_format_dissector_table;
static dissector_table_t eaf1_f125_packet_id_dissector_table;

static int hf_eaf1_packet_format;
static int hf_eaf1_game_year;
static int hf_eaf1_game_version;
static int hf_eaf1_proto_version;
static int hf_eaf1_game_major_version;
static int hf_eaf1_game_minor_version;
static int hf_eaf1_packet_version;
static int hf_eaf1_packet_id;
static int hf_eaf1_session_uid;
static int hf_eaf1_session_time;
static int hf_eaf1_frame_identifier;
static int hf_eaf1_overall_frame_identifier;
static int hf_eaf1_player_car_index;
static int hf_eaf1_secondary_player_car_index;

static int hf_eaf1_lobby_info_num_players;
static int hf_eaf1_lobby_info_ai_controlled;
static int hf_eaf1_lobby_info_team_id;
static int hf_eaf1_lobby_info_player_name;
static int hf_eaf1_lobby_info_nationality;
static int hf_eaf1_lobby_info_platform;
static int hf_eaf1_lobby_info_car_number;
static int hf_eaf1_lobby_info_your_telemetry;
static int hf_eaf1_lobby_info_show_online_names;
static int hf_eaf1_lobby_info_tech_level;
static int hf_eaf1_lobby_info_ready_status;

static int hf_eaf1_event_code;
static int hf_eaf1_event_button_status;
static int hf_eaf1_event_safetycar_type;
static int hf_eaf1_event_safetycar_eventtype;
static int hf_eaf1_event_fastestlap_vehicleindex;
static int hf_eaf1_event_fastestlap_laptime;
static int hf_eaf1_event_retirement_vehicleindex;
static int hf_eaf1_event_retirement_reason;
static int hf_eaf1_event_drsdisabled_reason;
static int hf_eaf1_event_teammateinpits_vehicleindex;
static int hf_eaf1_event_racewinner_vehicleindex;
static int hf_eaf1_event_overtake_overtakingvehicleindex;
static int hf_eaf1_event_overtake_overtakenvehicleindex;

static int hf_eaf1_participants_activecars;

static int ett_eaf1;
static int ett_eaf1_version;
static int ett_eaf1_packetid;
static int ett_eaf1_lobbyinfo_numplayers;
static int ett_eaf1_lobbyinfo_player_name;
static int ett_eaf1_event_eventcode;

static int dissect_eaf1_2025_lobbyinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);
static int dissect_eaf1_2025_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);
static int dissect_eaf1_2025_participants(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);

static const char *lookup_driver_name(uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index)
{
	const char *ret = NULL;

	auto conversation = find_conversation(packet_number, &src_addr, NULL, CONVERSATION_UDP, src_port, 0, NO_ADDR_B | NO_PORT_B);
	if (conversation)
	{
		F125::PacketParticipantsData *Participants = (F125::PacketParticipantsData *)conversation_get_proto_data(conversation, proto_eaf1);
		if (Participants)
		{
			ret = Participants->m_participants[vehicle_index].m_name;
		}
	}

	return ret;
}

static void add_vehicle_index_and_name(proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	uint32_t vehicle_index;
	auto ti_vehicle_index = proto_tree_add_item_ret_uint(tree, header_field, tvb, offset, sizeof(uint8), ENC_LITTLE_ENDIAN, &vehicle_index);

	const char *driver_name = lookup_driver_name(pinfo->num, pinfo->src, pinfo->srcport, vehicle_index);
	if (driver_name)
	{
		proto_item_append_text(ti_vehicle_index, " (%s)", driver_name);
	}
}

static int dissect_eaf1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAF1");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_eaf1, tvb, 0, -1, ENC_NA);
	proto_tree *eaf1_tree = proto_item_add_subtree(ti, ett_eaf1);
	uint32_t eaf1_packet_format;
	proto_tree_add_item_ret_uint(eaf1_tree, hf_eaf1_packet_format, tvb, offsetof(F124::PacketHeader, m_packetFormat), 2, ENC_LITTLE_ENDIAN, &eaf1_packet_format);
	proto_tree_add_item(eaf1_tree, hf_eaf1_game_year, tvb, offsetof(F124::PacketHeader, m_gameYear), 1, ENC_LITTLE_ENDIAN);

	proto_item *ti_version = proto_tree_add_string(eaf1_tree, hf_eaf1_game_version, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "%d.%d", tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_gameMajorVersion)), tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_gameMinorVersion))));
	proto_item_set_generated(ti_version);

	proto_tree *eaf1_version_tree = proto_item_add_subtree(ti_version, ett_eaf1_version);
	proto_tree_add_item(eaf1_version_tree, hf_eaf1_game_major_version, tvb, offsetof(F124::PacketHeader, m_gameMajorVersion), 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_version_tree, hf_eaf1_game_minor_version, tvb, offsetof(F124::PacketHeader, m_gameMinorVersion), 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(eaf1_tree, hf_eaf1_packet_version, tvb, offsetof(F124::PacketHeader, m_packetVersion), 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_session_uid, tvb, offsetof(F124::PacketHeader, m_sessionUID), 8, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_session_time, tvb, offsetof(F124::PacketHeader, m_sessionTime), 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_frame_identifier, tvb, offsetof(F124::PacketHeader, m_frameIdentifier), 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_overall_frame_identifier, tvb, offsetof(F124::PacketHeader, m_overallFrameIdentifier), 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_player_car_index, tvb, offsetof(F124::PacketHeader, m_playerCarIndex), 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(eaf1_tree, hf_eaf1_secondary_player_car_index, tvb, offsetof(F124::PacketHeader, m_secondaryPlayerCarIndex), 1, ENC_LITTLE_ENDIAN);
	proto_item *packetid_ti = proto_tree_add_item(eaf1_tree, hf_eaf1_packet_id, tvb, offsetof(F124::PacketHeader, m_packetId), 1, ENC_LITTLE_ENDIAN);
	proto_tree *eaf1_packetid_tree = proto_item_add_subtree(packetid_ti, ett_eaf1_packetid);

	if (!dissector_try_uint_new(eaf1_packet_format_dissector_table,
								eaf1_packet_format, tvb, pinfo, eaf1_packetid_tree,
								false, eaf1_packetid_tree))
	{
		call_data_dissector(tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 23");

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2024(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 24");

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 25");
	col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "%d", tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_packetId))));

	uint8_t eaf1_packet_id = tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_packetId));

	if (!dissector_try_uint_new(eaf1_f125_packet_id_dissector_table,
								eaf1_packet_id, tvb, pinfo, tree,
								false, tree))
	{
		call_data_dissector(tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_lobbyinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketLobbyInfoData))
	{
		F125::PacketLobbyInfoData *LobbyInfo = (F125::PacketLobbyInfoData *)tvb_memdup(pinfo->pool, tvb, 0, sizeof(F125::PacketLobbyInfoData));

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "LobbyInfo: %d players", LobbyInfo->m_numPlayers));

		auto num_players_ti = proto_tree_add_item(tree, hf_eaf1_lobby_info_num_players, tvb, offsetof(F125::PacketLobbyInfoData, m_numPlayers), 1, ENC_LITTLE_ENDIAN);

		proto_tree *eaf1_num_players_tree = proto_item_add_subtree(num_players_ti, ett_eaf1_lobbyinfo_numplayers);

		for (int count = 0; count < LobbyInfo->m_numPlayers; count++)
		{
			auto base_offset = offsetof(F125::PacketLobbyInfoData, m_lobbyPlayers) + count * sizeof(F125::LobbyInfoData);

			auto player_name_ti = proto_tree_add_item(eaf1_num_players_tree, hf_eaf1_lobby_info_player_name, tvb, base_offset + offsetof(F125::LobbyInfoData, m_name), F125::cs_maxParticipantNameLen, ENC_UTF_8);
			proto_tree *eaf1_player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_lobbyinfo_player_name);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_ai_controlled, tvb, base_offset + offsetof(F125::LobbyInfoData, m_aiControlled), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_team_id, tvb, base_offset + offsetof(F125::LobbyInfoData, m_teamId), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_nationality, tvb, base_offset + offsetof(F125::LobbyInfoData, m_nationality), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_platform, tvb, base_offset + offsetof(F125::LobbyInfoData, m_platform), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_car_number, tvb, base_offset + offsetof(F125::LobbyInfoData, m_carNumber), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_your_telemetry, tvb, base_offset + offsetof(F125::LobbyInfoData, m_yourTelemetry), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_show_online_names, tvb, base_offset + offsetof(F125::LobbyInfoData, m_showOnlineNames), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_tech_level, tvb, base_offset + offsetof(F125::LobbyInfoData, m_techLevel), sizeof(uint16), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_ready_status, tvb, base_offset + offsetof(F125::LobbyInfoData, m_readyStatus), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketEventData))
	{
		F125::PacketEventData *Event = (F125::PacketEventData *)tvb_memdup(pinfo->pool, tvb, 0, sizeof(F125::PacketEventData));

		const char *EventCode;

		auto event_code_ti = proto_tree_add_item_ret_string(tree, hf_eaf1_event_code, tvb, offsetof(F125::PacketEventData, m_eventStringCode), F125::cs_eventStringCodeLen, ENC_UTF_8, pinfo->pool, (const uint8_t **)&EventCode);
		proto_tree *eaf1_event_code_tree = proto_item_add_subtree(event_code_ti, ett_eaf1_event_eventcode);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Event: %s", EventCode));

		if (0 == strcmp(EventCode, F125::PacketEventData::cs_sessionStartedEventCode))
		{
			proto_item_set_text(event_code_ti, "Session start");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_sessionEndedEventCode))
		{
			proto_item_set_text(event_code_ti, "Session end");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_fastestLapEventCode))
		{
			proto_item_set_text(event_code_ti, "Fastest lap");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_fastestlap_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.FastestLap.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_fastestlap_laptime, tvb, offsetof(F125::PacketEventData, m_eventDetails.FastestLap.lapTime), sizeof(float), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_retirementEventCode))
		{
			proto_item_set_text(event_code_ti, "Retirement");

			uint32_t vehicle_index;

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_retirement_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Retirement.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_retirement_reason, tvb, offsetof(F125::PacketEventData, m_eventDetails.Retirement.reason), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_drsEnabledEventCode))
		{
			proto_item_set_text(event_code_ti, "DRS Enabled");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_drsDisabledEventCode))
		{
			proto_item_set_text(event_code_ti, "DRS Disabled");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_drsdisabled_reason, tvb, offsetof(F125::PacketEventData, m_eventDetails.DRSDisabled.reason), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_teamMateInPitsEventCode))
		{
			proto_item_set_text(event_code_ti, "Teammate in pits");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_teammateinpits_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.TeamMateInPits.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_chequeredFlagEventCode))
		{
			proto_item_set_text(event_code_ti, "Chequered flag");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_raceWinnerEventCode))
		{
			proto_item_set_text(event_code_ti, "Race winner");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_racewinner_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.RaceWinner.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_penaltyEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_speedTrapEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_startLightsEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_lightsOutEventCode))
		{
			proto_item_set_text(event_code_ti, "Lights out");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_driveThroughServedEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_stopGoServedEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_flashbackEventCode))
		{
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_buttonStatusEventCode))
		{
			proto_item_set_text(event_code_ti, "Button");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_button_status, tvb, offsetof(F125::PacketEventData, m_eventDetails.Buttons.buttonStatus), sizeof(uint32), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_redFlagEventCode))
		{
			proto_item_set_text(event_code_ti, "Red flag");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_overtakeEventCode))
		{
			proto_item_set_text(event_code_ti, "Overtake");

			uint32_t overtaking_vehicle_index;
			uint32_t overtaken_vehicle_index;

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_overtake_overtakingvehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Overtake.overtakingVehicleIdx));
			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_overtake_overtakenvehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Overtake.beingOvertakenVehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_safetyCarEventCode))
		{
			proto_item_set_text(event_code_ti, "Safety car");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_safetycar_type, tvb, offsetof(F125::PacketEventData, m_eventDetails.SafetyCar.safetyCarType), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_safetycar_eventtype, tvb, offsetof(F125::PacketEventData, m_eventDetails.SafetyCar.eventType), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_collisionEventCode))
		{
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_participants(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketParticipantsData))
	{
		F125::PacketEventData *Event = (F125::PacketEventData *)tvb_memdup(pinfo->pool, tvb, 0, sizeof(F125::PacketEventData));

		uint32_t active_cars;

		proto_tree_add_item_ret_uint(tree, hf_eaf1_participants_activecars, tvb, offsetof(F125::PacketParticipantsData, m_numActiveCars), 1, ENC_LITTLE_ENDIAN, &active_cars);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Participants: %d active", active_cars));

		if (!PINFO_FD_VISITED(pinfo))
		{
			auto conversation = conversation_new(pinfo->num, &pinfo->src,
												 NULL, CONVERSATION_UDP, pinfo->srcport,
												 0, NO_ADDR2 | NO_PORT2);

			if (conversation)
			{
				conversation_add_proto_data(conversation, proto_eaf1, tvb_memdup(wmem_file_scope(), tvb, 0, tvb_captured_length(tvb)));
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

extern "C"
{
	void proto_register_eaf1(void)
	{
		static const value_string packetidnames[] = {
			{0, "Motion"},
			{1, "Session"},
			{2, "LapData"},
			{3, "Event"},
			{4, "Participants"},
			{5, "CarSetups"},
			{6, "CarTelemetry"},
			{7, "CarStatus"},
			{8, "FinalClassification"},
			{9, "LobbyInfo"},
			{10, "CarDamage"},
			{11, "SessionHistory"},
			{12, "TyreSets"},
			{13, "MotionEx"},
			{14, "TimeTrial"},
			{15, "LapPositions"},
			{0, NULL},
		};

		static const value_string teamidnames[] = {
			{0, "Mercedes"},
			{1, "Ferrari"},
			{2, "Red Bull Racing"},
			{3, "Williams"},
			{4, "Aston Martin"},
			{5, "Alpine"},
			{6, "RB"},
			{7, "Haas"},
			{8, "McLaren"},
			{9, "Sauber"},
			{41, "F1 Generic"},
			{104, "F1 Custom Team"},
			{143, "Art GP '23"},
			{144, "Campos '23"},
			{145, "Carlin '23"},
			{146, "PHM '23"},
			{147, "Dams '23"},
			{148, "Hitech '23"},
			{149, "MP Motorsport '23"},
			{150, "Prema '23"},
			{151, "Trident '23"},
			{152, "Van Amersfoort Racing '23"},
			{153, "Virtuosi '23"},
			{0, NULL},
		};

		static const value_string nationalityidnames[] = {
			{0, "Not set"},
			{1, "American"},
			{2, "Argentinean"},
			{3, "Australian"},
			{4, "Austrian"},
			{5, "Azerbaijani"},
			{6, "Bahraini"},
			{7, "Belgian"},
			{8, "Bolivian"},
			{9, "Brazilian"},
			{10, "British"},
			{11, "Bulgarian"},
			{12, "Cameroonian"},
			{13, "Canadian"},
			{14, "Chilean"},
			{15, "Chinese"},
			{16, "Colombian"},
			{17, "Costa Rican"},
			{18, "Croatian"},
			{19, "Cypriot"},
			{20, "Czech"},
			{21, "Danish"},
			{22, "Dutch"},
			{23, "Ecuadorian"},
			{24, "English"},
			{25, "Emirian"},
			{26, "Estonian"},
			{27, "Finnish"},
			{28, "French"},
			{29, "German"},
			{30, "Ghanaian"},
			{31, "Greek"},
			{32, "Guatemalan"},
			{33, "Honduran"},
			{34, "Hong Konger"},
			{35, "Hungarian"},
			{36, "Icelander"},
			{37, "Indian"},
			{38, "Indonesian"},
			{39, "Irish"},
			{40, "Israeli"},
			{41, "Italian"},
			{42, "Jamaican"},
			{43, "Japanese"},
			{44, "Jordanian"},
			{45, "Kuwaiti"},
			{46, "Latvian"},
			{47, "Lebanese"},
			{48, "Lithuanian"},
			{49, "Luxembourger"},
			{50, "Malaysian"},
			{51, "Maltese"},
			{52, "Mexican"},
			{53, "Monegasque"},
			{54, "New Zealander"},
			{55, "Nicaraguan"},
			{56, "Northern Irish"},
			{57, "Norwegian"},
			{58, "Omani"},
			{59, "Pakistani"},
			{60, "Panamanian"},
			{61, "Paraguayan"},
			{62, "Peruvian"},
			{63, "Polish"},
			{64, "Portuguese"},
			{65, "Qatari"},
			{66, "Romanian"},
			{68, "Salvadoran"},
			{69, "Saudi"},
			{70, "Scottish"},
			{71, "Serbian"},
			{72, "Singaporean"},
			{73, "Slovakian"},
			{74, "Slovenian"},
			{75, "South Korean"},
			{76, "South African"},
			{77, "Spanish"},
			{78, "Swedish"},
			{79, "Swiss"},
			{80, "Thai"},
			{81, "Turkish"},
			{82, "Uruguayan"},
			{83, "Ukrainian"},
			{84, "Venezuelan"},
			{85, "Barbadian"},
			{86, "Welsh"},
			{87, "Vietnamese"},
			{88, "Algerian"},
			{89, "Bosnian"},
			{90, "Filipino"},
			{0, NULL},
		};

		static const value_string platformidnames[] = {
			{1, "Steam"},
			{3, "PlayStation"},
			{4, "Xbox"},
			{6, "Origin"},
			{255, "unknown"},
			{0, NULL},
		};

		static const value_string yourtelemetrynames[] = {
			{0, "Restricted"},
			{1, "Public"},
			{0, NULL},
		};

		static const value_string showonlinenames[] = {
			{0, "Off"},
			{1, "On"},
			{0, NULL},
		};

		static const value_string readystatusnames[] = {
			{0, "Not ready"},
			{1, "Ready"},
			{2, "Spectating"},
			{0, NULL},
		};

		static const value_string safetycartypenames[] = {
			{0, "No Safety Car"},
			{1, "Full Safety Car"},
			{2, "Virtual Safety Car"},
			{3, "Formation Lap Safety Car"},
		};

		static const value_string safetycareventtypenames[] = {
			{0, "Deployed"},
			{1, "Returning"},
			{2, "Returned"},
			{3, "Resume Race"},
		};

		static const value_string retirementreasonnames[] = {
			{0, "Invalid"},
			{1, "Retired"},
			{2, "Finished"},
			{3, "Terminal damage"},
			{4, "Inactive"},
			{5, "Not enough laps completed"},
			{6, "Black flagged"},
			{7, "Red flagged"},
			{8, "Mechanical failure"},
			{9, "Session skipped"},
			{10, "Session simulated"},
		};

		static const value_string drsdisabledreasonnames[] = {
			{0, "Wet track"},
			{1, "Safety car deployed"},
			{2, "Red flag"},
			{3, "Min lap not reached"},
		};

		static hf_register_info hf[] = {
			// Header

			{
				&hf_eaf1_packet_format,
				{
					"Packet Format",
					"eaf1.packetformat",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					"Packet format",
					HFILL,
				},
			},
			{
				&hf_eaf1_game_year,
				{
					"Game Year",
					"eaf1.gameyear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Game year",
					HFILL,
				},
			},
			{
				&hf_eaf1_game_version,
				{
					"Game Version",
					"eaf1.gameversion",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					"Game version",
					HFILL,
				},
			},
			{
				&hf_eaf1_proto_version,
				{
					"Proto Version",
					"eaf1.protoversion",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					"Protoversion",
					HFILL,
				},
			},
			{
				&hf_eaf1_game_major_version,
				{
					"Game Major Version",
					"eaf1.gamemajorversion",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Game major version",
					HFILL,
				},
			},
			{
				&hf_eaf1_game_minor_version,
				{
					"Game Minor Version",
					"eaf1.gameminorversion",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Game minor version",
					HFILL,
				},
			},
			{
				&hf_eaf1_packet_version,
				{
					"Packet Version",
					"eaf1.packetversion",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Packet version",
					HFILL,
				},
			},
			{
				&hf_eaf1_packet_id,
				{
					"Packet ID",
					"eaf1.packetid",
					FT_UINT8,
					BASE_DEC,
					VALS(packetidnames),
					0x0,
					"Packet ID",
					HFILL,
				},
			},
			{
				&hf_eaf1_session_uid,
				{
					"Session UID",
					"eaf1.sessionuid",
					FT_UINT64,
					BASE_DEC,
					NULL,
					0x0,
					"Session UID",
					HFILL,
				},
			},
			{
				&hf_eaf1_session_time,
				{
					"Session Time",
					"eaf1.sessiontime",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Session time",
					HFILL,
				},
			},
			{
				&hf_eaf1_frame_identifier,
				{
					"Frame Identifier",
					"eaf1.frameidentifier",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					"Frame identifier",
					HFILL,
				},
			},
			{
				&hf_eaf1_overall_frame_identifier,
				{
					"Overall Frame Identifier",
					"eaf1.overallframeidentifier",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					"Overall frame identifier",
					HFILL,
				},
			},
			{
				&hf_eaf1_player_car_index,
				{
					"Player Car Index",
					"eaf1.playercarindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Player car index",
					HFILL,
				},
			},
			{
				&hf_eaf1_secondary_player_car_index,
				{
					"Secondary Player Car Index",
					"eaf1.secondaryplayercarindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Secondary player car index",
					HFILL,
				},
			},

			// Lobbyinfo packet

			{
				&hf_eaf1_lobby_info_num_players,
				{
					"Number of players",
					"eaf1.lobbyinfo.numplayers",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Number of players",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_player_name,
				{
					"Player name",
					"eaf1.lobbyinfo.playername",
					FT_STRINGZ,
					BASE_NONE,
					NULL,
					0x0,
					"Player name",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_ai_controlled,
				{
					"AI Controlled",
					"eaf1.lobbyinfo.playeraicontrolled",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Player AI controlled",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_team_id,
				{
					"Team ID",
					"eaf1.lobbyinfo.playerteamid",
					FT_UINT8,
					BASE_DEC,
					VALS(teamidnames),
					0x0,
					"Player team ID",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_nationality,
				{
					"Nationality ID",
					"eaf1.lobbyinfo.playernationalityid",
					FT_UINT8,
					BASE_DEC,
					VALS(nationalityidnames),
					0x0,
					"Player nationality ID",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_platform,
				{
					"Platform ID",
					"eaf1.lobbyinfo.playerplatformid",
					FT_UINT8,
					BASE_DEC,
					VALS(platformidnames),
					0x0,
					"Player platform ID",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_car_number,
				{
					"Car number",
					"eaf1.lobbyinfo.playercarnumber",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Player car number",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_your_telemetry,
				{
					"Your telemetry",
					"eaf1.lobbyinfo.playeryourtelemetry",
					FT_UINT8,
					BASE_DEC,
					VALS(yourtelemetrynames),
					0x0,
					"Player your telemetry",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_show_online_names,
				{
					"Show online names",
					"eaf1.lobbyinfo.playershowonlinenames",
					FT_UINT8,
					BASE_DEC,
					VALS(showonlinenames),
					0x0,
					"Player show online names",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_tech_level,
				{
					"Tech level",
					"eaf1.lobbyinfo.playershowonlinenames",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					"Player tech level",
					HFILL,
				},
			},

			{
				&hf_eaf1_lobby_info_ready_status,
				{
					"Ready status",
					"eaf1.lobbyinfo.playerreadystatus",
					FT_UINT8,
					BASE_DEC,
					VALS(readystatusnames),
					0x0,
					"Player ready status",
					HFILL,
				},
			},

			// Event packet

			{
				&hf_eaf1_event_code,
				{
					"Event code",
					"eaf1.event.code",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					"Event code",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status,
				{
					"Event button status",
					"eaf1.event.buttonstatus",
					FT_UINT32,
					BASE_HEX,
					NULL,
					0x0,
					"Event button status",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_safetycar_type,
				{
					"Event safety car type",
					"eaf1.event.safetycar.type",
					FT_UINT8,
					BASE_DEC,
					VALS(safetycartypenames),
					0x0,
					"Event safety car type",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_safetycar_eventtype,
				{
					"Event safety car event type",
					"eaf1.event.safetycar.eventtype",
					FT_UINT8,
					BASE_DEC,
					VALS(safetycareventtypenames),
					0x0,
					"Event safety car event type",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_fastestlap_vehicleindex,
				{
					"Event fastest lap vehicle index",
					"eaf1.event.fastestlap.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event fastest lap vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_fastestlap_laptime,
				{
					"Event fastest lap laptime",
					"eaf1.event.fastestlap.laptime",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Event fastest lap laptime",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_retirement_vehicleindex,
				{
					"Event retirement vehicle index",
					"eaf1.event.retirement.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event retirement vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_retirement_reason,
				{
					"Event retirement reason",
					"eaf1.event.retirement.reason",
					FT_UINT8,
					BASE_DEC,
					VALS(retirementreasonnames),
					0x0,
					"Event retirement reason",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_drsdisabled_reason,
				{
					"Event DRS disabled reason",
					"eaf1.event.drsdisabled.reason",
					FT_UINT8,
					BASE_DEC,
					VALS(drsdisabledreasonnames),
					0x0,
					"Event DRS disabled reason",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_teammateinpits_vehicleindex,
				{
					"Event team mate in pits index",
					"eaf1.event.teammateinpits.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event team mate in pits vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_racewinner_vehicleindex,
				{
					"Event race winner index",
					"eaf1.event.racewinner.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event race winner vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_overtake_overtakingvehicleindex,
				{
					"Event overtake overtaking vehicle index",
					"eaf1.event.overtake.overtakingvehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event overtake overtaking vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_overtake_overtakenvehicleindex,
				{
					"Event overtake overtaken vehicle index",
					"eaf1.event.overtake.overtakenvehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event overtake overtaken vehicle index",
					HFILL,
				},
			},

			// Participants packet

			{
				&hf_eaf1_participants_activecars,
				{
					"Participants num active cars",
					"eaf1.participants.numactivecars",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Participants num active cars",
					HFILL,
				},
			},
		};

		/* Setup protocol subtree array */
		static int *ett[] =
			{
				&ett_eaf1,
				&ett_eaf1_version,
				&ett_eaf1_packetid,
				&ett_eaf1_lobbyinfo_numplayers,
				&ett_eaf1_lobbyinfo_player_name,
				&ett_eaf1_event_eventcode,
			};

		proto_eaf1 = proto_register_protocol(
			"EASports F1 Telemetry", /* protocol name        */
			"EAF1",					 /* protocol short name  */
			"eaf1"					 /* protocol filter_name */
		);

		proto_register_field_array(proto_eaf1, hf, array_length(hf));
		proto_register_subtree_array(ett, array_length(ett));

		eaf1_handle = register_dissector_with_description(
			"eaf1",			 /* dissector name           */
			"EAF1 Protocol", /* dissector description    */
			dissect_eaf1,	 /* dissector function       */
			proto_eaf1		 /* protocol being dissected */
		);

		eaf1_packet_format_dissector_table = register_dissector_table("eaf1.packetformat",
																	  "EAf1 Packet Format",
																	  proto_eaf1, FT_UINT16,
																	  BASE_DEC);

		eaf1_f125_packet_id_dissector_table = register_dissector_table("eaf1.f125packetid",
																	   "EAf1 F125 Packet ID",
																	   proto_eaf1, FT_UINT8,
																	   BASE_DEC);
	}

	void proto_reg_handoff_eaf1(void)
	{
		dissector_add_uint("udp.port", EAF1_PORT, eaf1_handle);

		dissector_handle_t eaf1_2023_handle, eaf1_2024_handle, eaf1_2025_handle;

		eaf1_2023_handle = create_dissector_handle(dissect_eaf1_2023, proto_eaf1);
		eaf1_2024_handle = create_dissector_handle(dissect_eaf1_2024, proto_eaf1);
		eaf1_2025_handle = create_dissector_handle(dissect_eaf1_2025, proto_eaf1);

		dissector_add_uint("eaf1.packetformat", 2023, eaf1_2023_handle);
		dissector_add_uint("eaf1.packetformat", 2024, eaf1_2024_handle);
		dissector_add_uint("eaf1.packetformat", 2025, eaf1_2025_handle);

		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdLobbyInfo, create_dissector_handle(dissect_eaf1_2025_lobbyinfo, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdEvent, create_dissector_handle(dissect_eaf1_2025_event, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdParticipants, create_dissector_handle(dissect_eaf1_2025_participants, proto_eaf1));
	}
}
