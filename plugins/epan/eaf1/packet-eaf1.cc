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
static int hf_eaf1_event_button_status_cross;
static int hf_eaf1_event_button_status_triangle;
static int hf_eaf1_event_button_status_circle;
static int hf_eaf1_event_button_status_square;
static int hf_eaf1_event_button_status_dpadleft;
static int hf_eaf1_event_button_status_dpadright;
static int hf_eaf1_event_button_status_dpadup;
static int hf_eaf1_event_button_status_dpaddown;
static int hf_eaf1_event_button_status_options;
static int hf_eaf1_event_button_status_l1;
static int hf_eaf1_event_button_status_r1;
static int hf_eaf1_event_button_status_l2;
static int hf_eaf1_event_button_status_r2;
static int hf_eaf1_event_button_status_leftstickclick;
static int hf_eaf1_event_button_status_rightstickclick;
static int hf_eaf1_event_button_status_rightstickleft;
static int hf_eaf1_event_button_status_rightstickright;
static int hf_eaf1_event_button_status_rightstickup;
static int hf_eaf1_event_button_status_rightstickdown;
static int hf_eaf1_event_button_status_special;
static int hf_eaf1_event_button_status_udp1;
static int hf_eaf1_event_button_status_udp2;
static int hf_eaf1_event_button_status_udp3;
static int hf_eaf1_event_button_status_udp4;
static int hf_eaf1_event_button_status_udp5;
static int hf_eaf1_event_button_status_udp6;
static int hf_eaf1_event_button_status_udp7;
static int hf_eaf1_event_button_status_udp8;
static int hf_eaf1_event_button_status_udp9;
static int hf_eaf1_event_button_status_udp10;
static int hf_eaf1_event_button_status_udp11;
static int hf_eaf1_event_button_status_udp12;
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
static int hf_eaf1_event_penalty_penaltytype;
static int hf_eaf1_event_penalty_infringementtype;
static int hf_eaf1_event_penalty_vehicleindex;
static int hf_eaf1_event_penalty_othervehicleindex;
static int hf_eaf1_event_penalty_time;
static int hf_eaf1_event_penalty_lapnumber;
static int hf_eaf1_event_penalty_placesgained;
static int hf_eaf1_event_speedtrap_vehicleindex;
static int hf_eaf1_event_speedtrap_speed;
static int hf_eaf1_event_speedtrap_isoverallfastestinsession;
static int hf_eaf1_event_speedtrap_isdriverfastestinsession;
static int hf_eaf1_event_speedtrap_fastestvehicleindexinsession;
static int hf_eaf1_event_speedtrap_fastestspeedinsession;
static int hf_eaf1_event_startlights_numlights;
static int hf_eaf1_event_drivethroughpenaltyserved_vehicleindex;
static int hf_eaf1_event_stopgopenaltyserved_vehicleindex;
static int hf_eaf1_event_stopgopenaltyserved_stoptime;
static int hf_eaf1_event_flashback_frameidentifier;
static int hf_eaf1_event_flashback_sessiontime;
static int hf_eaf1_event_collision_vehicle1index;
static int hf_eaf1_event_collision_vehicle2index;

static int hf_eaf1_participants_activecars;

static int ett_eaf1;
static int ett_eaf1_version;
static int ett_eaf1_packetid;
static int ett_eaf1_lobbyinfo_numplayers;
static int ett_eaf1_lobbyinfo_player_name;
static int ett_eaf1_event_eventcode;
static int ett_eaf1_event_buttonstatus;

static int dissect_eaf1_2025_lobbyinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);
static int dissect_eaf1_2025_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);
static int dissect_eaf1_2025_participants(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data);

static const char *lookup_driver_name(uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index)
{
	const char *ret = NULL;

	if (vehicle_index != 255)
	{
		auto conversation = find_conversation(packet_number, &src_addr, NULL, CONVERSATION_UDP, src_port, 0, NO_ADDR_B | NO_PORT_B);
		if (conversation)
		{
			F125::PacketParticipantsData *Participants = (F125::PacketParticipantsData *)conversation_get_proto_data(conversation, proto_eaf1);
			if (Participants)
			{
				ret = Participants->m_participants[vehicle_index].m_name;
			}
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
			proto_item_set_text(event_code_ti, "Penalty");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_penaltytype, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.penaltyType), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_infringementtype, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.infringementType), sizeof(uint8), ENC_LITTLE_ENDIAN);
			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_penalty_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.vehicleIdx));
			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_penalty_othervehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.otherVehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_time, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.time), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_lapnumber, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.lapNum), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_placesgained, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.placesGained), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_speedTrapEventCode))
		{
			proto_item_set_text(event_code_ti, "Speed trap");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_speedtrap_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_speed, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.speed), sizeof(float), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_isoverallfastestinsession, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.isOverallFastestInSession), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_isdriverfastestinsession, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.isDriverFastestInSession), sizeof(uint8), ENC_LITTLE_ENDIAN);
			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_speedtrap_fastestvehicleindexinsession, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.fastestVehicleIdxInSession));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_fastestspeedinsession, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.fastestSpeedInSession), sizeof(float), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_startLightsEventCode))
		{
			proto_item_set_text(event_code_ti, "Start lights");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_startlights_numlights, tvb, offsetof(F125::PacketEventData, m_eventDetails.StartLights.numLights), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_lightsOutEventCode))
		{
			proto_item_set_text(event_code_ti, "Lights out");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_driveThroughServedEventCode))
		{
			proto_item_set_text(event_code_ti, "Drive through penalty served");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_drivethroughpenaltyserved_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.DriveThroughPenaltyServed.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_stopGoServedEventCode))
		{
			proto_item_set_text(event_code_ti, "Stop go penalty served");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_stopgopenaltyserved_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.StopGoPenaltyServed.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_stopgopenaltyserved_stoptime, tvb, offsetof(F125::PacketEventData, m_eventDetails.StopGoPenaltyServed.stopTime), sizeof(float), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_flashbackEventCode))
		{
			proto_item_set_text(event_code_ti, "Flashback");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_flashback_frameidentifier, tvb, offsetof(F125::PacketEventData, m_eventDetails.Flashback.flashbackFrameIdentifier), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_flashback_sessiontime, tvb, offsetof(F125::PacketEventData, m_eventDetails.Flashback.flashbackSessionTime), sizeof(float), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_buttonStatusEventCode))
		{
			proto_item_set_text(event_code_ti, "Button");

			static int *const button_status_fields[] = {
				&hf_eaf1_event_button_status_cross,
				&hf_eaf1_event_button_status_triangle,
				&hf_eaf1_event_button_status_circle,
				&hf_eaf1_event_button_status_square,
				&hf_eaf1_event_button_status_dpadleft,
				&hf_eaf1_event_button_status_dpadright,
				&hf_eaf1_event_button_status_dpadup,
				&hf_eaf1_event_button_status_dpaddown,
				&hf_eaf1_event_button_status_options,
				&hf_eaf1_event_button_status_l1,
				&hf_eaf1_event_button_status_r1,
				&hf_eaf1_event_button_status_l2,
				&hf_eaf1_event_button_status_r2,
				&hf_eaf1_event_button_status_leftstickclick,
				&hf_eaf1_event_button_status_rightstickclick,
				&hf_eaf1_event_button_status_rightstickleft,
				&hf_eaf1_event_button_status_rightstickright,
				&hf_eaf1_event_button_status_rightstickup,
				&hf_eaf1_event_button_status_rightstickdown,
				&hf_eaf1_event_button_status_special,
				&hf_eaf1_event_button_status_udp1,
				&hf_eaf1_event_button_status_udp2,
				&hf_eaf1_event_button_status_udp3,
				&hf_eaf1_event_button_status_udp4,
				&hf_eaf1_event_button_status_udp5,
				&hf_eaf1_event_button_status_udp6,
				&hf_eaf1_event_button_status_udp7,
				&hf_eaf1_event_button_status_udp8,
				&hf_eaf1_event_button_status_udp9,
				&hf_eaf1_event_button_status_udp10,
				&hf_eaf1_event_button_status_udp11,
				&hf_eaf1_event_button_status_udp12,
				NULL,
			};

			// proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_button_status, tvb, offsetof(F125::PacketEventData, m_eventDetails.Buttons.buttonStatus), sizeof(uint32), ENC_LITTLE_ENDIAN);
			proto_tree_add_bitmask(eaf1_event_code_tree, tvb, offsetof(F125::PacketEventData, m_eventDetails.Buttons.buttonStatus), hf_eaf1_event_button_status,
								   ett_eaf1_event_buttonstatus, button_status_fields, ENC_LITTLE_ENDIAN);
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
			proto_item_set_text(event_code_ti, "Collision");

			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_collision_vehicle1index, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Collision.vehicle1Idx));
			add_vehicle_index_and_name(eaf1_event_code_tree, hf_eaf1_event_collision_vehicle2index, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Collision.vehicle2Idx));
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

		static const value_string penaltytypenames[] = {
			{0, "Drive through"},
			{1, "Stop Go"},
			{2, "Grid penalty"},
			{3, "Penalty reminder"},
			{4, "Time penalty"},
			{5, "Warning"},
			{6, "Disqualified"},
			{7, "Removed from formation lap"},
			{8, "Parked too long timer"},
			{9, "Tyre regulations"},
			{10, "This lap invalidated"},
			{11, "This and next lap invalidated"},
			{12, "This lap invalidated without reason"},
			{13, "This and next lap invalidated without reason"},
			{14, "This and previous lap invalidated"},
			{15, "This and previous lap invalidated without reason"},
			{16, "Retired"},
			{17, "Black flag timer"},
		};

		static const value_string infringementtypenames[] = {
			{0, "Blocking by slow driving"},
			{1, "Blocking by wrong way driving"},
			{2, "Reversing off the start line"},
			{3, "Big Collision"},
			{4, "Small Collision"},
			{5, "Collision failed to hand back position single"},
			{6, "Collision failed to hand back position multiple"},
			{7, "Corner cutting gained time"},
			{8, "Corner cutting overtake single"},
			{9, "Corner cutting overtake multiple"},
			{10, "Crossed pit exit lane"},
			{11, "Ignoring blue flags"},
			{12, "Ignoring yellow flags"},
			{13, "Ignoring drive through"},
			{14, "Too many drive throughs"},
			{15, "Drive through reminder serve within n laps"},
			{16, "Drive through reminder serve this lap"},
			{17, "Pit lane speeding"},
			{18, "Parked for too long"},
			{19, "Ignoring tyre regulations"},
			{20, "Too many penalties"},
			{21, "Multiple warnings"},
			{22, "Approaching disqualification"},
			{23, "Tyre regulations select single"},
			{24, "Tyre regulations select multiple"},
			{25, "Lap invalidated corner cutting"},
			{26, "Lap invalidated running wide"},
			{27, "Corner cutting ran wide gained time minor"},
			{28, "Corner cutting ran wide gained time significant"},
			{29, "Corner cutting ran wide gained time extreme"},
			{30, "Lap invalidated wall riding"},
			{31, "Lap invalidated flashback used"},
			{32, "Lap invalidated reset to track"},
			{33, "Blocking the pitlane"},
			{34, "Jump start"},
			{35, "Safety car to car collision"},
			{36, "Safety car illegal overtake"},
			{37, "Safety car exceeding allowed pace"},
			{38, "Virtual safety car exceeding allowed pace"},
			{39, "Formation lap below allowed speed"},
			{40, "Formation lap parking"},
			{41, "Retired mechanical failure"},
			{42, "Retired terminally damaged"},
			{43, "Safety car falling too far back"},
			{44, "Black flag timer"},
			{45, "Unserved stop go penalty"},
			{46, "Unserved drive through penalty"},
			{47, "Engine component change"},
			{48, "Gearbox change"},
			{49, "Parc Fermé change"},
			{50, "League grid penalty"},
			{51, "Retry penalty"},
			{52, "Illegal time gain"},
			{53, "Mandatory pitstop"},
			{54, "Attribute assigned"},
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
				&hf_eaf1_event_button_status_cross,
				{
					"Cross",
					"eaf1.event.buttonstatus.cross",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000001,
					"Cross",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_triangle,
				{
					"Triangle",
					"eaf1.event.buttonstatus.triangle",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000002,
					"Triangle",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_circle,
				{
					"Circle",
					"eaf1.event.buttonstatus.circle",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000004,
					"Circle",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_square,
				{
					"Square",
					"eaf1.event.buttonstatus.square",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000008,
					"Square",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_dpadleft,
				{
					"D-pad left",
					"eaf1.event.buttonstatus.dpadleft",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000010,
					"D-pad left",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_dpadright,
				{
					"D-pad right",
					"eaf1.event.buttonstatus.dpadright",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000020,
					"D-pad right",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_dpadup,
				{
					"D-pad up",
					"eaf1.event.buttonstatus.dpadup",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000040,
					"D-pad up",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_dpaddown,
				{
					"D-pad down",
					"eaf1.event.buttonstatus.dpaddown",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000080,
					"D-pad down",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_options,
				{
					"Options",
					"eaf1.event.buttonstatus.options",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000100,
					"Options",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_l1,
				{
					"L1",
					"eaf1.event.buttonstatus.l1",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000200,
					"L1",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_r1,
				{
					"R1",
					"eaf1.event.buttonstatus.r1",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000400,
					"R1",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_l2,
				{
					"L2",
					"eaf1.event.buttonstatus.l2",
					FT_BOOLEAN,
					32,
					NULL,
					0x00000800,
					"L2",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_r2,
				{
					"R2",
					"eaf1.event.buttonstatus.r2",
					FT_BOOLEAN,
					32,
					NULL,
					0x00001000,
					"R2",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_leftstickclick,
				{
					"Left stick click",
					"eaf1.event.buttonstatus.leftstickclick",
					FT_BOOLEAN,
					32,
					NULL,
					0x00002000,
					"Left stick click",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_rightstickclick,
				{
					"Right stick click",
					"eaf1.event.buttonstatus.rightstickclick",
					FT_BOOLEAN,
					32,
					NULL,
					0x00004000,
					"Right stick click",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_rightstickleft,
				{
					"Right stick left",
					"eaf1.event.buttonstatus.rightstickleft",
					FT_BOOLEAN,
					32,
					NULL,
					0x00008000,
					"Right stick left",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_rightstickright,
				{
					"Right stick right",
					"eaf1.event.buttonstatus.rightstickright",
					FT_BOOLEAN,
					32,
					NULL,
					0x00010000,
					"Right stick right",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_rightstickup,
				{
					"Right stick up",
					"eaf1.event.buttonstatus.rightstickup",
					FT_BOOLEAN,
					32,
					NULL,
					0x00020000,
					"Right stick up",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_rightstickdown,
				{
					"Right stick down",
					"eaf1.event.buttonstatus.rightstickdown",
					FT_BOOLEAN,
					32,
					NULL,
					0x00040000,
					"Right stick down",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_special,
				{
					"Special",
					"eaf1.event.buttonstatus.special",
					FT_BOOLEAN,
					32,
					NULL,
					0x00080000,
					"Special",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp1,
				{
					"UDP 1",
					"eaf1.event.buttonstatus.udp1",
					FT_BOOLEAN,
					32,
					NULL,
					0x00100000,
					"UDP 1",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp2,
				{
					"UDP 2",
					"eaf1.event.buttonstatus.udp2",
					FT_BOOLEAN,
					32,
					NULL,
					0x00200000,
					"UDP 2",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp3,
				{
					"UDP 3",
					"eaf1.event.buttonstatus.udp3",
					FT_BOOLEAN,
					32,
					NULL,
					0x00400000,
					"UDP 3",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp4,
				{
					"UDP 4",
					"eaf1.event.buttonstatus.udp4",
					FT_BOOLEAN,
					32,
					NULL,
					0x00800000,
					"UDP 4",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp5,
				{
					"UDP 5",
					"eaf1.event.buttonstatus.udp5",
					FT_BOOLEAN,
					32,
					NULL,
					0x01000000,
					"UDP 5",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp6,
				{
					"UDP 6",
					"eaf1.event.buttonstatus.udp6",
					FT_BOOLEAN,
					32,
					NULL,
					0x02000000,
					"UDP 6",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp7,
				{
					"UDP 7",
					"eaf1.event.buttonstatus.udp7",
					FT_BOOLEAN,
					32,
					NULL,
					0x04000000,
					"UDP 7",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp8,
				{
					"UDP 8",
					"eaf1.event.buttonstatus.udp8",
					FT_BOOLEAN,
					32,
					NULL,
					0x08000000,
					"UDP 8",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp9,
				{
					"UDP 9",
					"eaf1.event.buttonstatus.udp9",
					FT_BOOLEAN,
					32,
					NULL,
					0x10000000,
					"UDP 9",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp10,
				{
					"UDP 10",
					"eaf1.event.buttonstatus.udp10",
					FT_BOOLEAN,
					32,
					NULL,
					0x20000000,
					"UDP 10",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp11,
				{
					"UDP 11",
					"eaf1.event.buttonstatus.udp11",
					FT_BOOLEAN,
					32,
					NULL,
					0x40000000,
					"UDP 11",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_button_status_udp12,
				{
					"UDP 12",
					"eaf1.event.buttonstatus.udp12",
					FT_BOOLEAN,
					32,
					NULL,
					0x80000000,
					"UDP 12",
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

			{
				&hf_eaf1_event_penalty_penaltytype,
				{
					"Event penalty penalty type",
					"eaf1.event.penalty.type",
					FT_UINT8,
					BASE_DEC,
					VALS(penaltytypenames),
					0x0,
					"Event penalty penalty type",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_infringementtype,
				{
					"Event penalty infringement type",
					"eaf1.event.penalty.infringementtype",
					FT_UINT8,
					BASE_DEC,
					VALS(infringementtypenames),
					0x0,
					"Event penalty infringement type",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_vehicleindex,
				{
					"Event penalty vehicle index",
					"eaf1.event.penalty.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event penalty vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_othervehicleindex,
				{
					"Event penalty other vehicle index",
					"eaf1.event.penalty.othervehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event penalty other vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_time,
				{
					"Event penalty time",
					"eaf1.event.penalty.time",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event penalty time",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_lapnumber,
				{
					"Event penalty lap number",
					"eaf1.event.penalty.lapnumber",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event penalty lap number",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_penalty_placesgained,
				{
					"Event penalty places gained",
					"eaf1.event.penalty.placesgained",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event penalty places gained",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_vehicleindex,
				{
					"Event speedtrap vehicle index",
					"eaf1.event.speedtrap.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_speed,
				{
					"Event speedtrap speed",
					"eaf1.event.speedtrap.speed",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap speed",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_isoverallfastestinsession,
				{
					"Event speedtrap is overall fastest in session",
					"eaf1.event.speedtrap.isoverallfastestinsession",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap is overall fastest in session",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_isdriverfastestinsession,
				{
					"Event speedtrap is driver fastest in session",
					"eaf1.event.speedtrap.isdriverfastestinsession",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap is driver fastest in session",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_fastestvehicleindexinsession,
				{
					"Event speedtrap fastest vehicle index in session",
					"eaf1.event.speedtrap.fastestvehicleindexinsession",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap fastest vehicle index in session",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_speedtrap_fastestspeedinsession,
				{
					"Event speedtrap fastest speed in session",
					"eaf1.event.speedtrap.fastestspeedinsession",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Event speedtrap fastest speed in session",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_startlights_numlights,
				{
					"Event startlights num lights",
					"eaf1.event.startlights.numlights",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event startlights num lights",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_drivethroughpenaltyserved_vehicleindex,
				{
					"Event drive through penalty served vehicle index",
					"eaf1.event.drivethroughpenaltyserved.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event drive through penalty served vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_stopgopenaltyserved_vehicleindex,
				{
					"Event stop go penalty served vehicle index",
					"eaf1.event.stopgopenaltyserved.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event stop go penalty served vehicle index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_flashback_frameidentifier,
				{
					"Event flashback frame identifier",
					"eaf1.event.flashback.frameidentifier",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event flashback frame identifier",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_flashback_sessiontime,
				{
					"Event flashback session time",
					"eaf1.event.flashback.sessiontime",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Event flashback session time",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_stopgopenaltyserved_stoptime,
				{
					"Event stop go penalty served stop time",
					"eaf1.event.stopgopenaltyserved.stoptime",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					"Event stop go penalty served stop time",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_collision_vehicle1index,
				{
					"Event collision vehicle 1 index",
					"eaf1.event.collision.vehicle1index",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event collision vehicle 1 index",
					HFILL,
				},
			},

			{
				&hf_eaf1_event_collision_vehicle2index,
				{
					"Event collision vehicle 2 index",
					"eaf1.event.collision.vehicle2index",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Event collision vehicle 2 index",
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
				&ett_eaf1_event_buttonstatus,
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
