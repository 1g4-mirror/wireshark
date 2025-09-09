/* packet-eaf1.cc
 *
 * Copyright 2025, Andy Hawkins <andy@gently.org.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

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
static dissector_table_t e1f1_f125_event_code_dissector_table;

// Different packet types
enum F125PacketId
{
	eF125PacketIdMotion = 0,			  // Contains all motion data for player’s car – only sent while player is in control
	eF125PacketIdSession = 1,			  // Data about the session – track, time left
	eF125PacketIdLapData = 2,			  // Data about all the lap times of cars in the session
	eF125PacketIdEvent = 3,				  // Various notable events that happen during a session
	eF125PacketIdParticipants = 4,		  // List of participants in the session, mostly relevant for multiplayer
	eF125PacketIdCarSetups = 5,			  // Packet detailing car setups for cars in the race
	eF125PacketIdCarTelemetry = 6,		  // Telemetry data for all cars
	eF125PacketIdCarStatus = 7,			  // Status data for all cars
	eF125PacketIdFinalClassification = 8, // Final classification confirmation at the end of a race
	eF125PacketIdLobbyInfo = 9,			  // Information about players in a multiplayer lobby
	eF125PacketIdCarDamage = 10,		  // Damage status for all cars
	eF125PacketIdSessionHistory = 11,	  // Lap and tyre data for session
	eF125PacketIdTyreSets = 12,			  // Extended tyre set data
	eF125PacketIdMotionEx = 13,			  // Extended motion data for player car
	eF125PacketIdTimeTrial = 14,		  // Time Trial specific data
	eF125PacketIdLapPositions = 15,		  // Lap positions on each lap so a chart can be constructed
	eF125PacketIdMax
};

// Valid event strings
static constexpr const char *eaf1_F125SessionStartedEventCode = "SSTA";
static constexpr const char *eaf1_F125SessionEndedEventCode = "SEND";
static constexpr const char *eaf1_F125FastestLapEventCode = "FTLP";
static constexpr const char *eaf1_F125RetirementEventCode = "RTMT";
static constexpr const char *eaf1_F125DRSEnabledEventCode = "DRSE";
static constexpr const char *eaf1_F125DRSDisabledEventCode = "DRSD";
static constexpr const char *eaf1_F125TeamMateInPitsEventCode = "TMPT";
static constexpr const char *eaf1_F125ChequeredFlagEventCode = "CHQF";
static constexpr const char *eaf1_F125RaceWinnerEventCode = "RCWN";
static constexpr const char *eaf1_F125PenaltyEventCode = "PENA";
static constexpr const char *eaf1_F125SpeedTrapEventCode = "SPTP";
static constexpr const char *eaf1_F125StartLightsEventCode = "STLG";
static constexpr const char *eaf1_F125LightsOutEventCode = "LGOT";
static constexpr const char *eaf1_F125DriveThroughServedEventCode = "DTSV";
static constexpr const char *eaf1_F125StopGoServedEventCode = "SGSV";
static constexpr const char *eaf1_F125FlashbackEventCode = "FLBK";
static constexpr const char *eaf1_F125ButtonStatusEventCode = "BUTN";
static constexpr const char *eaf1_F125RedFlagEventCode = "RDFL";
static constexpr const char *eaf1_F125OvertakeEventCode = "OVTK";
static constexpr const char *eaf1_F125SafetyCarEventCode = "SCAR";
static constexpr const char *eaf1_F125CollisionEventCode = "COLL";

static const uint32_t eaf1_F125MaxNumCarsInUDPData = 22;
static const uint8_t eaf1_F125NumLiveryColours = 4;
static const uint32_t eaf1_F125MaxParticipantNameLen = 32;
static const uint32 eaf1_f125_maxMarshalsZonePerLap = 21;
static const uint32 eaf1_f125_maxWeatherForecastSamples = 64;
static const uint32 eaf1_f125_maxSessionsInWeekend = 12;
static const uint32 eaf1_f125_maxTyreStints = 8;
static const uint32 eaf1_F125MaxNumTyreSets = 13 + 7; // 13 slick and 7 wet weather
static const uint eaf1_f125_maxNumLapsInHistory = 100;
static const uint8 eaf1_F125MaxNumLapsInLapPositionsHistoryPacket = 50;

static const size_t eaf1_headerSize = 29;
// static const size_t eaf1_f125_motionSize = 1349;
static const size_t eaf1_f125_sessionSize = 753;
// static const size_t eaf1_f125_lapDataSize = 1285;
static const size_t eaf1_f125_eventDataSize = 45;
static const size_t eaf1_f125_participantsSize = 1284;
// static const size_t eaf1_f125_carSetupsSize = 1133;
// static const size_t eaf1_f125_carTelemetrySize = 1352;
static const size_t eaf1_f125_carStatusSize = 1239;
static const size_t eaf1_f125_finalClassificationSize = 1042;
static const size_t eaf1_f125_lobbyInfoSize = 954;
static const size_t eaf1_f125_carDamageSize = 1041;
static const size_t eaf1_f125_sessionHistorySize = 1460;
static const size_t eaf1_f125_tyreSetsSize = 231;
// static const size_t eaf1_f125_motionExSize = 273;
// static const size_t eaf1_f125_timeTrialSize = 101;
static const size_t eaf1_f125_lapPositionsSize = 1131;

static const uint eaf1_eventStringCodeLen = 4;

typedef struct
{
	char m_DriverNames[eaf1_F125MaxNumCarsInUDPData][eaf1_F125MaxParticipantNameLen];
} tConversationData;

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
static int hf_eaf1_participants_aicontrolled;
static int hf_eaf1_participants_driverid;
static int hf_eaf1_participants_networkid;
static int hf_eaf1_participants_teamid;
static int hf_eaf1_participants_myteam;
static int hf_eaf1_participants_racenumber;
static int hf_eaf1_participants_nationality;
static int hf_eaf1_participants_name;
static int hf_eaf1_participants_yourtelemetry;
static int hf_eaf1_participants_showonlinenames;
static int hf_eaf1_participants_techlevel;
static int hf_eaf1_participants_platform;
static int hf_eaf1_participants_numcolours;
static int hf_eaf1_participants_liverycolour;
static int hf_eaf1_participants_liverycolour_red;
static int hf_eaf1_participants_liverycolour_green;
static int hf_eaf1_participants_liverycolour_blue;

static int hf_eaf1_session_weather;
static int hf_eaf1_session_tracktemperature;
static int hf_eaf1_session_airtemperature;
static int hf_eaf1_session_totallaps;
static int hf_eaf1_session_tracklength;
static int hf_eaf1_session_sessiontype;
static int hf_eaf1_session_trackid;
static int hf_eaf1_session_formula;
static int hf_eaf1_session_sessiontimeleft;
static int hf_eaf1_session_sessionduration;
static int hf_eaf1_session_pitspeedlimit;
static int hf_eaf1_session_gamepaused;
static int hf_eaf1_session_isspectating;
static int hf_eaf1_session_spectatorcarindex;
static int hf_eaf1_session_slipronativesupport;
static int hf_eaf1_session_nummarshalzones;
static int hf_eaf1_session_marshalzone;
static int hf_eaf1_session_marshalzone_start;
static int hf_eaf1_session_marshalzone_flag;
static int hf_eaf1_session_safetycarstatus;
static int hf_eaf1_session_networkgame;
static int hf_eaf1_session_numweatherforecastsamples;
static int hf_eaf1_session_weatherforecastsample;
static int hf_eaf1_session_weatherforecastsample_sessiontype;
static int hf_eaf1_session_weatherforecastsample_timeoffset;
static int hf_eaf1_session_weatherforecastsample_weather;
static int hf_eaf1_session_weatherforecastsample_tracktemperature;
static int hf_eaf1_session_weatherforecastsample_tracktemperaturechange;
static int hf_eaf1_session_weatherforecastsample_airtemperature;
static int hf_eaf1_session_weatherforecastsample_airtemperaturechange;
static int hf_eaf1_session_weatherforecastsample_rainpercentage;
static int hf_eaf1_session_forecastaccuracy;
static int hf_eaf1_session_aidifficulty;
static int hf_eaf1_session_seasonlinkidentifier;
static int hf_eaf1_session_weekendlinkidentifier;
static int hf_eaf1_session_sessionlinkidentifier;
static int hf_eaf1_session_pitstopwindowideallap;
static int hf_eaf1_session_pitstopwindowlatestlap;
static int hf_eaf1_session_pitstoprejoinposition;
static int hf_eaf1_session_steeringassist;
static int hf_eaf1_session_brakingassist;
static int hf_eaf1_session_gearboxassist;
static int hf_eaf1_session_pitassist;
static int hf_eaf1_session_pitreleaseassist;
static int hf_eaf1_session_ersassist;
static int hf_eaf1_session_drsassist;
static int hf_eaf1_session_dynamicracingline;
static int hf_eaf1_session_dynamicracinglinetype;
static int hf_eaf1_session_gamemode;
static int hf_eaf1_session_ruleset;
static int hf_eaf1_session_timeofday;
static int hf_eaf1_session_sessionlength;
static int hf_eaf1_session_speedunitsleadplayer;
static int hf_eaf1_session_temperatureunitsleadplayer;
static int hf_eaf1_session_speedunitssecondaryplayer;
static int hf_eaf1_session_temperatureunitssecondaryplayer;
static int hf_eaf1_session_numsafetycarperiods;
static int hf_eaf1_session_numvirtualsafetycarperiods;
static int hf_eaf1_session_numredflagperiods;
static int hf_eaf1_session_equalcarperformance;
static int hf_eaf1_session_recoverymode;
static int hf_eaf1_session_flashbacklimit;
static int hf_eaf1_session_surfacetype;
static int hf_eaf1_session_lowfuelmode;
static int hf_eaf1_session_racestarts;
static int hf_eaf1_session_tyretemperature;
static int hf_eaf1_session_pitlanetyresim;
static int hf_eaf1_session_cardamage;
static int hf_eaf1_session_cardamagerate;
static int hf_eaf1_session_collisions;
static int hf_eaf1_session_collisionsoffforfirstlaponly;
static int hf_eaf1_session_mpunsafepitrelease;
static int hf_eaf1_session_mpoffforgriefing;
static int hf_eaf1_session_cornercuttingstringency;
static int hf_eaf1_session_parcfermerules;
static int hf_eaf1_session_pitstopexperience;
static int hf_eaf1_session_safetycar;
static int hf_eaf1_session_safetycarexperience;
static int hf_eaf1_session_formationlap;
static int hf_eaf1_session_formationlapexperience;
static int hf_eaf1_session_redflags;
static int hf_eaf1_session_affectslicencelevelsolo;
static int hf_eaf1_session_affectslicencelevelmp;
static int hf_eaf1_session_numsessionsinweekend;
static int hf_eaf1_session_sessionsinweekend_sessiontype;
static int hf_eaf1_session_sector2lapdistancestart;
static int hf_eaf1_session_sector3lapdistancestart;

static int hf_eaf1_cardamage_drivername;
static int hf_eaf1_cardamage_tyrewear;
static int hf_eaf1_cardamage_tyrewear_rearleft;
static int hf_eaf1_cardamage_tyrewear_rearright;
static int hf_eaf1_cardamage_tyrewear_frontleft;
static int hf_eaf1_cardamage_tyrewear_frontright;
static int hf_eaf1_cardamage_tyredamage;
static int hf_eaf1_cardamage_tyredamage_rearleft;
static int hf_eaf1_cardamage_tyredamage_rearright;
static int hf_eaf1_cardamage_tyredamage_frontleft;
static int hf_eaf1_cardamage_tyredamage_frontright;
static int hf_eaf1_cardamage_brakesdamage;
static int hf_eaf1_cardamage_brakesdamage_rearleft;
static int hf_eaf1_cardamage_brakesdamage_rearright;
static int hf_eaf1_cardamage_brakesdamage_frontleft;
static int hf_eaf1_cardamage_brakesdamage_frontright;
static int hf_eaf1_cardamage_tyreblisters;
static int hf_eaf1_cardamage_tyreblisters_rearleft;
static int hf_eaf1_cardamage_tyreblisters_rearright;
static int hf_eaf1_cardamage_tyreblisters_frontleft;
static int hf_eaf1_cardamage_tyreblisters_frontright;
static int hf_eaf1_cardamage_frontleftwingdamage;
static int hf_eaf1_cardamage_frontrightwingdamage;
static int hf_eaf1_cardamage_rearwingdamage;
static int hf_eaf1_cardamage_floordamage;
static int hf_eaf1_cardamage_diffuserdamage;
static int hf_eaf1_cardamage_sidepoddamage;
static int hf_eaf1_cardamage_drsfault;
static int hf_eaf1_cardamage_ersfault;
static int hf_eaf1_cardamage_gearboxdamage;
static int hf_eaf1_cardamage_enginedamage;
static int hf_eaf1_cardamage_enginemguhwear;
static int hf_eaf1_cardamage_engineeswear;
static int hf_eaf1_cardamage_enginecewear;
static int hf_eaf1_cardamage_engineicewear;
static int hf_eaf1_cardamage_enginemgukwear;
static int hf_eaf1_cardamage_enginetcwear;
static int hf_eaf1_cardamage_engineblown;
static int hf_eaf1_cardamage_engineseized;

static int hf_eaf1_tyresets_vehicleindex;
static int hf_eaf1_tyresets_fittedindex;
static int hf_eaf1_tyresets_tyreset;
static int hf_eaf1_tyresets_tyreset_actualtyrecompound;
static int hf_eaf1_tyresets_tyreset_visualtyrecompound;
static int hf_eaf1_tyresets_tyreset_wear;
static int hf_eaf1_tyresets_tyreset_available;
static int hf_eaf1_tyresets_tyreset_recommendedsession;
static int hf_eaf1_tyresets_tyreset_lifespan;
static int hf_eaf1_tyresets_tyreset_usablelife;
static int hf_eaf1_tyresets_tyreset_lapdeltatime;
static int hf_eaf1_tyresets_tyreset_fitted;

static int hf_eaf1_lappositions_numlaps;
static int hf_eaf1_lappositions_lapstart;
static int hf_eaf1_lappositions_lap;
static int hf_eaf1_lappositions_position;

static int hf_eaf1_sessionhistory_caridx;
static int hf_eaf1_sessionhistory_numlaps;
static int hf_eaf1_sessionhistory_numtyrestints;
static int hf_eaf1_sessionhistory_bestlaptimelapnum;
static int hf_eaf1_sessionhistory_bestsector1lapnum;
static int hf_eaf1_sessionhistory_bestsector2lapnum;
static int hf_eaf1_sessionhistory_bestsector3lapnum;
static int hf_eaf1_sessionhistory_lap;
static int hf_eaf1_sessionhistory_laptime;
static int hf_eaf1_sessionhistory_sector1time;
static int hf_eaf1_sessionhistory_sector1timemspart;
static int hf_eaf1_sessionhistory_sector1timeminutespart;
static int hf_eaf1_sessionhistory_sector2time;
static int hf_eaf1_sessionhistory_sector2timemspart;
static int hf_eaf1_sessionhistory_sector2timeminutespart;
static int hf_eaf1_sessionhistory_sector3time;
static int hf_eaf1_sessionhistory_sector3timemspart;
static int hf_eaf1_sessionhistory_sector3timeminutespart;
static int hf_eaf1_sessionhistory_lapvalidbitflags;
static int hf_eaf1_sessionhistory_lapvalidbitflags_lap;
static int hf_eaf1_sessionhistory_lapvalidbitflags_sector1;
static int hf_eaf1_sessionhistory_lapvalidbitflags_sector2;
static int hf_eaf1_sessionhistory_lapvalidbitflags_sector3;
static int hf_eaf1_sessionhistory_tyrestint;
static int hf_eaf1_sessionhistory_endlap;
static int hf_eaf1_sessionhistory_tyreactualcompound;
static int hf_eaf1_sessionhistory_tyrevisualcompound;

static int hf_eaf1_finalclassification_numcars;
static int hf_eaf1_finalclassification_drivername;
static int hf_eaf1_finalclassification_position;
static int hf_eaf1_finalclassification_numlaps;
static int hf_eaf1_finalclassification_gridposition;
static int hf_eaf1_finalclassification_points;
static int hf_eaf1_finalclassification_numpitstops;
static int hf_eaf1_finalclassification_resultstatus;
static int hf_eaf1_finalclassification_resultreason;
static int hf_eaf1_finalclassification_bestlaptimeinms;
static int hf_eaf1_finalclassification_totalracetime;
static int hf_eaf1_finalclassification_penaltiestime;
static int hf_eaf1_finalclassification_numpenalties;
static int hf_eaf1_finalclassification_numtyrestints;
static int hf_eaf1_finalclassification_tyrestint;
static int hf_eaf1_finalclassification_tyrestint_actual;
static int hf_eaf1_finalclassification_tyrestint_visual;
static int hf_eaf1_finalclassification_tyrestint_endlaps;

static int hf_eaf1_carstatus_drivername;
static int hf_eaf1_carstatus_tractioncontrol;
static int hf_eaf1_carstatus_antilockbrakes;
static int hf_eaf1_carstatus_fuelmix;
static int hf_eaf1_carstatus_frontbrakebias;
static int hf_eaf1_carstatus_pitlimiterstatus;
static int hf_eaf1_carstatus_fuelintank;
static int hf_eaf1_carstatus_fuelcapacity;
static int hf_eaf1_carstatus_fuelremaininglaps;
static int hf_eaf1_carstatus_maxrpm;
static int hf_eaf1_carstatus_idlerpm;
static int hf_eaf1_carstatus_maxgears;
static int hf_eaf1_carstatus_drsallowed;
static int hf_eaf1_carstatus_drsactivationdistance;
static int hf_eaf1_carstatus_actualtyrecompound;
static int hf_eaf1_carstatus_visualtyrecompound;
static int hf_eaf1_carstatus_tyresagelaps;
static int hf_eaf1_carstatus_vehiclefiaflags;
static int hf_eaf1_carstatus_enginepowerice;
static int hf_eaf1_carstatus_enginepowermguk;
static int hf_eaf1_carstatus_ersstoreenergy;
static int hf_eaf1_carstatus_ersdeploymode;
static int hf_eaf1_carstatus_ersharvestedthislapmguk;
static int hf_eaf1_carstatus_ersharvestedthislapmguh;
static int hf_eaf1_carstatus_ersdeployedthislap;
static int hf_eaf1_carstatus_networkpaused;

static int hf_eaf1_lapdata_drivername;
static int hf_eaf1_lapdata_lastlaptimeinms;
static int hf_eaf1_lapdata_currentlaptimeinms;
static int hf_eaf1_lapdata_sector1time;
static int hf_eaf1_lapdata_sector1timemspart;
static int hf_eaf1_lapdata_sector1timeminutespart;
static int hf_eaf1_lapdata_sector2time;
static int hf_eaf1_lapdata_sector2timemspart;
static int hf_eaf1_lapdata_sector2timeminutespart;
static int hf_eaf1_lapdata_deltatocarinfront;
static int hf_eaf1_lapdata_deltatocarinfrontmspart;
static int hf_eaf1_lapdata_deltatocarinfrontminutespart;
static int hf_eaf1_lapdata_deltatoraceleader;
static int hf_eaf1_lapdata_deltatoraceleadermspart;
static int hf_eaf1_lapdata_deltatoraceleaderminutespart;
static int hf_eaf1_lapdata_lapdistance;
static int hf_eaf1_lapdata_totaldistance;
static int hf_eaf1_lapdata_safetycardelta;
static int hf_eaf1_lapdata_carposition;
static int hf_eaf1_lapdata_currentlapnum;
static int hf_eaf1_lapdata_pitstatus;
static int hf_eaf1_lapdata_numpitstops;
static int hf_eaf1_lapdata_sector;
static int hf_eaf1_lapdata_currentlapinvalid;
static int hf_eaf1_lapdata_penalties;
static int hf_eaf1_lapdata_totalwarnings;
static int hf_eaf1_lapdata_cornercuttingwarnings;
static int hf_eaf1_lapdata_numunserveddrivethroughpens;
static int hf_eaf1_lapdata_numunservedstopgopens;
static int hf_eaf1_lapdata_gridposition;
static int hf_eaf1_lapdata_driverstatus;
static int hf_eaf1_lapdata_resultstatus;
static int hf_eaf1_lapdata_pitlanetimeractive;
static int hf_eaf1_lapdata_pitlanetimeinlaneinms;
static int hf_eaf1_lapdata_pitstoptimerinms;
static int hf_eaf1_lapdata_pitstopshouldservepen;
static int hf_eaf1_lapdata_speedtrapfastestspeed;
static int hf_eaf1_lapdata_speedtrapfastestlap;
static int hf_eaf1_lapdata_timetrialpbcaridx;
static int hf_eaf1_lapdata_timetrialrivalcaridx;

static int ett_eaf1;
static int ett_eaf1_version;
static int ett_eaf1_packetid;
static int ett_eaf1_lobbyinfo_numplayers;
static int ett_eaf1_lobbyinfo_player_name;
static int ett_eaf1_event_eventcode;
static int ett_eaf1_event_buttonstatus;
static int ett_eaf1_participants_player_name;
static int ett_eaf1_participants_numcolours;
static int ett_eaf1_participants_livery_colour;
static int ett_eaf1_session_nummarshalzones;
static int ett_eaf1_session_marshalzone;
static int ett_eaf1_session_numweatherforecastsamples;
static int ett_eaf1_session_weatherforecastsample;
static int ett_eaf1_session_numsessionsinweekend;
static int ett_eaf1_cardamage_drivername;
static int ett_eaf1_cardamage_tyrewear;
static int ett_eaf1_cardamage_tyredamage;
static int ett_eaf1_cardamage_brakesdamage;
static int ett_eaf1_cardamage_tyreblisters;
static int ett_eaf1_tyresets_vehicleindex;
static int ett_eaf1_tyresets_tyreset;
static int ett_eaf1_lappositions_lap;
static int ett_eaf1_sessionhistory_vehicleindex;
static int ett_eaf1_sessionhistory_numlaps;
static int ett_eaf1_sessionhistory_numtyrestints;
static int ett_eaf1_sessionhistory_lap;
static int ett_eaf1_sessionhistory_sector1time;
static int ett_eaf1_sessionhistory_sector2time;
static int ett_eaf1_sessionhistory_sector3time;
static int ett_eaf1_sessionhistory_lapvalidbitflags;
static int ett_eaf1_sessionhistory_tyrestint;
static int ett_eaf1_finalclassification_drivername;
static int ett_eaf1_finalclassification_numstints;
static int ett_eaf1_finalclassification_tyrestint;
static int ett_eaf1_carstatus_drivername;
static int ett_eaf1_lapdata_drivername;
static int ett_eaf1_lapdata_sector1time;
static int ett_eaf1_lapdata_sector2time;
static int ett_eaf1_lapdata_deltatocarinfront;
static int ett_eaf1_lapdata_deltatoraceleader;

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

static const value_string flagnames[] = {
	{(uint32_t)-1, "Invalid / unknown"},
	{0, "None"},
	{1, "Green"},
	{2, "Blue"},
	{3, "Yellow"},
	{0, NULL},
};

static const value_string networkgamenames[] = {
	{0, "Offline"},
	{1, "Online"},
	{0, NULL},
};

static const value_string safetycartypenames[] = {
	{0, "No Safety Car"},
	{1, "Full Safety Car"},
	{2, "Virtual Safety Car"},
	{3, "Formation Lap"},
	{0, NULL},
};

static const value_string safetycareventtypenames[] = {
	{0, "Deployed"},
	{1, "Returning"},
	{2, "Returned"},
	{3, "Resume Race"},
	{0, NULL},
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
	{0, NULL},
};

static const value_string drsdisabledreasonnames[] = {
	{0, "Wet track"},
	{1, "Safety car deployed"},
	{2, "Red flag"},
	{3, "Min lap not reached"},
	{0, NULL},
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
	{0, NULL},
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
	{0, NULL},
};

static const value_string weathernames[] = {
	{0, "Clear"},
	{1, "Light cloud"},
	{2, "Overcast"},
	{3, "Light rain"},
	{4, "Heavy rain"},
	{5, "Storm"},
	{0, NULL},
};

static const value_string sessiontypenames[] = {
	{0, "Unknown"},
	{1, "Practice 1"},
	{2, "Practice 2"},
	{3, "Practice 3"},
	{4, "Short Practice"},
	{5, "Qualifying 1"},
	{6, "Qualifying 2"},
	{7, "Qualifying 3"},
	{8, "Short Qualifying"},
	{9, "One - Shot Qualifying"},
	{10, "Sprint Shootout 1"},
	{11, "Sprint Shootout 2"},
	{12, "Sprint Shootout 3"},
	{13, "Short Sprint Shootout"},
	{14, "One - Shot Sprint Shootout"},
	{15, "Race"},
	{16, "Race 2"},
	{17, "Race 3"},
	{18, "Time Trial"},
	{0, NULL},
};

static const value_string tracknames[] = {
	{0, "Melbourne"},
	{2, "Shanghai"},
	{3, "Sakhir (Bahrain)"},
	{4, "Catalunya"},
	{5, "Monaco"},
	{6, "Montreal"},
	{7, "Silverstone"},
	{9, "Hungaroring"},
	{10, "Spa"},
	{11, "Monza"},
	{12, "Singapore"},
	{13, "Suzuka"},
	{14, "Abu Dhabi"},
	{15, "Texas"},
	{16, "Brazil"},
	{17, "Austria"},
	{19, "Mexico"},
	{20, "Baku (Azerbaijan)"},
	{26, "Zandvoort"},
	{27, "Imola"},
	{29, "Jeddah"},
	{30, "Miami"},
	{31, "Las Vegas"},
	{32, "Losail"},
	{39, "Silverstone (Reverse)"},
	{40, "Austria (Reverse)"},
	{41, "Zandvoort (Reverse)"},
	{0, NULL},
};

static const value_string formulanames[] = {
	{0, "F1 Modern"},
	{1, "F1 Classic"},
	{2, "F2"},
	{3, "F1 Generic"},
	{4, "Beta"},
	{6, "Esports"},
	{8, "F1 World"},
	{9, "F1 Elimination"},
	{0, NULL},
};

static const value_string forecastaccuracynames[] = {
	{0, "Perfect"},
	{1, "Approximate"},
	{0, NULL},
};

static const value_string brakingassistnames[] = {
	{0, "Off"},
	{1, "Low"},
	{2, "Medium"},
	{3, "High"},
	{0, NULL},
};

static const value_string gearboxassistnames[] = {
	{1, "Manual"},
	{2, "Manual & suggested gear"},
	{3, "Auto"},
	{0, NULL},
};

static const value_string dynamicracinglinenames[] = {
	{0, "Off"},
	{1, "Corners only"},
	{2, "Full"},
	{0, NULL},
};

static const value_string dynamicracinglinetypenames[] = {
	{0, "2D"},
	{1, "3D"},
	{0, NULL},
};

static const value_string gamemodenames[] = {
	{4, "Grand Prix ‘23"},
	{5, "Time Trial"},
	{6, "Splitscreen"},
	{7, "Online Custom"},
	{15, "Online Weekly Event"},
	{17, "Story Mode (Braking Point)"},
	{27, "My Team Career ‘25"},
	{28, "Driver Career ‘25"},
	{29, "Career ’25 Online"},
	{30, "Challenge Career ‘25"},
	{75, "Story Mode (APXGP)"},
	{127, "Benchmark"},
	{0, NULL},
};

static const value_string rulesetnames[] = {
	{0, "Practice & Qualifying"},
	{1, "Race"},
	{2, "Time Trial"},
	{12, "Elimination"},
	{0, NULL},
};

static const value_string sessionlengthnames[] = {
	{0, "None"},
	{2, "Very short"},
	{3, "Short"},
	{4, "Medium"},
	{5, "Medium Long"},
	{6, "Long"},
	{7, "Full"},
	{0, NULL},
};

static const value_string speedunitsnames[] = {
	{0, "MPH"},
	{1, "KPH"},
	{0, NULL},
};

static const value_string temperatureunitsnames[] = {
	{0, "Celsius"},
	{1, "Fahrenheit"},
	{0, NULL},
};

static const value_string recoverymodenames[] = {
	{0, "None"},
	{1, "Flashbacks"},
	{2, "Auto - recovery"},
	{0, NULL},
};

static const value_string flashbacklimitnames[] = {
	{0, "Low"},
	{1, "Medium"},
	{2, "High"},
	{3, "Unlimited"},
	{0, NULL},
};

static const value_string surfacetypenames[] = {
	{0, "Simplified"},
	{1, "Realistic"},
	{0, NULL},
};

static const value_string lowfuelmodenames[] = {
	{0, "Easy"},
	{1, "Hard"},
	{0, NULL},
};

static const value_string racestartsnames[] = {
	{0, "Manual"},
	{1, "Assisted"},
	{0, NULL},
};

static const value_string tyretemperaturenames[] = {
	{0, "Surface only"},
	{1, "Surface & Carcass"},
	{0, NULL},
};

static const value_string pitlanetyresimnames[] = {
	{0, "On"},
	{1, "Off"},
	{0, NULL},
};

static const value_string cardamagenames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Simulation"},
	{0, NULL},
};

static const value_string cardamageratenames[] = {
	{0, "Reduced"},
	{1, "Standard"},
	{2, "Simulation"},
	{0, NULL},
};

static const value_string collisionsnames[] = {
	{0, "Off"},
	{1, "Player - to - Player Off"},
	{2, "On"},
	{0, NULL},
};

static const value_string mpunsafepitreleasenames[] = {
	{0, "On"},
	{1, "Off (Multiplayer)"},
	{0, NULL},
};

static const value_string cornercuttingstringencynames[] = {
	{0, "Regular"},
	{1, "Strict"},
	{0, NULL},
};

static const value_string pitstopexperiencenames[] = {
	{0, "Automatic"},
	{1, "Broadcast"},
	{2, "Immersive"},
	{0, NULL},
};

static const value_string safetycarnames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Increased"},
	{0, NULL},
};

static const value_string safetycarexperiencenames[] = {
	{0, "Broadcast"},
	{1, "Immersive"},
	{0, NULL},
};

static const value_string formationlapexperiencenames[] = {
	{0, "Broadcast"},
	{1, "Immersive"},
	{0, NULL},
};

static const value_string redflagnames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Increased"},
	{0, NULL},
};

static const value_string actualtyrecompoundnames[] = {
	{16, "C5"},
	{17, "C4"},
	{18, "C3"},
	{19, "C2"},
	{20, "C1"},
	{21, "C0"},
	{22, "C6"},
	{7, "inter"},
	{8, "wet"},
	{9, "dry"},
	{10, "wet"},
	{11, "super soft"},
	{12, "soft"},
	{13, "medium"},
	{14, "hard"},
	{15, "wet"},
	{0, NULL},
};

static const value_string visualtyrecompoundnames[] = {
	{16, "soft"},
	{17, "medium"},
	{18, "hard"},
	{7, "inter"},
	{8, "wet"},
	{9, "dry"},
	{10, "wet"},
	{15, "wet"},
	{19, "super soft"},
	{20, "soft"},
	{21, "medium"},
	{22, "hard"},
	{0, NULL},
};

static const value_string resultstatusnames[] = {
	{0, "Invalid"},
	{1, "Inactive"},
	{2, "Active"},
	{3, "Finished"},
	{4, "DNF"},
	{5, "Disqualified"},
	{6, "Not classified"},
	{7, "Retired"},
	{0, NULL},
};

static const value_string resultreasonnames[] = {
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
	{0, NULL},
};

static const value_string tractioncontrolnames[] = {
	{0, "Off"},
	{1, "Medium"},
	{2, "Full"},
	{0, NULL},
};

static const value_string pitstatusnames[] = {
	{0, "None"},
	{1, "Pitting"},
	{2, "In pit area"},
	{0, NULL},
};

static const value_string sectornames[] = {
	{0, "Sector 1"},
	{1, "Sector 2"},
	{2, "Sector 3"},
	{0, NULL},
};

static const value_string driverstatusnames[] = {
	{0, "In garage"},
	{1, "Flying lap"},
	{2, "In lap"},
	{3, "Out lap"},
	{4, "On track"},
	{0, NULL},
};

static const value_string fuelmixnames[] = {
	{0, "Lean"},
	{1, "Standard"},
	{2, "Rich"},
	{3, "Max"},
	{0, NULL},
};

static const char *lookup_driver_name(int proto, uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index)
{
	const char *ret = NULL;

	if (vehicle_index != 255)
	{
		auto conversation = find_conversation(packet_number, &src_addr, NULL, CONVERSATION_UDP, src_port, 0, NO_ADDR_B | NO_PORT_B);
		if (conversation)
		{
			tConversationData *conversation_data = (tConversationData *)conversation_get_proto_data(conversation, proto);
			if (conversation_data)
			{
				ret = conversation_data->m_DriverNames[vehicle_index];
			}
		}
	}

	return ret;
}

static proto_item *add_vehicle_index_and_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	uint32_t vehicle_index;
	auto ti_vehicle_index = proto_tree_add_item_ret_uint(tree, header_field, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &vehicle_index);

	const char *driver_name = lookup_driver_name(proto, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index);
	if (driver_name)
	{
		proto_item_append_text(ti_vehicle_index, " (%s)", driver_name);
	}

	return ti_vehicle_index;
}

static proto_item *add_driver_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, uint8_t participant_index)
{
	auto ti_driver_name = proto_tree_add_item(tree, header_field, tvb, 0, 0, ENC_UTF_8);

	const char *driver_name = lookup_driver_name(proto, pinfo->num, pinfo->src, pinfo->srcport, participant_index);
	if (driver_name)
	{
		proto_item_set_text(ti_driver_name, "%d - '%s'", participant_index, driver_name);
	}

	return ti_driver_name;
}

static void add_sector_time(proto_tree *tree, int header_field_time, int header_field_timems, int header_field_timemin, int ett, packet_info *pinfo, tvbuff_t *tvb, int msoffset, int minoffset)
{
	uint8 mins = tvb_get_uint8(tvb, minoffset);
	uint16 ms = tvb_get_uint16(tvb, msoffset, ENC_LITTLE_ENDIAN);

	auto sector_ti = proto_tree_add_string(tree,
										   header_field_time,
										   tvb,
										   msoffset,
										   sizeof(uint16_t) + sizeof(uint8_t),
										   wmem_strdup_printf(pinfo->pool, "%01d:%02d.%03d",
															  mins,
															  ms / 1000,
															  ms % 1000));
	auto sector_tree = proto_item_add_subtree(sector_ti, ett);

	proto_tree_add_item(sector_tree, header_field_timems, tvb, msoffset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sector_tree, header_field_timemin, tvb, minoffset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
}

static int dissect_eaf1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAF1");
	/* Clear the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_eaf1, tvb, 0, -1, ENC_NA);
	proto_tree *eaf1_tree = proto_item_add_subtree(ti, ett_eaf1);
	uint32_t packet_format;

	int offset = 0;

	proto_tree_add_item_ret_uint(eaf1_tree, hf_eaf1_packet_format, tvb, offset, 2, ENC_LITTLE_ENDIAN, &packet_format);
	offset += 2;

	proto_tree_add_item(eaf1_tree, hf_eaf1_game_year, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	uint8_t version_major = tvb_get_uint8(tvb, offset);
	uint8_t version_minor = tvb_get_uint8(tvb, offset + 1);

	proto_item *ti_version = proto_tree_add_string(eaf1_tree,
												   hf_eaf1_game_version,
												   tvb, offset, 2,
												   wmem_strdup_printf(pinfo->pool,
																	  "%d.%d",
																	  version_major,
																	  version_minor));

	proto_item_set_generated(ti_version);

	proto_tree *eaf1_version_tree = proto_item_add_subtree(ti_version, ett_eaf1_version);
	proto_tree_add_item(eaf1_version_tree, hf_eaf1_game_major_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(eaf1_version_tree, hf_eaf1_game_minor_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(eaf1_tree, hf_eaf1_packet_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	int offset_packetid = offset;
	offset += 1;

	proto_tree_add_item(eaf1_tree, hf_eaf1_session_uid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(eaf1_tree, hf_eaf1_session_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(eaf1_tree, hf_eaf1_frame_identifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(eaf1_tree, hf_eaf1_overall_frame_identifier, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(eaf1_tree, hf_eaf1_player_car_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(eaf1_tree, hf_eaf1_secondary_player_car_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	uint32_t packet_id;
	proto_item *packetid_ti = proto_tree_add_item_ret_uint(eaf1_tree, hf_eaf1_packet_id, tvb, offset_packetid, 1, ENC_LITTLE_ENDIAN, &packet_id);
	proto_tree *packetid_tree = proto_item_add_subtree(packetid_ti, ett_eaf1_packetid);

	col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "%d", packet_id));

	if (!dissector_try_uint_new(eaf1_packet_format_dissector_table,
								packet_format, tvb, pinfo, packetid_tree,
								false, &packet_id))
	{
		auto next_tvb = tvb_new_subset_remaining(tvb, eaf1_headerSize);

		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 23");

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2024(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 24");

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1 25");

	uint32_t eaf1_packet_id = *(uint32_t *)data;

	if (!dissector_try_uint_new(eaf1_f125_packet_id_dissector_table,
								eaf1_packet_id, tvb, pinfo, tree,
								false, tree))
	{
		auto next_tvb = tvb_new_subset_remaining(tvb, eaf1_headerSize);

		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_lobbyinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_lobbyInfoSize)
	{
		int offset = eaf1_headerSize;

		uint8_t num_players = tvb_get_uint8(tvb, offset);
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "LobbyInfo: %d players", num_players));

		auto num_players_ti = proto_tree_add_item(tree, hf_eaf1_lobby_info_num_players, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree *eaf1_num_players_tree = proto_item_add_subtree(num_players_ti, ett_eaf1_lobbyinfo_numplayers);

		for (int count = 0; count < num_players; count++)
		{
			auto player_name_ti = proto_tree_add_item(eaf1_num_players_tree, hf_eaf1_lobby_info_player_name, tvb, offset + 4, eaf1_F125MaxParticipantNameLen, ENC_UTF_8);
			proto_tree *eaf1_player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_lobbyinfo_player_name);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_ai_controlled, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_team_id, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_nationality, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_platform, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			// We've added in the player name above
			offset += eaf1_F125MaxParticipantNameLen;

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_car_number, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_your_telemetry, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_show_online_names, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_tech_level, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint16_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_lobby_info_ready_status, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_eventDataSize)
	{
		int offset = eaf1_headerSize;

		const char *EventCode;

		auto event_code_ti = proto_tree_add_item_ret_string(tree, hf_eaf1_event_code, tvb, offset, eaf1_eventStringCodeLen, ENC_UTF_8, pinfo->pool, (const uint8_t **)&EventCode);
		proto_tree *eaf1_event_code_tree = proto_item_add_subtree(event_code_ti, ett_eaf1_event_eventcode);
		offset += eaf1_eventStringCodeLen;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Event: %s", EventCode));

		static const string_string event_desc_lookup[] = {
			{
				eaf1_F125SessionStartedEventCode,
				"Session start",
			},
			{
				eaf1_F125SessionEndedEventCode,
				"Session end",
			},
			{
				eaf1_F125FastestLapEventCode,
				"Fastest lap ",
			},
			{
				eaf1_F125RetirementEventCode,
				"Retirement",
			},
			{
				eaf1_F125DRSEnabledEventCode,
				"DRS Enabled",
			},
			{
				eaf1_F125DRSDisabledEventCode,
				"DRS Disabled",
			},
			{
				eaf1_F125TeamMateInPitsEventCode,
				"Teammate in pits",
			},
			{
				eaf1_F125ChequeredFlagEventCode,
				"Chequered flag",
			},
			{
				eaf1_F125RaceWinnerEventCode,
				"Race winner",
			},
			{
				eaf1_F125PenaltyEventCode,
				"Penalty",
			},
			{
				eaf1_F125SpeedTrapEventCode,
				"Speed trap",
			},
			{
				eaf1_F125StartLightsEventCode,
				"Start lights",
			},
			{
				eaf1_F125LightsOutEventCode,
				"Lights out",
			},
			{
				eaf1_F125DriveThroughServedEventCode,
				"Drive through penalty served",
			},
			{
				eaf1_F125StopGoServedEventCode,
				"Stop go penalty served",
			},
			{
				eaf1_F125FlashbackEventCode,
				"Flashback",
			},
			{
				eaf1_F125ButtonStatusEventCode,
				"Button",
			},
			{
				eaf1_F125RedFlagEventCode,
				"Red flag",
			},
			{
				eaf1_F125OvertakeEventCode,
				"Overtake",
			},
			{
				eaf1_F125SafetyCarEventCode,
				"Safety car",
			},
			{
				eaf1_F125CollisionEventCode,
				"Collision",
			},
			{NULL, NULL},
		};

		const char *event_desc = try_str_to_str(EventCode, event_desc_lookup);
		if (event_desc)
		{
			proto_item_set_text(event_code_ti, "%s", event_desc);
		}

		auto next_tvb = tvb_new_subset_remaining(tvb, eaf1_headerSize + eaf1_eventStringCodeLen);

		if (!dissector_try_string_new(e1f1_f125_event_code_dissector_table,
									  EventCode, next_tvb, pinfo, eaf1_event_code_tree,
									  false, NULL))
		{
			call_data_dissector(next_tvb, pinfo, tree);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_event_sessionstarted(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_sessionended(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_fastestlap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_fastestlap_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_fastestlap_laptime, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
	offset += sizeof(float);

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_retirement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_retirement_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_retirement_reason, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_drsenabled(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_drsdisabled(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_eaf1_event_drsdisabled_reason, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_teammateinpits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_teammateinpits_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_chequeredflag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_racewinner(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_racewinner_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_penalty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_eaf1_event_penalty_penaltytype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_penalty_infringementtype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_penalty_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_penalty_othervehicleindex, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_penalty_time, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_penalty_lapnumber, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_penalty_placesgained, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_speedtrap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_speedtrap_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_speedtrap_speed, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
	offset += sizeof(float);

	proto_tree_add_item(tree, hf_eaf1_event_speedtrap_isoverallfastestinsession, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_speedtrap_isdriverfastestinsession, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_speedtrap_fastestvehicleindexinsession, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_speedtrap_fastestspeedinsession, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
	offset += sizeof(float);

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_startlights(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_eaf1_event_startlights_numlights, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_lightsout(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_drivethroughserved(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_drivethroughpenaltyserved_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_stopgoserved(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_stopgopenaltyserved_vehicleindex, pinfo, tvb, offset);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_stopgopenaltyserved_stoptime, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
	offset += sizeof(float);

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_flashback(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_eaf1_event_flashback_frameidentifier, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_flashback_sessiontime, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
	offset += sizeof(float);

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_button(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
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

	int offset = 0;

	proto_tree_add_bitmask(tree, tvb, offset, hf_eaf1_event_button_status,
						   ett_eaf1_event_buttonstatus, button_status_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_redflag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	// No data for this event type

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_overtake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_overtake_overtakingvehicleindex, pinfo, tvb, offset);
	offset += 1;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_overtake_overtakenvehicleindex, pinfo, tvb, offset);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_safetycar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	proto_tree_add_item(tree, hf_eaf1_event_safetycar_type, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_eaf1_event_safetycar_eventtype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_event_collision(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	int offset = 0;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_collision_vehicle1index, pinfo, tvb, offset);
	offset += 1;

	add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_event_collision_vehicle2index, pinfo, tvb, offset);
	offset += 1;

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_participants(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_participantsSize)
	{
		tConversationData conversation_data;
		memset(&conversation_data, 0, sizeof(conversation_data));

		int offset = eaf1_headerSize;

		uint32_t active_cars;

		proto_tree_add_item_ret_uint(tree, hf_eaf1_participants_activecars, tvb, offset, 1, ENC_LITTLE_ENDIAN, &active_cars);
		offset += 1;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Participants: %d active", active_cars));

		for (std::remove_const<decltype(eaf1_F125MaxNumCarsInUDPData)>::type participant = 0; participant < eaf1_F125MaxNumCarsInUDPData; participant++)
		{
			char *player_name;

			auto player_name_ti = proto_tree_add_item_ret_string(tree, hf_eaf1_participants_name, tvb, offset + 7, eaf1_F125MaxParticipantNameLen, ENC_UTF_8, pinfo->pool, (const uint8_t **)&player_name);
			proto_tree *eaf1_player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_participants_player_name);

			if (!PINFO_FD_VISITED(pinfo))
			{
				snprintf(conversation_data.m_DriverNames[participant], sizeof(conversation_data.m_DriverNames[participant]), "%s", player_name);
			}

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_aicontrolled, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_driverid, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_networkid, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_teamid, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_myteam, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_racenumber, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_nationality, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			// We got the name above
			offset += eaf1_F125MaxParticipantNameLen;

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_yourtelemetry, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_showonlinenames, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_techlevel, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint16_t);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_platform, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			uint32_t num_colours;
			auto num_colours_ti = proto_tree_add_item_ret_uint(eaf1_player_name_tree, hf_eaf1_participants_numcolours, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_colours);
			offset += sizeof(uint8_t);

			proto_tree *eaf1_num_colours_tree = proto_item_add_subtree(num_colours_ti, ett_eaf1_participants_numcolours);

			for (uint32_t colour = 0; colour < eaf1_F125NumLiveryColours; colour++)
			{
				if (colour < num_colours)
				{
					auto livery_colour_ti = proto_tree_add_item(eaf1_num_colours_tree, hf_eaf1_participants_liverycolour, tvb, 0, 0, ENC_LITTLE_ENDIAN);
					proto_tree *eaf1_livery_colour_tree = proto_item_add_subtree(livery_colour_ti, ett_eaf1_participants_livery_colour);

					uint32_t red;
					uint32_t green;
					uint32_t blue;

					proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_red, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &red);
					offset += sizeof(uint8_t);

					proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_green, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &green);
					offset += sizeof(uint8_t);

					proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_blue, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &blue);
					offset += sizeof(uint8_t);

					proto_item_append_text(livery_colour_ti, " (0x%02x%02x%02x)", red, green, blue);
				}
				else
				{
					offset += 3;
				}
			}
		}

		if (!PINFO_FD_VISITED(pinfo))
		{
			auto conversation = conversation_new(pinfo->num, &pinfo->src,
												 NULL, CONVERSATION_UDP, pinfo->srcport,
												 0, NO_ADDR2 | NO_PORT2);

			if (conversation)
			{
				conversation_add_proto_data(conversation, proto_eaf1, wmem_memdup(wmem_file_scope(), &conversation_data, sizeof(conversation_data)));
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_sessionSize)
	{
		int offset = eaf1_headerSize;

		proto_tree_add_item(tree, hf_eaf1_session_weather, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_tracktemperature, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(int8_t);

		proto_tree_add_item(tree, hf_eaf1_session_airtemperature, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(int8_t);

		proto_tree_add_item(tree, hf_eaf1_session_totallaps, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_tracklength, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint16_t);

		uint32_t session_type;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_session_sessiontype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &session_type);
		offset += sizeof(uint8_t);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session (%s)", val_to_str(session_type, sessiontypenames, "Invalid session %u")));

		proto_tree_add_item(tree, hf_eaf1_session_trackid, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(int8_t);

		proto_tree_add_item(tree, hf_eaf1_session_formula, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_sessiontimeleft, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint16_t);

		proto_tree_add_item(tree, hf_eaf1_session_sessionduration, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint16_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitspeedlimit, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_gamepaused, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_isspectating, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_spectatorcarindex, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_slipronativesupport, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		uint32_t num_marshal_zones;

		auto num_marshal_zones_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_nummarshalzones, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_marshal_zones);
		offset += sizeof(uint8_t);

		auto num_marshal_zones_tree = proto_item_add_subtree(num_marshal_zones_ti, ett_eaf1_session_nummarshalzones);

		for (uint32_t zone = 0; zone < eaf1_f125_maxMarshalsZonePerLap; zone++)
		{
			if (zone < num_marshal_zones)
			{
				auto marshal_zone_ti = proto_tree_add_item(num_marshal_zones_tree, hf_eaf1_session_marshalzone, tvb, 0, 0, ENC_LITTLE_ENDIAN);
				proto_tree *marshal_zone_tree = proto_item_add_subtree(marshal_zone_ti, ett_eaf1_session_marshalzone);

				proto_tree_add_item(marshal_zone_tree, hf_eaf1_session_marshalzone_start, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
				offset += sizeof(float);

				proto_tree_add_item(marshal_zone_tree, hf_eaf1_session_marshalzone_flag, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(int8_t);
			}
			else
			{
				offset += sizeof(float) + sizeof(int8_t);
			}
		}

		proto_tree_add_item(tree, hf_eaf1_session_safetycarstatus, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_networkgame, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		uint32_t num_weather_forecast_samples;
		auto num_weather_forecast_samples_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_numweatherforecastsamples, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_weather_forecast_samples);
		offset += sizeof(uint8_t);

		auto num_weather_forecast_samples_tree = proto_item_add_subtree(num_weather_forecast_samples_ti, ett_eaf1_session_numweatherforecastsamples);

		for (uint32_t sample = 0; sample < eaf1_f125_maxWeatherForecastSamples; sample++)
		{
			if (sample < num_weather_forecast_samples)
			{
				auto weather_sample_ti = proto_tree_add_item(num_weather_forecast_samples_tree, hf_eaf1_session_weatherforecastsample, tvb, 0, 0, ENC_LITTLE_ENDIAN);
				proto_tree *weather_sample_tree = proto_item_add_subtree(weather_sample_ti, ett_eaf1_session_weatherforecastsample);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_sessiontype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_timeoffset, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_weather, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_tracktemperature, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(int8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_tracktemperaturechange, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(int8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_airtemperature, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(int8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_airtemperaturechange, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(int8_t);

				proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_rainpercentage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);
			}
			else
			{
				offset += 8;
			}
		}

		proto_tree_add_item(tree, hf_eaf1_session_forecastaccuracy, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_aidifficulty, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_seasonlinkidentifier, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint32_t);

		proto_tree_add_item(tree, hf_eaf1_session_weekendlinkidentifier, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint32_t);

		proto_tree_add_item(tree, hf_eaf1_session_sessionlinkidentifier, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint32_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitstopwindowideallap, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitstopwindowlatestlap, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitstoprejoinposition, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_steeringassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_brakingassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_gearboxassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitreleaseassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_ersassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_drsassist, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_dynamicracingline, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_dynamicracinglinetype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_gamemode, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_ruleset, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_timeofday, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint32_t);

		proto_tree_add_item(tree, hf_eaf1_session_sessionlength, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_speedunitsleadplayer, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_temperatureunitsleadplayer, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_speedunitssecondaryplayer, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_temperatureunitssecondaryplayer, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_numsafetycarperiods, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_numvirtualsafetycarperiods, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_numredflagperiods, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_equalcarperformance, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_recoverymode, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_flashbacklimit, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_surfacetype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_lowfuelmode, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_racestarts, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_tyretemperature, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitlanetyresim, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_cardamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_cardamagerate, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_collisions, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_collisionsoffforfirstlaponly, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_mpunsafepitrelease, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_mpoffforgriefing, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_cornercuttingstringency, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_parcfermerules, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_pitstopexperience, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_safetycar, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_safetycarexperience, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_formationlap, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_formationlapexperience, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_redflags, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_affectslicencelevelsolo, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(tree, hf_eaf1_session_affectslicencelevelmp, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		uint32_t num_sessions_in_weekend;
		auto num_sessions_in_weekend_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_numsessionsinweekend, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_sessions_in_weekend);
		offset += sizeof(uint8_t);

		auto num_sessions_in_weekend_tree = proto_item_add_subtree(num_sessions_in_weekend_ti, ett_eaf1_session_numsessionsinweekend);

		for (uint32_t session = 0; session < eaf1_f125_maxSessionsInWeekend; session++)
		{
			if (session < num_sessions_in_weekend)
			{
				proto_tree_add_item(num_sessions_in_weekend_tree, hf_eaf1_session_sessionsinweekend_sessiontype, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);
			}
			else
			{
				offset += sizeof(uint8_t);
			}
		}

		proto_tree_add_item(tree, hf_eaf1_session_sector2lapdistancestart, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
		offset += sizeof(float);

		proto_tree_add_item(tree, hf_eaf1_session_sector3lapdistancestart, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
		offset += sizeof(float);

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_cardamage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_carDamageSize)
	{
		int offset = eaf1_headerSize;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Car damage"));

		for (std::remove_const<decltype(eaf1_F125MaxNumCarsInUDPData)>::type participant = 0; participant < eaf1_F125MaxNumCarsInUDPData; participant++)
		{
			auto driver_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_cardamage_drivername, pinfo, tvb, participant);
			auto driver_name_tree = proto_item_add_subtree(driver_name_ti, ett_eaf1_cardamage_drivername);

			auto tyre_wear_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyrewear, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_wear_tree = proto_item_add_subtree(tyre_wear_ti, ett_eaf1_cardamage_tyrewear);

			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_rearleft, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_rearright, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_frontleft, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_frontright, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			auto tyre_damage_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyredamage, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_damage_tree = proto_item_add_subtree(tyre_damage_ti, ett_eaf1_cardamage_tyredamage);

			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_rearleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_rearright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_frontleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_frontright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			auto brakes_damage_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_brakesdamage, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto brakes_damage_tree = proto_item_add_subtree(brakes_damage_ti, ett_eaf1_cardamage_brakesdamage);

			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_rearleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_rearright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_frontleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_frontright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			auto tyre_blisters_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyreblisters, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_blisters_tree = proto_item_add_subtree(tyre_blisters_ti, ett_eaf1_cardamage_tyreblisters);

			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_rearleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_rearright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_frontleft, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_frontright, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_frontleftwingdamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_frontrightwingdamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_rearwingdamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_floordamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_diffuserdamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_sidepoddamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_drsfault, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_ersfault, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_gearboxdamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginedamage, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginemguhwear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineeswear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginecewear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineicewear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginemgukwear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginetcwear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineblown, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineseized, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_tyresets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_tyreSetsSize)
	{
		int offset = eaf1_headerSize;

		uint8_t vehicle_index = tvb_get_uint8(tvb, offset);

		auto vehicle_index_ti = add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_tyresets_vehicleindex, pinfo, tvb, offset);
		offset += sizeof(uint8_t);

		auto vehicle_index_tree = proto_item_add_subtree(vehicle_index_ti, ett_eaf1_tyresets_vehicleindex);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Tyre sets (%s)", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index)));

		for (std::remove_const<decltype(eaf1_F125MaxNumTyreSets)>::type tyre_set = 0; tyre_set < eaf1_F125MaxNumTyreSets; tyre_set++)
		{
			auto tyreset_ti = proto_tree_add_string(vehicle_index_tree, hf_eaf1_tyresets_tyreset, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "Set %d", tyre_set));
			auto tyreset_tree = proto_item_add_subtree(tyreset_ti, ett_eaf1_tyresets_tyreset);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_actualtyrecompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_visualtyrecompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_wear, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_available, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_recommendedsession, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_lifespan, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_usablelife, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_lapdeltatime, tvb, offset, sizeof(int16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(int16_t);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_fitted, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);
		}

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_tyresets_fittedindex, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_lappositions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_lapPositionsSize)
	{
		int offset = eaf1_headerSize;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Lap positions"));

		uint32_t num_laps;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_lappositions_numlaps, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_laps);
		offset += sizeof(uint8_t);

		uint32_t lap_start;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_lappositions_lapstart, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &lap_start);
		offset += sizeof(uint8_t);

		for (std::remove_const<decltype(eaf1_F125MaxNumLapsInLapPositionsHistoryPacket)>::type lap = 0; lap < num_laps; lap++)
		{
			auto lap_ti = proto_tree_add_string(tree,
												hf_eaf1_lappositions_lap,
												tvb,
												offset,
												eaf1_F125MaxNumCarsInUDPData,
												wmem_strdup_printf(pinfo->pool, "Lap %d", lap_start + lap + 1));
			auto lap_tree = proto_item_add_subtree(lap_ti, ett_eaf1_lappositions_lap);

			for (std::remove_const<decltype(eaf1_F125MaxNumCarsInUDPData)>::type vehicle_index = 0; vehicle_index < eaf1_F125MaxNumCarsInUDPData; vehicle_index++)
			{
				auto position = tvb_get_uint8(tvb, offset);

				proto_tree_add_string(lap_tree,
									  hf_eaf1_lappositions_position,
									  tvb,
									  offset,
									  sizeof(uint8_t),
									  wmem_strdup_printf(pinfo->pool, "%s: %d", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index), position));

				offset += sizeof(uint8_t);
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_sessionhistory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_sessionHistorySize)
	{
		int offset = eaf1_headerSize;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session history"));

		uint8_t vehicle_index = tvb_get_uint8(tvb, offset);

		auto vehicle_index_ti = add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_sessionhistory_caridx, pinfo, tvb, offset);
		offset += sizeof(uint8_t);

		auto vehicle_index_tree = proto_item_add_subtree(vehicle_index_ti, ett_eaf1_sessionhistory_vehicleindex);

		int num_laps_offset = offset;
		offset += sizeof(uint8_t);

		int num_tyrestints_offset = offset;
		offset += sizeof(uint8_t);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session history (%s)", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index)));

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestlaptimelapnum, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector1lapnum, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector2lapnum, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector3lapnum, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
		offset += sizeof(uint8_t);

		uint32_t num_laps;
		auto num_laps_ti = proto_tree_add_item_ret_uint(vehicle_index_tree, hf_eaf1_sessionhistory_numlaps, tvb, num_laps_offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_laps);
		auto num_laps_tree = proto_item_add_subtree(num_laps_ti, ett_eaf1_sessionhistory_numlaps);

		static int eaf1_f125_lap_history_data_size = sizeof(uint32) +
													 sizeof(uint16) +
													 sizeof(uint8) +
													 sizeof(uint16) +
													 sizeof(uint8) +
													 sizeof(uint16) +
													 sizeof(uint8) +
													 sizeof(uint8);

		for (uint32_t lap_number = 0; lap_number < eaf1_f125_maxNumLapsInHistory; lap_number++)
		{
			if (lap_number < num_laps)
			{
				auto lap_ti = proto_tree_add_string(num_laps_tree,
													hf_eaf1_sessionhistory_lap,
													tvb,
													offset,
													eaf1_f125_lap_history_data_size,
													wmem_strdup_printf(pinfo->pool, "Lap %d", lap_number + 1));

				auto lap_tree = proto_item_add_subtree(lap_ti, ett_eaf1_sessionhistory_lap);

				proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_laptime, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint32_t);

				add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector1time, hf_eaf1_sessionhistory_sector1timemspart, hf_eaf1_sessionhistory_sector1timeminutespart, ett_eaf1_sessionhistory_sector1time, pinfo, tvb, offset, offset + sizeof(uint16));
				offset += sizeof(uint16_t) + sizeof(uint8_t);

				add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector2time, hf_eaf1_sessionhistory_sector2timemspart, hf_eaf1_sessionhistory_sector2timeminutespart, ett_eaf1_sessionhistory_sector2time, pinfo, tvb, offset, offset + sizeof(uint16));
				offset += sizeof(uint16_t) + sizeof(uint8_t);

				add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector3time, hf_eaf1_sessionhistory_sector3timemspart, hf_eaf1_sessionhistory_sector3timeminutespart, ett_eaf1_sessionhistory_sector3time, pinfo, tvb, offset, offset + sizeof(uint16));
				offset += sizeof(uint16_t) + sizeof(uint8_t);

				static int *const valid_status_fields[] = {
					&hf_eaf1_sessionhistory_lapvalidbitflags_lap,
					&hf_eaf1_sessionhistory_lapvalidbitflags_sector1,
					&hf_eaf1_sessionhistory_lapvalidbitflags_sector2,
					&hf_eaf1_sessionhistory_lapvalidbitflags_sector3,
					NULL,
				};

				proto_tree_add_bitmask(lap_tree, tvb, offset, hf_eaf1_sessionhistory_lapvalidbitflags,
									   ett_eaf1_sessionhistory_lapvalidbitflags, valid_status_fields, ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);
			}
			else
			{
				offset += eaf1_f125_lap_history_data_size;
			}
		}

		static int eaf1_f125_tyre_stint_history_data_size = sizeof(uint8) +
															sizeof(uint8) +
															sizeof(uint8);

		uint32_t num_tyre_stints;
		auto num_tyre_stints_ti = proto_tree_add_item_ret_uint(vehicle_index_tree, hf_eaf1_sessionhistory_numtyrestints, tvb, num_tyrestints_offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_tyre_stints);
		auto num_tyre_stints_tree = proto_item_add_subtree(num_tyre_stints_ti, ett_eaf1_sessionhistory_numtyrestints);

		for (uint32_t tyre_stint_number = 0; tyre_stint_number < eaf1_f125_maxTyreStints; tyre_stint_number++)
		{
			if (tyre_stint_number < num_tyre_stints)
			{
				auto tyre_stint_ti = proto_tree_add_string(num_tyre_stints_tree,
														   hf_eaf1_sessionhistory_tyrestint,
														   tvb,
														   offset,
														   eaf1_f125_tyre_stint_history_data_size,
														   wmem_strdup_printf(pinfo->pool, "Tyre stint %d", tyre_stint_number + 1));

				auto tyre_stint_tree = proto_item_add_subtree(tyre_stint_ti, ett_eaf1_sessionhistory_tyrestint);

				proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_endlap, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);

				proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_tyreactualcompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);

				proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_tyrevisualcompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				offset += sizeof(uint8_t);
			}
			else
			{
				offset += eaf1_f125_tyre_stint_history_data_size;
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_finalclassification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_finalClassificationSize)
	{
		int offset = eaf1_headerSize;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Final classification"));

		uint32_t num_cars;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_finalclassification_numcars, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_cars);
		offset += sizeof(uint8_t);

		for (uint32_t car = 0; car < num_cars; car++)
		{
			auto player_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_finalclassification_drivername, pinfo, tvb, car);
			proto_tree *player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_finalclassification_drivername);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_position, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numlaps, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_gridposition, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_points, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numpitstops, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_resultstatus, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_resultreason, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_bestlaptimeinms, tvb, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint32_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_totalracetime, tvb, offset, sizeof(double), ENC_LITTLE_ENDIAN);
			offset += sizeof(double);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_penaltiestime, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numpenalties, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			uint32_t num_stints;
			auto num_stints_ti = proto_tree_add_item_ret_uint(player_name_tree, hf_eaf1_finalclassification_numtyrestints, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN, &num_stints);
			offset += sizeof(uint8_t);

			proto_tree *num_stints_tree = proto_item_add_subtree(num_stints_ti, ett_eaf1_finalclassification_numstints);

			int actual_offset = offset;
			offset += eaf1_f125_maxTyreStints;

			int visual_offset = offset;
			offset += eaf1_f125_maxTyreStints;

			int endlap_offset = offset;
			offset += eaf1_f125_maxTyreStints;

			for (uint32_t stint = 0; stint < num_stints; stint++)
			{
				auto tyre_stint_ti = proto_tree_add_string(num_stints_tree,
														   hf_eaf1_finalclassification_tyrestint,
														   tvb,
														   0,
														   0,
														   wmem_strdup_printf(pinfo->pool, "Tyre stint %d", stint + 1));
				auto tyre_stint_tree = proto_item_add_subtree(tyre_stint_ti, ett_eaf1_sessionhistory_tyrestint);

				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_actual, tvb, actual_offset + stint * sizeof(uint8_t), sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_visual, tvb, visual_offset + stint * sizeof(uint8_t), sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_endlaps, tvb, endlap_offset + stint * sizeof(uint8_t), sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_carstatus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= eaf1_f125_carStatusSize)
	{
		int offset = eaf1_headerSize;

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Car status"));

		for (std::remove_const<decltype(eaf1_F125MaxNumCarsInUDPData)>::type participant = 0; participant < eaf1_F125MaxNumCarsInUDPData; participant++)
		{
			auto driver_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_carstatus_drivername, pinfo, tvb, participant);
			auto driver_name_tree = proto_item_add_subtree(driver_name_ti, ett_eaf1_carstatus_drivername);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_tractioncontrol, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_antilockbrakes, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_fuelmix, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_frontbrakebias, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_pitlimiterstatus, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_fuelintank, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_fuelcapacity, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_fuelremaininglaps, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_maxrpm, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint16_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_idlerpm, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint16_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_maxgears, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_drsallowed, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_drsactivationdistance, tvb, offset, sizeof(uint16_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint16_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_actualtyrecompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_visualtyrecompound, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_tyresagelaps, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_vehiclefiaflags, tvb, offset, sizeof(int8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(int8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_enginepowerice, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_enginepowermguk, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_ersstoreenergy, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_ersdeploymode, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_ersharvestedthislapmguk, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_ersharvestedthislapmguh, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_ersdeployedthislap, tvb, offset, sizeof(float), ENC_LITTLE_ENDIAN);
			offset += sizeof(float);

			proto_tree_add_item(driver_name_tree, hf_eaf1_carstatus_networkpaused, tvb, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			offset += sizeof(uint8_t);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_lapdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketLapData))
	{
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Lap data"));

		for (std::remove_const<decltype(eaf1_F125MaxNumCarsInUDPData)>::type participant = 0; participant < eaf1_F125MaxNumCarsInUDPData; participant++)
		{
			int participant_offset = offsetof(F125::PacketLapData, m_lapData) + participant * sizeof(F125::LapData);

			auto driver_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_lapdata_drivername, pinfo, tvb, participant);
			auto driver_name_tree = proto_item_add_subtree(driver_name_ti, ett_eaf1_lapdata_drivername);

			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_lastlaptimeinms, tvb, participant_offset + offsetof(F125::LapData, m_lastLapTimeInMS), sizeof(F125::LapData::m_lastLapTimeInMS), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_currentlaptimeinms, tvb, participant_offset + offsetof(F125::LapData, m_currentLapTimeInMS), sizeof(F125::LapData::m_currentLapTimeInMS), ENC_LITTLE_ENDIAN);
			add_sector_time(driver_name_tree, hf_eaf1_lapdata_sector1time, hf_eaf1_lapdata_sector1timemspart, hf_eaf1_lapdata_sector1timeminutespart, ett_eaf1_lapdata_sector1time, pinfo, tvb, participant_offset + offsetof(F125::LapData, m_sector1TimeMSPart), participant_offset + offsetof(F125::LapData, m_sector1TimeMinutesPart));
			add_sector_time(driver_name_tree, hf_eaf1_lapdata_sector2time, hf_eaf1_lapdata_sector2timemspart, hf_eaf1_lapdata_sector2timeminutespart, ett_eaf1_lapdata_sector2time, pinfo, tvb, participant_offset + offsetof(F125::LapData, m_sector2TimeMSPart), participant_offset + offsetof(F125::LapData, m_sector2TimeMinutesPart));
			add_sector_time(driver_name_tree, hf_eaf1_lapdata_deltatocarinfront, hf_eaf1_lapdata_deltatocarinfrontmspart, hf_eaf1_lapdata_deltatocarinfrontminutespart, ett_eaf1_lapdata_deltatocarinfront, pinfo, tvb, participant_offset + offsetof(F125::LapData, m_deltaToCarInFrontMSPart), participant_offset + offsetof(F125::LapData, m_deltaToCarInFrontMinutesPart));
			add_sector_time(driver_name_tree, hf_eaf1_lapdata_deltatoraceleader, hf_eaf1_lapdata_deltatoraceleadermspart, hf_eaf1_lapdata_deltatoraceleaderminutespart, ett_eaf1_lapdata_deltatoraceleader, pinfo, tvb, participant_offset + offsetof(F125::LapData, m_deltaToRaceLeaderMSPart), participant_offset + offsetof(F125::LapData, m_deltaToRaceLeaderMinutesPart));
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_lapdistance, tvb, participant_offset + offsetof(F125::LapData, m_lapDistance), sizeof(F125::LapData::m_lapDistance), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_totaldistance, tvb, participant_offset + offsetof(F125::LapData, m_totalDistance), sizeof(F125::LapData::m_totalDistance), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_safetycardelta, tvb, participant_offset + offsetof(F125::LapData, m_safetyCarDelta), sizeof(F125::LapData::m_safetyCarDelta), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_carposition, tvb, participant_offset + offsetof(F125::LapData, m_carPosition), sizeof(F125::LapData::m_carPosition), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_currentlapnum, tvb, participant_offset + offsetof(F125::LapData, m_currentLapNum), sizeof(F125::LapData::m_currentLapNum), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_pitstatus, tvb, participant_offset + offsetof(F125::LapData, m_pitStatus), sizeof(F125::LapData::m_pitStatus), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_numpitstops, tvb, participant_offset + offsetof(F125::LapData, m_numPitStops), sizeof(F125::LapData::m_numPitStops), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_sector, tvb, participant_offset + offsetof(F125::LapData, m_sector), sizeof(F125::LapData::m_sector), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_currentlapinvalid, tvb, participant_offset + offsetof(F125::LapData, m_currentLapInvalid), sizeof(F125::LapData::m_currentLapInvalid), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_penalties, tvb, participant_offset + offsetof(F125::LapData, m_penalties), sizeof(F125::LapData::m_penalties), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_totalwarnings, tvb, participant_offset + offsetof(F125::LapData, m_totalWarnings), sizeof(F125::LapData::m_totalWarnings), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_cornercuttingwarnings, tvb, participant_offset + offsetof(F125::LapData, m_cornerCuttingWarnings), sizeof(F125::LapData::m_cornerCuttingWarnings), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_numunserveddrivethroughpens, tvb, participant_offset + offsetof(F125::LapData, m_numUnservedDriveThroughPens), sizeof(F125::LapData::m_numUnservedDriveThroughPens), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_numunservedstopgopens, tvb, participant_offset + offsetof(F125::LapData, m_numUnservedStopGoPens), sizeof(F125::LapData::m_numUnservedStopGoPens), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_gridposition, tvb, participant_offset + offsetof(F125::LapData, m_gridPosition), sizeof(F125::LapData::m_gridPosition), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_driverstatus, tvb, participant_offset + offsetof(F125::LapData, m_driverStatus), sizeof(F125::LapData::m_driverStatus), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_resultstatus, tvb, participant_offset + offsetof(F125::LapData, m_resultStatus), sizeof(F125::LapData::m_resultStatus), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_pitlanetimeractive, tvb, participant_offset + offsetof(F125::LapData, m_pitLaneTimerActive), sizeof(F125::LapData::m_pitLaneTimerActive), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_pitlanetimeinlaneinms, tvb, participant_offset + offsetof(F125::LapData, m_pitLaneTimeInLaneInMS), sizeof(F125::LapData::m_pitLaneTimeInLaneInMS), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_pitstoptimerinms, tvb, participant_offset + offsetof(F125::LapData, m_pitStopTimerInMS), sizeof(F125::LapData::m_pitStopTimerInMS), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_pitstopshouldservepen, tvb, participant_offset + offsetof(F125::LapData, m_pitStopShouldServePen), sizeof(F125::LapData::m_pitStopShouldServePen), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_speedtrapfastestspeed, tvb, participant_offset + offsetof(F125::LapData, m_speedTrapFastestSpeed), sizeof(F125::LapData::m_speedTrapFastestSpeed), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_lapdata_speedtrapfastestlap, tvb, participant_offset + offsetof(F125::LapData, m_speedTrapFastestLap), sizeof(F125::LapData::m_speedTrapFastestLap), ENC_LITTLE_ENDIAN);
		}

		proto_tree_add_item(tree, hf_eaf1_lapdata_timetrialpbcaridx, tvb, offsetof(F125::PacketLapData, m_timeTrialPBCarIdx), sizeof(F125::PacketLapData::m_timeTrialPBCarIdx), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_lapdata_timetrialrivalcaridx, tvb, offsetof(F125::PacketLapData, m_timeTrialRivalCarIdx), sizeof(F125::PacketLapData::m_timeTrialRivalCarIdx), ENC_LITTLE_ENDIAN);

		return tvb_captured_length(tvb);
	}

	return 0;
}

extern "C"
{
	void proto_register_eaf1(void)
	{
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
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
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_aicontrolled,
				{
					"Participants AI controlled",
					"eaf1.participants.aicontrolled",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_driverid,
				{
					"Participants driver id",
					"eaf1.participants.driverid",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_networkid,
				{
					"Participants network id",
					"eaf1.participants.networkid",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_teamid,
				{
					"Participants team id",
					"eaf1.participants.teamid",
					FT_UINT8,
					BASE_DEC,
					VALS(teamidnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_myteam,
				{
					"Participants my team",
					"eaf1.participants.myteam",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_racenumber,
				{
					"Participants race number",
					"eaf1.participants.racenumber",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_nationality,
				{
					"Participants nationality",
					"eaf1.participants.nationality",
					FT_UINT8,
					BASE_DEC,
					VALS(nationalityidnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_name,
				{
					"Participants name",
					"eaf1.participants.name",
					FT_STRINGZ,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_yourtelemetry,
				{
					"Participants your telemetry",
					"eaf1.participants.yourtelemetry",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_showonlinenames,
				{
					"Participants show online names",
					"eaf1.participants.showonlinenames",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_techlevel,
				{
					"Participants tech level",
					"eaf1.participants.techlevel",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_platform,
				{
					"Participants platform",
					"eaf1.participants.platform",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_numcolours,
				{
					"Participants num livery colours",
					"eaf1.participants.numcolours",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_liverycolour,
				{
					"Participants livery colour",
					"eaf1.participants.liverycolour",
					FT_NONE,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_liverycolour_red,
				{
					"Participants livery colour red",
					"eaf1.participants.liverycolour.red",
					FT_UINT8,
					BASE_HEX,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_liverycolour_green,
				{
					"Participants livery colour green",
					"eaf1.participants.liverycolour.green",
					FT_UINT8,
					BASE_HEX,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_liverycolour_blue,
				{
					"Participants livery colour blue",
					"eaf1.participants.liverycolour.blue",
					FT_UINT8,
					BASE_HEX,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Session packet

			{
				&hf_eaf1_session_weather,
				{
					"Session weather",
					"eaf1.session.weather",
					FT_UINT8,
					BASE_DEC,
					VALS(weathernames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_tracktemperature,
				{
					"Session track temperature",
					"eaf1.session.tracktemperature",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_airtemperature,
				{
					"Session air temperature",
					"eaf1.session.airtemperature",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_totallaps,
				{
					"Session total laps",
					"eaf1.session.totallaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_tracklength,
				{
					"Session track length",
					"eaf1.session.tracklength",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessiontype,
				{
					"Session type",
					"eaf1.session.sessiontype",
					FT_UINT8,
					BASE_DEC,
					VALS(sessiontypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_trackid,
				{
					"Session track id",
					"eaf1.session.trackid",
					FT_INT8,
					BASE_DEC,
					VALS(tracknames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_formula,
				{
					"Session formula",
					"eaf1.session.formula",
					FT_UINT8,
					BASE_DEC,
					VALS(formulanames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessiontimeleft,
				{
					"Session time left",
					"eaf1.session.sessiontimeleft",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessionduration,
				{
					"Session duration",
					"eaf1.session.sessionduration",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitspeedlimit,
				{
					"Session pit speed limit",
					"eaf1.session.pitspeedlimit",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_gamepaused,
				{
					"Session game paused",
					"eaf1.session.gamepaused",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_isspectating,
				{
					"Session is spectating",
					"eaf1.session.isspectating",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_spectatorcarindex,
				{
					"Session spectator car index",
					"eaf1.session.spectatorcarindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_slipronativesupport,
				{
					"Session SLI Pro native support",
					"eaf1.session.slipronativesupport",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_nummarshalzones,
				{
					"Session num marshal zones",
					"eaf1.session.nummarshalzones",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_marshalzone,
				{
					"Session marshal zone",
					"eaf1.session.marshalzone",
					FT_NONE,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_marshalzone_start,
				{
					"Session marshal zone start",
					"eaf1.session.marshalzone.start",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_marshalzone_flag,
				{
					"Session marshal zone flag",
					"eaf1.session.marshalzone.flag",
					FT_INT8,
					BASE_DEC,
					VALS(flagnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_safetycarstatus,
				{
					"Session safety car status",
					"eaf1.session.safetycarstatus",
					FT_UINT8,
					BASE_DEC,
					VALS(safetycartypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_networkgame,
				{
					"Session network game",
					"eaf1.session.networkgame",
					FT_UINT8,
					BASE_DEC,
					VALS(networkgamenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_numweatherforecastsamples,
				{
					"Session num weather forecast samples",
					"eaf1.session.numweatherforecastsamples",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample,
				{
					"Session weather forecast sample",
					"eaf1.session.weatherforecastsample",
					FT_NONE,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_sessiontype,
				{
					"sessionType",
					"eaf1.session.weatherforecastsample.sessionType",
					FT_UINT8,
					BASE_DEC,
					VALS(sessiontypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_timeoffset,
				{
					"timeOffset",
					"eaf1.session.weatherforecastsample.timeOffset",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_weather,
				{
					"weather",
					"eaf1.session.weatherforecastsample.weather",
					FT_UINT8,
					BASE_DEC,
					VALS(weathernames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_tracktemperature,
				{
					"trackTemperature",
					"eaf1.session.weatherforecastsample.trackTemperature",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_tracktemperaturechange,
				{
					"trackTemperatureChange",
					"eaf1.session.weatherforecastsample.trackTemperatureChange",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_airtemperature,
				{
					"airTemperature",
					"eaf1.session.weatherforecastsample.airTemperature",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_airtemperaturechange,
				{
					"airTemperatureChange",
					"eaf1.session.weatherforecastsample.airTemperatureChange",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weatherforecastsample_rainpercentage,
				{
					"rainPercentage",
					"eaf1.session.weatherforecastsample.rainPercentage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_forecastaccuracy,
				{
					"Session forecast accuracy",
					"eaf1.session.forecastaccuracy",
					FT_UINT8,
					BASE_DEC,
					VALS(forecastaccuracynames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_aidifficulty,
				{
					"Session AI difficulty",
					"eaf1.session.aidifficulty",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_seasonlinkidentifier,
				{
					"Session season link identifier",
					"eaf1.session.seasonlinkidentifier",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_weekendlinkidentifier,
				{
					"Session weekend link identifier",
					"eaf1.session.weekendlinkidentifier",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessionlinkidentifier,
				{
					"Session session link identifier",
					"eaf1.session.sessionlinkidentifier",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitstopwindowideallap,
				{
					"Session pit stop window ideal lap",
					"eaf1.session.pitstopwindowideallap",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitstopwindowlatestlap,
				{
					"Session pit stop window latest lap",
					"eaf1.session.pitstopwindowlatestlap",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitstoprejoinposition,
				{
					"Session pit stop rejoin position",
					"eaf1.session.pitstoprejoinposition",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_steeringassist,
				{
					"Session steering assist",
					"eaf1.session.steeringassist",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_brakingassist,
				{
					"Session braking assist",
					"eaf1.session.brakingassist",
					FT_UINT8,
					BASE_DEC,
					VALS(brakingassistnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_gearboxassist,
				{
					"Session gearbox assist",
					"eaf1.session.gearboxassist",
					FT_UINT8,
					BASE_DEC,
					VALS(gearboxassistnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitassist,
				{
					"Session pit assist",
					"eaf1.session.pitassist",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitreleaseassist,
				{
					"Session pit release assist",
					"eaf1.session.pitreleaseassist",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_ersassist,
				{
					"Session ERS assist",
					"eaf1.session.ersassist",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_drsassist,
				{
					"Session DRS assist",
					"eaf1.session.drsassist",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_dynamicracingline,
				{
					"Session dynamic racing line",
					"eaf1.session.dynamicracingline",
					FT_UINT8,
					BASE_DEC,
					VALS(dynamicracinglinenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_dynamicracinglinetype,
				{
					"Session dynamic racing line type",
					"eaf1.session.dynamicracinglinetype",
					FT_UINT8,
					BASE_DEC,
					VALS(dynamicracinglinetypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_gamemode,
				{
					"Session game mode",
					"eaf1.session.gamemode",
					FT_UINT8,
					BASE_DEC,
					VALS(gamemodenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_ruleset,
				{
					"Session rule set",
					"eaf1.session.ruleset",
					FT_UINT8,
					BASE_DEC,
					VALS(rulesetnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_timeofday,
				{
					"Session time Of day",
					"eaf1.session.timeofday",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessionlength,
				{
					"Session session length",
					"eaf1.session.sessionlength",
					FT_UINT8,
					BASE_DEC,
					VALS(sessionlengthnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_speedunitsleadplayer,
				{
					"Session speed units lead player",
					"eaf1.session.speedunitsleadplayer",
					FT_UINT8,
					BASE_DEC,
					VALS(speedunitsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_temperatureunitsleadplayer,
				{
					"Session temperature units lead player",
					"eaf1.session.temperatureunitsleadplayer",
					FT_UINT8,
					BASE_DEC,
					VALS(temperatureunitsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_speedunitssecondaryplayer,
				{
					"Session speed units secondary player",
					"eaf1.session.speedunitssecondaryplayer",
					FT_UINT8,
					BASE_DEC,
					VALS(speedunitsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_temperatureunitssecondaryplayer,
				{
					"Session temperature units secondary player",
					"eaf1.session.temperatureunitssecondaryplayer",
					FT_UINT8,
					BASE_DEC,
					VALS(temperatureunitsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_numsafetycarperiods,
				{
					"Session num safety car periods",
					"eaf1.session.numsafetycarperiods",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_numvirtualsafetycarperiods,
				{
					"Session num virtual safety car periods",
					"eaf1.session.numvirtualsafetycarperiods",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_numredflagperiods,
				{
					"Session num red flag periods",
					"eaf1.session.numredflagperiods",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_equalcarperformance,
				{
					"Session equal car performance",
					"eaf1.session.equalcarperformance",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_recoverymode,
				{
					"Session recovery mode",
					"eaf1.session.recoverymode",
					FT_UINT8,
					BASE_DEC,
					VALS(recoverymodenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_flashbacklimit,
				{
					"Session flashback limit",
					"eaf1.session.flashbacklimit",
					FT_UINT8,
					BASE_DEC,
					VALS(flashbacklimitnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_surfacetype,
				{
					"Session surface type",
					"eaf1.session.surfacetype",
					FT_UINT8,
					BASE_DEC,
					VALS(surfacetypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_lowfuelmode,
				{
					"Session low fuel mode",
					"eaf1.session.lowfuelmode",
					FT_UINT8,
					BASE_DEC,
					VALS(lowfuelmodenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_racestarts,
				{
					"Session race starts",
					"eaf1.session.racestarts",
					FT_UINT8,
					BASE_DEC,
					VALS(racestartsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_tyretemperature,
				{
					"Session tyre temperature",
					"eaf1.session.tyretemperature",
					FT_UINT8,
					BASE_DEC,
					VALS(tyretemperaturenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitlanetyresim,
				{
					"Session pit lane tyre sim",
					"eaf1.session.pitlanetyresim",
					FT_UINT8,
					BASE_DEC,
					VALS(pitlanetyresimnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_cardamage,
				{
					"Session car damage",
					"eaf1.session.cardamage",
					FT_UINT8,
					BASE_DEC,
					VALS(cardamagenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_cardamagerate,
				{
					"Session car damage rate",
					"eaf1.session.cardamagerate",
					FT_UINT8,
					BASE_DEC,
					VALS(cardamageratenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_collisions,
				{
					"Session collisions",
					"eaf1.session.collisions",
					FT_UINT8,
					BASE_DEC,
					VALS(collisionsnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_collisionsoffforfirstlaponly,
				{
					"Session collisions off for first lap only",
					"eaf1.session.collisionsoffforfirstlaponly",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_mpunsafepitrelease,
				{
					"Session MP unsafe pit release",
					"eaf1.session.mpunsafepitrelease",
					FT_UINT8,
					BASE_DEC,
					VALS(mpunsafepitreleasenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_mpoffforgriefing,
				{
					"Session MP off for griefing",
					"eaf1.session.mpoffforgriefing",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_cornercuttingstringency,
				{
					"Session corner cutting stringency",
					"eaf1.session.cornercuttingstringency",
					FT_UINT8,
					BASE_DEC,
					VALS(cornercuttingstringencynames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_parcfermerules,
				{
					"Session parc ferme rules",
					"eaf1.session.parcfermerules",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_pitstopexperience,
				{
					"Session pit stop experience",
					"eaf1.session.pitstopexperience",
					FT_UINT8,
					BASE_DEC,
					VALS(pitstopexperiencenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_safetycar,
				{
					"Session safety car",
					"eaf1.session.safetycar",
					FT_UINT8,
					BASE_DEC,
					VALS(safetycarnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_safetycarexperience,
				{
					"Session safety car experience",
					"eaf1.session.safetycarexperience",
					FT_UINT8,
					BASE_DEC,
					VALS(safetycarexperiencenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_formationlap,
				{
					"Session formation lap",
					"eaf1.session.formationlap",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_formationlapexperience,
				{
					"Session formation lap experience",
					"eaf1.session.formationlapexperience",
					FT_UINT8,
					BASE_DEC,
					VALS(formationlapexperiencenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_redflags,
				{
					"Session red flags",
					"eaf1.session.redflags",
					FT_UINT8,
					BASE_DEC,
					VALS(redflagnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_affectslicencelevelsolo,
				{
					"Session affects licence level solo",
					"eaf1.session.affectslicencelevelsolo",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_affectslicencelevelmp,
				{
					"Session affects licence level MP",
					"eaf1.session.affectslicencelevelmp",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_numsessionsinweekend,
				{
					"Session num sessions in weekend",
					"eaf1.session.numsessionsinweekend",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sessionsinweekend_sessiontype,
				{
					"Session session in weekend session type",
					"eaf1.session.sessionsinweekend.sessiontype",
					FT_UINT8,
					BASE_DEC,
					VALS(sessiontypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sector2lapdistancestart,
				{
					"Session sector 2 lap distance start",
					"eaf1.session.sector2lapdistancestart",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_session_sector3lapdistancestart,
				{
					"Session sector 3 lap distance start",
					"eaf1.session.sector3lapdistancestart",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// CarDamage packet

			{
				&hf_eaf1_cardamage_drivername,
				{
					"Car damage driver name",
					"eaf1.cardamage.drivername",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyrewear,
				{
					"Car damage tyre wear",
					"eaf1.cardamage.tyrewear",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyrewear_rearleft,
				{
					"Car damage tyre wear rear left",
					"eaf1.cardamage.tyrewear.rearleft",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyrewear_rearright,
				{
					"Car damage tyre wear rear right",
					"eaf1.cardamage.tyrewear.rearright",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyrewear_frontleft,
				{
					"Car damage tyre wear front left",
					"eaf1.cardamage.tyrewear.frontleft",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyrewear_frontright,
				{
					"Car damage tyre wear front right",
					"eaf1.cardamage.tyrewear.frontright",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyredamage,
				{
					"Car damage tyre damage",
					"eaf1.cardamage.tyredamage",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyredamage_rearleft,
				{
					"Car damage tyre damage rear left",
					"eaf1.cardamage.tyredamage.rearleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyredamage_rearright,
				{
					"Car damage tyre damage rear right",
					"eaf1.cardamage.tyredamage.rearright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyredamage_frontleft,
				{
					"Car damage tyre damage front left",
					"eaf1.cardamage.tyredamage.frontleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyredamage_frontright,
				{
					"Car damage tyre damage front right",
					"eaf1.cardamage.tyredamage.frontright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_brakesdamage,
				{
					"Car damage brakes damage",
					"eaf1.cardamage.brakesdamage",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_brakesdamage_rearleft,
				{
					"Car damage brakes damage rear left",
					"eaf1.cardamage.brakesdamage.rearleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_brakesdamage_rearright,
				{
					"Car damage brakes damage rear right",
					"eaf1.cardamage.brakesdamage.rearright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_brakesdamage_frontleft,
				{
					"Car damage brakes damage front left",
					"eaf1.cardamage.brakesdamage.frontleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_brakesdamage_frontright,
				{
					"Car damage brakes damage front right",
					"eaf1.cardamage.brakesdamage.frontright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},
			{
				&hf_eaf1_cardamage_tyreblisters,
				{
					"Car damage tyre blisters",
					"eaf1.cardamage.tyreblisters",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyreblisters_rearleft,
				{
					"Car damage tyre blisters rear left",
					"eaf1.cardamage.tyreblisters.rearleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyreblisters_rearright,
				{
					"Car damage tyre blisters rear right",
					"eaf1.cardamage.tyreblisters.rearright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyreblisters_frontleft,
				{
					"Car damage tyre blisters front left",
					"eaf1.cardamage.tyreblisters.frontleft",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_tyreblisters_frontright,
				{
					"Car damage tyre blisters front right",
					"eaf1.cardamage.tyreblisters.frontright",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_frontleftwingdamage,
				{
					"Car damage front left wing damage",
					"eaf1.cardamage.frontleftwingdamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_frontrightwingdamage,
				{
					"Car damage front right wing damage",
					"eaf1.cardamage.frontrightwingdamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_rearwingdamage,
				{
					"Car damage rear wing damage",
					"eaf1.cardamage.rearwingdamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_floordamage,
				{
					"Car damage floor damage",
					"eaf1.cardamage.floordamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_diffuserdamage,
				{
					"Car damage diffuser damage",
					"eaf1.cardamage.diffuserdamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_sidepoddamage,
				{
					"Car damage sidepod damage",
					"eaf1.cardamage.sidepoddamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_drsfault,
				{
					"Car damage DRS fault",
					"eaf1.cardamage.drsfault",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_ersfault,
				{
					"Car damage ERS fault",
					"eaf1.cardamage.ersfault",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_gearboxdamage,
				{
					"Car damage gearbox damage",
					"eaf1.cardamage.gearboxdamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_enginedamage,
				{
					"Car damage engine damage",
					"eaf1.cardamage.enginedamage",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_enginemguhwear,
				{
					"Car damage engine MGUH wear",
					"eaf1.cardamage.enginemguhwear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_engineeswear,
				{
					"Car damage engine ES wear",
					"eaf1.cardamage.engineeswear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_enginecewear,
				{
					"Car damage engine CE wear",
					"eaf1.cardamage.enginecewear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_engineicewear,
				{
					"Car damage engine ICE wear",
					"eaf1.cardamage.engineicewear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_enginemgukwear,
				{
					"Car damage engine MGUK wear",
					"eaf1.cardamage.enginemgukwear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_enginetcwear,
				{
					"Car damage engine TC wear",
					"eaf1.cardamage.enginetcwear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_engineblown,
				{
					"Car damage engine blown",
					"eaf1.cardamage.engineblown",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_cardamage_engineseized,
				{
					"Car damage engine seized",
					"eaf1.cardamage.engineseized",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Tyresets packet

			{
				&hf_eaf1_tyresets_vehicleindex,
				{
					"Tyresets vehicle index",
					"eaf1.tyresets.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_fittedindex,
				{
					"Tyresets fitted index",
					"eaf1.tyresets.fittedindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset,
				{
					"Tyresets tyreset",
					"eaf1.tyresets.tyreset",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_actualtyrecompound,
				{
					"Tyresets tyreset actual tyre compound",
					"eaf1.tyresets.tyreset.actualtyrecompound",
					FT_UINT8,
					BASE_DEC,
					VALS(actualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_visualtyrecompound,
				{
					"Tyresets tyreset visual tyre compound",
					"eaf1.tyresets.tyreset.visualtyrecompound",
					FT_UINT8,
					BASE_DEC,
					VALS(visualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_wear,
				{
					"Tyresets tyreset wear",
					"eaf1.tyresets.tyreset.wear",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_available,
				{
					"Tyresets tyreset available",
					"eaf1.tyresets.tyreset.available",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_recommendedsession,
				{
					"Tyresets tyreset recommended session",
					"eaf1.tyresets.tyreset.recommendedsession",
					FT_UINT8,
					BASE_DEC,
					VALS(sessiontypenames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_lifespan,
				{
					"Tyresets tyreset life span",
					"eaf1.tyresets.tyreset.lifespan",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_usablelife,
				{
					"Tyresets tyreset usable life",
					"eaf1.tyresets.tyreset.usablelife",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_lapdeltatime,
				{
					"Tyresets tyreset lap delta time",
					"eaf1.tyresets.tyreset.lapdeltatime",
					FT_INT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_tyresets_tyreset_fitted,
				{
					"Tyresets tyreset fitted",
					"eaf1.tyresets.tyreset.fitted",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// LapPositions packet

			{
				&hf_eaf1_lappositions_numlaps,
				{
					"Lap positions num laps",
					"eaf1.lappositions.numlaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lappositions_lapstart,
				{
					"Lap positions lap start",
					"eaf1.lappositions.lapstart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lappositions_lap,
				{
					"Lap positions lap",
					"eaf1.lappositions.lap",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lappositions_position,
				{
					"Lap positions position",
					"eaf1.lappositions.position",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Session history packet

			{
				&hf_eaf1_sessionhistory_caridx,
				{
					"Session history vehicle index",
					"eaf1.sessionhistory.vehicleindex",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_numlaps,
				{
					"Session history num laps",
					"eaf1.sessionhistory.numlaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_numtyrestints,
				{
					"Session history num tyre stints",
					"eaf1.sessionhistory.numtyrestints",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_bestlaptimelapnum,
				{
					"Session history best lap time lap num",
					"eaf1.sessionhistory.bestlaptimelapnum",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_bestsector1lapnum,
				{
					"Session history best sector 1 lap num",
					"eaf1.sessionhistory.bestsector1lapnum",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_bestsector2lapnum,
				{
					"Session history best sector 2 lap num",
					"eaf1.sessionhistory.bestsector2lapnum",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_bestsector3lapnum,
				{
					"Session history best sector 3 lap num",
					"eaf1.sessionhistory.bestsector3lapnum",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lap,
				{
					"Session history lap",
					"eaf1.sessionhistory.lap",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_laptime,
				{
					"Session history lap time",
					"eaf1.sessionhistory.lap.laptime",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector1time,
				{
					"Session history lap sector 1 time",
					"eaf1.sessionhistory.lap.sector1time",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector1timemspart,
				{
					"Session history lap sector 1 time mS part",
					"sessionhistory.lap.sector1timemspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector1timeminutespart,
				{
					"Session history lap sector 1 time minutes part",
					"sessionhistory.lap.sector1timeminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector2time,
				{
					"Session history lap sector 2 time",
					"eaf1.sessionhistory.lap.sector2time",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector2timemspart,
				{
					"Session history lap sector 2 time mS part",
					"sessionhistory.lap.sector2timemspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector2timeminutespart,
				{
					"Session history lap sector 2 time minutes part",
					"sessionhistory.lap.sector2timeminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector3time,
				{
					"Session history lap sector 3 time",
					"eaf1.sessionhistory.lap.sector3time",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector3timemspart,
				{
					"Session history lap sector 3 time mS part",
					"sessionhistory.lap.sector3timemspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_sector3timeminutespart,
				{
					"Session history lap sector 3 time minutes part",
					"sessionhistory.lap.sector3timeminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lapvalidbitflags,
				{
					"Session history lap lap valid bit flags",
					"eaf1.sessionhistory.lap.lapvalidbitflags",
					FT_UINT8,
					BASE_HEX,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lapvalidbitflags_lap,
				{
					"Lap",
					"eaf1.sessionhistory.lap.lapvalidbitflags.lap",
					FT_BOOLEAN,
					4,
					NULL,
					0x01,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector1,
				{
					"Sector 1",
					"eaf1.sessionhistory.lap.lapvalidbitflags.sector1",
					FT_BOOLEAN,
					4,
					NULL,
					0x02,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector2,
				{
					"Sector 2",
					"eaf1.sessionhistory.lap.lapvalidbitflags.sector2",
					FT_BOOLEAN,
					4,
					NULL,
					0x04,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector3,
				{
					"Sector 3",
					"eaf1.sessionhistory.lap.lapvalidbitflags.sector3",
					FT_BOOLEAN,
					4,
					NULL,
					0x08,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_tyrestint,
				{
					"Session history tyre stint",
					"eaf1.sessionhistory.tyrestint",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_endlap,
				{
					"Session history end lap",
					"eaf1.sessionhistory.endlap",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_tyreactualcompound,
				{
					"Session history tyre actual compound",
					"eaf1.sessionhistory.tyreactualcompound",
					FT_UINT8,
					BASE_DEC,
					VALS(actualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_sessionhistory_tyrevisualcompound,
				{
					"Session history tyre visual compound",
					"eaf1.sessionhistory.tyrevisualcompound",
					FT_UINT8,
					BASE_DEC,
					VALS(visualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Final classification packet

			{
				&hf_eaf1_finalclassification_numcars,
				{
					"Final classification num cars",
					"eaf1.finalclassification.numcars",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_drivername,
				{
					"Final classification driver name",
					"eaf1.finalclassification.drivername",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_position,
				{
					"Final classification position",
					"eaf1.finalclassification.position",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_numlaps,
				{
					"Final classification num laps",
					"eaf1.finalclassification.numlaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_gridposition,
				{
					"Final classification grid position",
					"eaf1.finalclassification.gridposition",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_points,
				{
					"Final classification points",
					"eaf1.finalclassification.points",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_numpitstops,
				{
					"Final classification num pit stops",
					"eaf1.finalclassification.numpitstops",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_resultstatus,
				{
					"Final classification result status",
					"eaf1.finalclassification.resultstatus",
					FT_UINT8,
					BASE_DEC,
					VALS(resultstatusnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_resultreason,
				{
					"Final classification result reason",
					"eaf1.finalclassification.resultreason",
					FT_UINT8,
					BASE_DEC,
					VALS(resultreasonnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_bestlaptimeinms,
				{
					"Final classification best lap time in mS",
					"eaf1.finalclassification.bestlaptimeinms",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_totalracetime,
				{
					"Final classification total race time",
					"eaf1.finalclassification.totalracetime",
					FT_DOUBLE,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_penaltiestime,
				{
					"Final classification penalties time",
					"eaf1.finalclassification.penaltiestime",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_numpenalties,
				{
					"Final classification num penalties",
					"eaf1.finalclassification.numenalties",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_numtyrestints,
				{
					"Final classification num tyre stints",
					"eaf1.finalclassification.numtyrestints",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_tyrestint,
				{
					"Final classification tyre stint",
					"eaf1.finalclassification.tyrestint",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_tyrestint_actual,
				{
					"Final classification tyre stint actual",
					"eaf1.finalclassification.tyrestint.actual",
					FT_UINT8,
					BASE_DEC,
					VALS(actualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_tyrestint_visual,
				{
					"Final classification tyre stint visual",
					"eaf1.finalclassification.tyrestint.visual",
					FT_UINT8,
					BASE_DEC,
					VALS(visualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_finalclassification_tyrestint_endlaps,
				{
					"Final classification tyre stint end lap",
					"eaf1.finalclassification.tyrestint.endlaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Car status packet

			{
				&hf_eaf1_carstatus_drivername,
				{
					"Car status driver name",
					"eaf1.carstatus.drivername",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_tractioncontrol,
				{
					"Car status traction control",
					"eaf1.carstatus.tractioncontrol",
					FT_UINT8,
					BASE_DEC,
					VALS(tractioncontrolnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_antilockbrakes,
				{
					"Car status anti lock brakes",
					"eaf1.carstatus.antilockbrakes",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_fuelmix,
				{
					"Car status fuel mix",
					"eaf1.carstatus.fuelmix",
					FT_UINT8,
					BASE_DEC,
					VALS(fuelmixnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_frontbrakebias,
				{
					"Car status front brake bias",
					"eaf1.carstatus.frontbrakebias",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_pitlimiterstatus,
				{
					"Car status pit limiter status",
					"eaf1.carstatus.pitlimiterstatus",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_fuelintank,
				{
					"Car status fuel in tank",
					"eaf1.carstatus.fuelintank",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_fuelcapacity,
				{
					"Car status fuel capacity",
					"eaf1.carstatus.fuelcapacity",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_fuelremaininglaps,
				{
					"Car status fuel remaining laps",
					"eaf1.carstatus.fuelremaininglaps",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_maxrpm,
				{
					"Car status max RPM",
					"eaf1.carstatus.maxrpm",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_idlerpm,
				{
					"Car status idle RPM",
					"eaf1.carstatus.idlerpm",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_maxgears,
				{
					"Car status max gears",
					"eaf1.carstatus.maxgears",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_drsallowed,
				{
					"Car status DRS allowed",
					"eaf1.carstatus.drsallowed",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_drsactivationdistance,
				{
					"Car status DRS activation distance",
					"eaf1.carstatus.drsactivationdistance",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_actualtyrecompound,
				{
					"Car status actual tyre compound",
					"eaf1.carstatus.actualtyrecompound",
					FT_UINT8,
					BASE_DEC,
					VALS(actualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_visualtyrecompound,
				{
					"Car status visual tyre compound",
					"eaf1.carstatus.visualtyrecompound",
					FT_UINT8,
					BASE_DEC,
					VALS(visualtyrecompoundnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_tyresagelaps,
				{
					"Car status tyres age laps",
					"eaf1.carstatus.tyresagelaps",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_vehiclefiaflags,
				{
					"Car status vehicle FIA flags",
					"eaf1.carstatus.vehiclefiaflags",
					FT_INT8,
					BASE_DEC,
					VALS(flagnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_enginepowerice,
				{
					"Car status engine power ICE",
					"eaf1.carstatus.enginepowerice",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_enginepowermguk,
				{
					"Car status engine power MGUK",
					"eaf1.carstatus.enginepowermguk",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_ersstoreenergy,
				{
					"Car status ERS store energy",
					"eaf1.carstatus.ersstoreenergy",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_ersdeploymode,
				{
					"Car status ERS deployMode",
					"eaf1.carstatus.ersdeploymode",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_ersharvestedthislapmguk,
				{
					"Car status ERS harvested this lap MGUK",
					"eaf1.carstatus.ersharvestedthislapmguk",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_ersharvestedthislapmguh,
				{
					"Car status ERS harvested this lap MGUH",
					"eaf1.carstatus.ersharvestedthislapmguh",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_ersdeployedthislap,
				{
					"Car status ERS deployed this lap",
					"eaf1.carstatus.ersdeployedthislap",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_carstatus_networkpaused,
				{
					"Car status network paused",
					"eaf1.carstatus.networkpaused",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			// Lap data packet

			{
				&hf_eaf1_lapdata_drivername,
				{
					"Lap data driver name",
					"eaf1.lapdata.drivername",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_lastlaptimeinms,
				{
					"Lap data last lap time in mS",
					"eaf1.lapdata.lastlaptimeinms",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_currentlaptimeinms,
				{
					"Lap data current lap time in mS",
					"eaf1.lapdata.currentlaptimeinms",
					FT_UINT32,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector1time,
				{
					"Lap data sector 1 time",
					"eaf1.lapdata.lap.sector1time",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector1timemspart,
				{
					"Lap data sector 1 time mS part",
					"eaf1.lapdata.lap.sector1timemspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector1timeminutespart,
				{
					"Lap data sector 1 time minutes part",
					"eaf1.lapdata.lap.sector1timeminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector2time,
				{
					"Lap data sector 2 time",
					"eaf1.lapdata.lap.sector2time",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector2timemspart,
				{
					"Lap data sector 2 time mS part",
					"eaf1.lapdata.lap.sector2timemspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector2timeminutespart,
				{
					"Lap data sector 2 time minutes part",
					"eaf1.lapdata.lap.sector2timeminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatocarinfront,
				{
					"Lap data delta to car in front",
					"eaf1.lapdata.lap.deltatocarinfront",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatocarinfrontmspart,
				{
					"Lap data delta to car in front mS part",
					"eaf1.lapdata.lap.deltatocarinfrontmspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatocarinfrontminutespart,
				{
					"Lap data delta to car in front minutes part",
					"eaf1.lapdata.lap.deltatocarinfrontminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatoraceleader,
				{
					"Lap data delta to race leader",
					"eaf1.lapdata.lap.deltatoraceleader",
					FT_STRING,
					BASE_NONE,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatoraceleadermspart,
				{
					"Lap data delta to race leader mS part",
					"eaf1.lapdata.lap.deltatoraceleadermspart",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_deltatoraceleaderminutespart,
				{
					"Lap data delta to race leader minutes part",
					"eaf1.lapdata.lap.deltatoraceleaderminutespart",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_lapdistance,
				{
					"Lap data lap distance",
					"eaf1.lapdata.lapdistance",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_totaldistance,
				{
					"Lap data total distance",
					"eaf1.lapdata.totaldistance",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_safetycardelta,
				{
					"Lap data safety car delta",
					"eaf1.lapdata.safetycardelta",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_carposition,
				{
					"Lap data car position",
					"eaf1.lapdata.carposition",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_currentlapnum,
				{
					"Lap data current lap num",
					"eaf1.lapdata.currentlapnum",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_pitstatus,
				{
					"Lap data pit status",
					"eaf1.lapdata.pitstatus",
					FT_UINT8,
					BASE_DEC,
					VALS(pitstatusnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_numpitstops,
				{
					"Lap data num pit stops",
					"eaf1.lapdata.numpitstops",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_sector,
				{
					"Lap data sector",
					"eaf1.lapdata.sector",
					FT_UINT8,
					BASE_DEC,
					VALS(sectornames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_currentlapinvalid,
				{
					"Lap data current lap invalid",
					"eaf1.lapdata.currentlapinvalid",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_penalties,
				{
					"Lap data penalties",
					"eaf1.lapdata.penalties",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_totalwarnings,
				{
					"Lap data total warnings",
					"eaf1.lapdata.totalwarnings",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_cornercuttingwarnings,
				{
					"Lap data corner cutting warnings",
					"eaf1.lapdata.cornercuttingwarnings",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_numunserveddrivethroughpens,
				{
					"Lap data num unserved drive through pens",
					"eaf1.lapdata.numunserveddrivethroughpens",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_numunservedstopgopens,
				{
					"Lap data num unserved stop go pens",
					"eaf1.lapdata.numunservedstopgopens",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_gridposition,
				{
					"Lap data grid position",
					"eaf1.lapdata.gridposition",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_driverstatus,
				{
					"Lap data driver status",
					"eaf1.lapdata.driverstatus",
					FT_UINT8,
					BASE_DEC,
					VALS(driverstatusnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_resultstatus,
				{
					"Lap data result status",
					"eaf1.lapdata.resultstatus",
					FT_UINT8,
					BASE_DEC,
					VALS(resultstatusnames),
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_pitlanetimeractive,
				{
					"Lap data pitLane timer active",
					"eaf1.lapdata.pitlanetimeractive",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_pitlanetimeinlaneinms,
				{
					"Lap data pit lane time in lane in mS",
					"eaf1.lapdata.pitlanetimeinlaneinms",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_pitstoptimerinms,
				{
					"Lap data pit stop timer in mS",
					"eaf1.lapdata.pitstoptimerinms",
					FT_UINT16,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_pitstopshouldservepen,
				{
					"Lap data pit stop should serve pen",
					"eaf1.lapdata.pitstopshouldservepen",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_speedtrapfastestspeed,
				{
					"Lap data speed trap fastest speed",
					"eaf1.lapdata.speedtrapfastestspeed",
					FT_FLOAT,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_speedtrapfastestlap,
				{
					"Lap data speed trap fastest lap",
					"eaf1.lapdata.speedtrapfastestlap",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_timetrialpbcaridx,
				{
					"Lap data time trial PB car index",
					"eaf1.lapdata.timetrialpbcaridx",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},

			{
				&hf_eaf1_lapdata_timetrialrivalcaridx,
				{
					"Lap data time trial rival car index",
					"eaf1.lapdata.timetrialrivalcaridx",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					NULL, //'Blurb'
					HFILL,
				},
			},
		};

		/* Setup protocol subtree array */

		static int *
			ett[] = {
				&ett_eaf1,
				&ett_eaf1_version,
				&ett_eaf1_packetid,
				&ett_eaf1_lobbyinfo_numplayers,
				&ett_eaf1_lobbyinfo_player_name,
				&ett_eaf1_event_eventcode,
				&ett_eaf1_event_buttonstatus,
				&ett_eaf1_participants_player_name,
				&ett_eaf1_participants_livery_colour,
				&ett_eaf1_session_nummarshalzones,
				&ett_eaf1_session_marshalzone,
				&ett_eaf1_session_numweatherforecastsamples,
				&ett_eaf1_session_weatherforecastsample,
				&ett_eaf1_session_numsessionsinweekend,
				&ett_eaf1_cardamage_drivername,
				&ett_eaf1_cardamage_tyrewear,
				&ett_eaf1_cardamage_tyredamage,
				&ett_eaf1_cardamage_brakesdamage,
				&ett_eaf1_cardamage_tyreblisters,
				&ett_eaf1_tyresets_vehicleindex,
				&ett_eaf1_tyresets_tyreset,
				&ett_eaf1_lappositions_lap,
				&ett_eaf1_sessionhistory_vehicleindex,
				&ett_eaf1_sessionhistory_numlaps,
				&ett_eaf1_sessionhistory_lap,
				&ett_eaf1_sessionhistory_sector1time,
				&ett_eaf1_sessionhistory_sector2time,
				&ett_eaf1_sessionhistory_sector3time,
				&ett_eaf1_sessionhistory_lapvalidbitflags,
				&ett_eaf1_sessionhistory_numtyrestints,
				&ett_eaf1_sessionhistory_tyrestint,
				&ett_eaf1_finalclassification_drivername,
				&ett_eaf1_finalclassification_numstints,
				&ett_eaf1_finalclassification_tyrestint,
				&ett_eaf1_carstatus_drivername,
				&ett_eaf1_lapdata_drivername,
				&ett_eaf1_lapdata_sector1time,
				&ett_eaf1_lapdata_sector2time,
				&ett_eaf1_lapdata_deltatocarinfront,
				&ett_eaf1_lapdata_deltatoraceleader,
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

		e1f1_f125_event_code_dissector_table = register_dissector_table("e1f1.f125.event.code",
																		"EAF1 F125 Event Code",
																		proto_eaf1, FT_STRING,
																		BASE_NONE);
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

		dissector_add_uint("eaf1.f125packetid", eF125PacketIdLobbyInfo, create_dissector_handle(dissect_eaf1_2025_lobbyinfo, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdEvent, create_dissector_handle(dissect_eaf1_2025_event, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdParticipants, create_dissector_handle(dissect_eaf1_2025_participants, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdSession, create_dissector_handle(dissect_eaf1_2025_session, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdCarDamage, create_dissector_handle(dissect_eaf1_2025_cardamage, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdTyreSets, create_dissector_handle(dissect_eaf1_2025_tyresets, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdLapPositions, create_dissector_handle(dissect_eaf1_2025_lappositions, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdSessionHistory, create_dissector_handle(dissect_eaf1_2025_sessionhistory, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdFinalClassification, create_dissector_handle(dissect_eaf1_2025_finalclassification, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdCarStatus, create_dissector_handle(dissect_eaf1_2025_carstatus, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", eF125PacketIdLapData, create_dissector_handle(dissect_eaf1_2025_lapdata, proto_eaf1));

		dissector_add_string("e1f1.f125.event.code", eaf1_F125SessionStartedEventCode, create_dissector_handle(dissect_eaf1_2025_event_sessionstarted, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125SessionEndedEventCode, create_dissector_handle(dissect_eaf1_2025_event_sessionended, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125FastestLapEventCode, create_dissector_handle(dissect_eaf1_2025_event_fastestlap, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125RetirementEventCode, create_dissector_handle(dissect_eaf1_2025_event_retirement, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125DRSEnabledEventCode, create_dissector_handle(dissect_eaf1_2025_event_drsenabled, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125DRSDisabledEventCode, create_dissector_handle(dissect_eaf1_2025_event_drsdisabled, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125TeamMateInPitsEventCode, create_dissector_handle(dissect_eaf1_2025_event_teammateinpits, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125ChequeredFlagEventCode, create_dissector_handle(dissect_eaf1_2025_event_chequeredflag, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125RaceWinnerEventCode, create_dissector_handle(dissect_eaf1_2025_event_racewinner, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125PenaltyEventCode, create_dissector_handle(dissect_eaf1_2025_event_penalty, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125SpeedTrapEventCode, create_dissector_handle(dissect_eaf1_2025_event_speedtrap, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125StartLightsEventCode, create_dissector_handle(dissect_eaf1_2025_event_startlights, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125LightsOutEventCode, create_dissector_handle(dissect_eaf1_2025_event_lightsout, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125DriveThroughServedEventCode, create_dissector_handle(dissect_eaf1_2025_event_drivethroughserved, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125StopGoServedEventCode, create_dissector_handle(dissect_eaf1_2025_event_stopgoserved, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125FlashbackEventCode, create_dissector_handle(dissect_eaf1_2025_event_flashback, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125ButtonStatusEventCode, create_dissector_handle(dissect_eaf1_2025_event_button, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125RedFlagEventCode, create_dissector_handle(dissect_eaf1_2025_event_redflag, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125OvertakeEventCode, create_dissector_handle(dissect_eaf1_2025_event_overtake, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125SafetyCarEventCode, create_dissector_handle(dissect_eaf1_2025_event_safetycar, proto_eaf1));
		dissector_add_string("e1f1.f125.event.code", eaf1_F125CollisionEventCode, create_dissector_handle(dissect_eaf1_2025_event_collision, proto_eaf1));

		// 6 - cartelemetry
		// 5 - carsetups
		// 0 - motion
		// 13 - motionex
		// 14 - timetrial
	}
}
