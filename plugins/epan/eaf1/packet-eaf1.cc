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

#include "eaf1-helpers.h"

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
};

static const value_string networkgamenames[] = {
	{0, "Offline"},
	{1, "Online"},
};

static const value_string safetycartypenames[] = {
	{0, "No Safety Car"},
	{1, "Full Safety Car"},
	{2, "Virtual Safety Car"},
	{3, "Formation Lap"},
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

static const value_string weathernames[] = {
	{0, "Clear"},
	{1, "Light cloud"},
	{2, "Overcast"},
	{3, "Light rain"},
	{4, "Heavy rain"},
	{5, "Storm"},
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
};

static const value_string forecastaccuracynames[] = {
	{0, "Perfect"},
	{1, "Approximate"},
};

static const value_string brakingassistnames[] = {
	{0, "Off"},
	{1, "Low"},
	{2, "Medium"},
	{3, "High"},
};

static const value_string gearboxassistnames[] = {
	{1, "Manual"},
	{2, "Manual & suggested gear"},
	{3, "Auto"},
};

static const value_string dynamicracinglinenames[] = {
	{0, "Off"},
	{1, "Corners only"},
	{2, "Full"},
};

static const value_string dynamicracinglinetypenames[] = {
	{0, "2D"},
	{1, "3D"},
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
};

static const value_string rulesetnames[] = {
	{0, "Practice & Qualifying"},
	{1, "Race"},
	{2, "Time Trial"},
	{12, "Elimination"},
};

static const value_string sessionlengthnames[] = {
	{0, "None"},
	{2, "Very short"},
	{3, "Short"},
	{4, "Medium"},
	{5, "Medium Long"},
	{6, "Long"},
	{7, "Full"},
};

static const value_string speedunitsnames[] = {
	{0, "MPH"},
	{1, "KPH"},
};

static const value_string temperatureunitsnames[] = {
	{0, "Celsius"},
	{1, "Fahrenheit"},
};

static const value_string recoverymodenames[] = {
	{0, "None"},
	{1, "Flashbacks"},
	{2, "Auto - recovery"},
};

static const value_string flashbacklimitnames[] = {
	{0, "Low"},
	{1, "Medium"},
	{2, "High"},
	{3, "Unlimited"},
};

static const value_string surfacetypenames[] = {
	{0, "Simplified"},
	{1, "Realistic"},
};

static const value_string lowfuelmodenames[] = {
	{0, "Easy"},
	{1, "Hard"},
};

static const value_string racestartsnames[] = {
	{0, "Manual"},
	{1, "Assisted"},
};

static const value_string tyretemperaturenames[] = {
	{0, "Surface only"},
	{1, "Surface & Carcass"},
};

static const value_string pitlanetyresimnames[] = {
	{0, "On"},
	{1, "Off"},
};

static const value_string cardamagenames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Simulation"},
};

static const value_string cardamageratenames[] = {
	{0, "Reduced"},
	{1, "Standard"},
	{2, "Simulation"},
};

static const value_string collisionsnames[] = {
	{0, "Off"},
	{1, "Player - to - Player Off"},
	{2, "On"},
};

static const value_string mpunsafepitreleasenames[] = {
	{0, "On"},
	{1, "Off (Multiplayer)"},
};

static const value_string cornercuttingstringencynames[] = {
	{0, "Regular"},
	{1, "Strict"},
};

static const value_string pitstopexperiencenames[] = {
	{0, "Automatic"},
	{1, "Broadcast"},
	{2, "Immersive"},
};

static const value_string safetycarnames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Increased"},
};

static const value_string safetycarexperiencenames[] = {
	{0, "Broadcast"},
	{1, "Immersive"},
};

static const value_string formationlapexperiencenames[] = {
	{0, "Broadcast"},
	{1, "Immersive"},
};

static const value_string redflagnames[] = {
	{0, "Off"},
	{1, "Reduced"},
	{2, "Standard"},
	{3, "Increased"},
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
};

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
		auto next_tvb = tvb_new_subset_remaining(tvb, sizeof(F125::PacketHeader));

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
	col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "%d", tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_packetId))));

	uint8_t eaf1_packet_id = tvb_get_uint8(tvb, offsetof(F124::PacketHeader, m_packetId));

	if (!dissector_try_uint_new(eaf1_f125_packet_id_dissector_table,
								eaf1_packet_id, tvb, pinfo, tree,
								false, tree))
	{
		auto next_tvb = tvb_new_subset_remaining(tvb, sizeof(F125::PacketHeader));

		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int dissect_eaf1_2025_lobbyinfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
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

static int dissect_eaf1_2025_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketEventData))
	{
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

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_fastestlap_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.FastestLap.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_fastestlap_laptime, tvb, offsetof(F125::PacketEventData, m_eventDetails.FastestLap.lapTime), sizeof(float), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_retirementEventCode))
		{
			proto_item_set_text(event_code_ti, "Retirement");

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_retirement_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Retirement.vehicleIdx));
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

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_teammateinpits_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.TeamMateInPits.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_chequeredFlagEventCode))
		{
			proto_item_set_text(event_code_ti, "Chequered flag");

			// No data for this event type
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_raceWinnerEventCode))
		{
			proto_item_set_text(event_code_ti, "Race winner");

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_racewinner_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.RaceWinner.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_penaltyEventCode))
		{
			proto_item_set_text(event_code_ti, "Penalty");

			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_penaltytype, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.penaltyType), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_infringementtype, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.infringementType), sizeof(uint8), ENC_LITTLE_ENDIAN);
			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_penalty_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.vehicleIdx));
			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_penalty_othervehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.otherVehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_time, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.time), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_lapnumber, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.lapNum), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_penalty_placesgained, tvb, offsetof(F125::PacketEventData, m_eventDetails.Penalty.placesGained), sizeof(uint8), ENC_LITTLE_ENDIAN);
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_speedTrapEventCode))
		{
			proto_item_set_text(event_code_ti, "Speed trap");

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_speedtrap_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.vehicleIdx));
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_speed, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.speed), sizeof(float), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_isoverallfastestinsession, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.isOverallFastestInSession), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_event_code_tree, hf_eaf1_event_speedtrap_isdriverfastestinsession, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.isDriverFastestInSession), sizeof(uint8), ENC_LITTLE_ENDIAN);
			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_speedtrap_fastestvehicleindexinsession, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.SpeedTrap.fastestVehicleIdxInSession));
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

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_drivethroughpenaltyserved_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.DriveThroughPenaltyServed.vehicleIdx));
		}
		else if (0 == strcmp(EventCode, F125::PacketEventData::cs_stopGoServedEventCode))
		{
			proto_item_set_text(event_code_ti, "Stop go penalty served");

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_stopgopenaltyserved_vehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.StopGoPenaltyServed.vehicleIdx));
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

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_overtake_overtakingvehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Overtake.overtakingVehicleIdx));
			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_overtake_overtakenvehicleindex, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Overtake.beingOvertakenVehicleIdx));
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

			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_collision_vehicle1index, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Collision.vehicle1Idx));
			add_vehicle_index_and_name(proto_eaf1, eaf1_event_code_tree, hf_eaf1_event_collision_vehicle2index, pinfo, tvb, offsetof(F125::PacketEventData, m_eventDetails.Collision.vehicle2Idx));
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_participants(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketParticipantsData))
	{
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

		uint32_t active_cars;

		proto_tree_add_item_ret_uint(tree, hf_eaf1_participants_activecars, tvb, offsetof(F125::PacketParticipantsData, m_numActiveCars), 1, ENC_LITTLE_ENDIAN, &active_cars);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Participants: %d active", active_cars));

		for (std::remove_const<decltype(F125::cs_maxNumCarsInUDPData)>::type participant = 0; participant < F125::cs_maxNumCarsInUDPData; participant++)
		{
			auto participant_offset = offsetof(F125::PacketParticipantsData, m_participants) + participant * sizeof(F125::ParticipantData);

			auto player_name_ti = proto_tree_add_item(tree, hf_eaf1_participants_name, tvb, participant_offset + offsetof(F125::ParticipantData, m_name), F125::cs_maxParticipantNameLen, ENC_UTF_8);
			proto_tree *eaf1_player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_participants_player_name);

			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_aicontrolled, tvb, participant_offset + offsetof(F125::ParticipantData, m_aiControlled), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_driverid, tvb, participant_offset + offsetof(F125::ParticipantData, m_driverId), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_networkid, tvb, participant_offset + offsetof(F125::ParticipantData, m_networkId), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_teamid, tvb, participant_offset + offsetof(F125::ParticipantData, m_teamId), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_myteam, tvb, participant_offset + offsetof(F125::ParticipantData, m_myTeam), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_racenumber, tvb, participant_offset + offsetof(F125::ParticipantData, m_raceNumber), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_nationality, tvb, participant_offset + offsetof(F125::ParticipantData, m_nationality), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_yourtelemetry, tvb, participant_offset + offsetof(F125::ParticipantData, m_yourTelemetry), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_showonlinenames, tvb, participant_offset + offsetof(F125::ParticipantData, m_showOnlineNames), sizeof(uint8), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_techlevel, tvb, participant_offset + offsetof(F125::ParticipantData, m_techLevel), sizeof(uint16), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(eaf1_player_name_tree, hf_eaf1_participants_platform, tvb, participant_offset + offsetof(F125::ParticipantData, m_platform), sizeof(uint8), ENC_LITTLE_ENDIAN);

			uint32_t num_colours;
			auto num_colours_ti = proto_tree_add_item_ret_uint(eaf1_player_name_tree, hf_eaf1_participants_numcolours, tvb, participant_offset + offsetof(F125::ParticipantData, m_numColours), sizeof(uint8), ENC_LITTLE_ENDIAN, &num_colours);
			proto_tree *eaf1_num_colours_tree = proto_item_add_subtree(num_colours_ti, ett_eaf1_participants_numcolours);

			for (uint32_t colour = 0; colour < num_colours; colour++)
			{
				auto livery_offset = participant_offset + offsetof(F125::ParticipantData, m_liveryColours) + colour * sizeof(F125::LiveryColour);

				auto livery_colour_ti = proto_tree_add_item(eaf1_num_colours_tree, hf_eaf1_participants_liverycolour, tvb, 0, 0, ENC_LITTLE_ENDIAN);
				proto_tree *eaf1_livery_colour_tree = proto_item_add_subtree(livery_colour_ti, ett_eaf1_participants_livery_colour);

				uint32_t red;
				uint32_t green;
				uint32_t blue;

				proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_red, tvb, livery_offset + offsetof(F125::LiveryColour, red), sizeof(uint8), ENC_LITTLE_ENDIAN, &red);
				proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_green, tvb, livery_offset + offsetof(F125::LiveryColour, green), sizeof(uint8), ENC_LITTLE_ENDIAN, &green);
				proto_tree_add_item_ret_uint(eaf1_livery_colour_tree, hf_eaf1_participants_liverycolour_blue, tvb, livery_offset + offsetof(F125::LiveryColour, blue), sizeof(uint8), ENC_LITTLE_ENDIAN, &blue);

				proto_item_append_text(livery_colour_ti, " (0x%02x%02x%02x)", red, green, blue);
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketSessionData))
	{
		proto_tree_add_item(tree, hf_eaf1_session_weather, tvb, offsetof(F125::PacketSessionData, m_weather), sizeof(F125::PacketSessionData::m_weather), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_tracktemperature, tvb, offsetof(F125::PacketSessionData, m_trackTemperature), sizeof(F125::PacketSessionData::m_trackTemperature), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_airtemperature, tvb, offsetof(F125::PacketSessionData, m_airTemperature), sizeof(F125::PacketSessionData::m_airTemperature), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_totallaps, tvb, offsetof(F125::PacketSessionData, m_totalLaps), sizeof(F125::PacketSessionData::m_totalLaps), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_tracklength, tvb, offsetof(F125::PacketSessionData, m_trackLength), sizeof(F125::PacketSessionData::m_trackLength), ENC_LITTLE_ENDIAN);

		uint32_t session_type;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_session_sessiontype, tvb, offsetof(F125::PacketSessionData, m_sessionType), sizeof(F125::PacketSessionData::m_sessionType), ENC_LITTLE_ENDIAN, &session_type);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session (%s)", val_to_str(session_type, sessiontypenames, "Invalid session %u")));

		proto_tree_add_item(tree, hf_eaf1_session_trackid, tvb, offsetof(F125::PacketSessionData, m_trackId), sizeof(F125::PacketSessionData::m_trackId), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_formula, tvb, offsetof(F125::PacketSessionData, m_formula), sizeof(F125::PacketSessionData::m_formula), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_sessiontimeleft, tvb, offsetof(F125::PacketSessionData, m_sessionTimeLeft), sizeof(F125::PacketSessionData::m_sessionTimeLeft), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_sessionduration, tvb, offsetof(F125::PacketSessionData, m_sessionDuration), sizeof(F125::PacketSessionData::m_sessionDuration), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitspeedlimit, tvb, offsetof(F125::PacketSessionData, m_pitSpeedLimit), sizeof(F125::PacketSessionData::m_pitSpeedLimit), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_gamepaused, tvb, offsetof(F125::PacketSessionData, m_gamePaused), sizeof(F125::PacketSessionData::m_gamePaused), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_isspectating, tvb, offsetof(F125::PacketSessionData, m_isSpectating), sizeof(F125::PacketSessionData::m_isSpectating), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_spectatorcarindex, tvb, offsetof(F125::PacketSessionData, m_spectatorCarIndex), sizeof(F125::PacketSessionData::m_spectatorCarIndex), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_slipronativesupport, tvb, offsetof(F125::PacketSessionData, m_sliProNativeSupport), sizeof(F125::PacketSessionData::m_sliProNativeSupport), ENC_LITTLE_ENDIAN);

		uint32_t num_marshal_zones;

		auto num_marshal_zones_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_nummarshalzones, tvb, offsetof(F125::PacketSessionData, m_numMarshalZones), sizeof(F125::PacketSessionData::m_numMarshalZones), ENC_LITTLE_ENDIAN, &num_marshal_zones);
		auto num_marshal_zones_tree = proto_item_add_subtree(num_marshal_zones_ti, ett_eaf1_session_nummarshalzones);

		for (uint32_t zone = 0; zone < num_marshal_zones; zone++)
		{
			auto zone_offset = offsetof(F125::PacketSessionData, m_marshalZones) + zone * sizeof(F125::MarshalZone);

			auto marshal_zone_ti = proto_tree_add_item(num_marshal_zones_tree, hf_eaf1_session_marshalzone, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			proto_tree *marshal_zone_tree = proto_item_add_subtree(marshal_zone_ti, ett_eaf1_session_marshalzone);

			proto_tree_add_item(marshal_zone_tree, hf_eaf1_session_marshalzone_start, tvb, zone_offset + offsetof(F125::MarshalZone, m_zoneStart), sizeof(F125::MarshalZone::m_zoneStart), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(marshal_zone_tree, hf_eaf1_session_marshalzone_flag, tvb, zone_offset + offsetof(F125::MarshalZone, m_zoneFlag), sizeof(F125::MarshalZone::m_zoneFlag), ENC_LITTLE_ENDIAN);
		}

		proto_tree_add_item(tree, hf_eaf1_session_safetycarstatus, tvb, offsetof(F125::PacketSessionData, m_safetyCarStatus), sizeof(F125::PacketSessionData::m_safetyCarStatus), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_networkgame, tvb, offsetof(F125::PacketSessionData, m_networkGame), sizeof(F125::PacketSessionData::m_networkGame), ENC_LITTLE_ENDIAN);

		uint32_t num_weather_forecast_samples;
		auto num_weather_forecast_samples_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_numweatherforecastsamples, tvb, offsetof(F125::PacketSessionData, m_numWeatherForecastSamples), sizeof(F125::PacketSessionData::m_numWeatherForecastSamples), ENC_LITTLE_ENDIAN, &num_weather_forecast_samples);
		auto num_weather_forecast_samples_tree = proto_item_add_subtree(num_weather_forecast_samples_ti, ett_eaf1_session_numweatherforecastsamples);

		for (uint32_t sample = 0; sample < num_weather_forecast_samples; sample++)
		{
			auto sample_offset = offsetof(F125::PacketSessionData, m_weatherForecastSamples) + sample * sizeof(F125::WeatherForecastSample);

			auto weather_sample_ti = proto_tree_add_item(num_weather_forecast_samples_tree, hf_eaf1_session_weatherforecastsample, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			proto_tree *weather_sample_tree = proto_item_add_subtree(weather_sample_ti, ett_eaf1_session_weatherforecastsample);

			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_sessiontype, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_sessionType), sizeof(F125::WeatherForecastSample::m_sessionType), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_timeoffset, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_timeOffset), sizeof(F125::WeatherForecastSample::m_timeOffset), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_weather, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_weather), sizeof(F125::WeatherForecastSample::m_weather), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_tracktemperature, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_trackTemperature), sizeof(F125::WeatherForecastSample::m_trackTemperature), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_tracktemperaturechange, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_trackTemperatureChange), sizeof(F125::WeatherForecastSample::m_trackTemperatureChange), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_airtemperature, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_airTemperature), sizeof(F125::WeatherForecastSample::m_airTemperature), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_airtemperaturechange, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_airTemperatureChange), sizeof(F125::WeatherForecastSample::m_airTemperatureChange), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(weather_sample_tree, hf_eaf1_session_weatherforecastsample_rainpercentage, tvb, sample_offset + offsetof(F125::WeatherForecastSample, m_rainPercentage), sizeof(F125::WeatherForecastSample::m_rainPercentage), ENC_LITTLE_ENDIAN);
		}

		proto_tree_add_item(tree, hf_eaf1_session_forecastaccuracy, tvb, offsetof(F125::PacketSessionData, m_forecastAccuracy), sizeof(F125::PacketSessionData::m_forecastAccuracy), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_aidifficulty, tvb, offsetof(F125::PacketSessionData, m_aiDifficulty), sizeof(F125::PacketSessionData::m_aiDifficulty), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_seasonlinkidentifier, tvb, offsetof(F125::PacketSessionData, m_seasonLinkIdentifier), sizeof(F125::PacketSessionData::m_seasonLinkIdentifier), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_weekendlinkidentifier, tvb, offsetof(F125::PacketSessionData, m_weekendLinkIdentifier), sizeof(F125::PacketSessionData::m_weekendLinkIdentifier), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_sessionlinkidentifier, tvb, offsetof(F125::PacketSessionData, m_sessionLinkIdentifier), sizeof(F125::PacketSessionData::m_sessionLinkIdentifier), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitstopwindowideallap, tvb, offsetof(F125::PacketSessionData, m_pitStopWindowIdealLap), sizeof(F125::PacketSessionData::m_pitStopWindowIdealLap), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitstopwindowlatestlap, tvb, offsetof(F125::PacketSessionData, m_pitStopWindowLatestLap), sizeof(F125::PacketSessionData::m_pitStopWindowLatestLap), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitstoprejoinposition, tvb, offsetof(F125::PacketSessionData, m_pitStopRejoinPosition), sizeof(F125::PacketSessionData::m_pitStopRejoinPosition), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_steeringassist, tvb, offsetof(F125::PacketSessionData, m_steeringAssist), sizeof(F125::PacketSessionData::m_steeringAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_brakingassist, tvb, offsetof(F125::PacketSessionData, m_brakingAssist), sizeof(F125::PacketSessionData::m_brakingAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_gearboxassist, tvb, offsetof(F125::PacketSessionData, m_gearboxAssist), sizeof(F125::PacketSessionData::m_gearboxAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitassist, tvb, offsetof(F125::PacketSessionData, m_pitAssist), sizeof(F125::PacketSessionData::m_pitAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitreleaseassist, tvb, offsetof(F125::PacketSessionData, m_pitReleaseAssist), sizeof(F125::PacketSessionData::m_pitReleaseAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_ersassist, tvb, offsetof(F125::PacketSessionData, m_ERSAssist), sizeof(F125::PacketSessionData::m_ERSAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_drsassist, tvb, offsetof(F125::PacketSessionData, m_DRSAssist), sizeof(F125::PacketSessionData::m_DRSAssist), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_dynamicracingline, tvb, offsetof(F125::PacketSessionData, m_dynamicRacingLine), sizeof(F125::PacketSessionData::m_dynamicRacingLine), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_dynamicracinglinetype, tvb, offsetof(F125::PacketSessionData, m_dynamicRacingLineType), sizeof(F125::PacketSessionData::m_dynamicRacingLineType), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_gamemode, tvb, offsetof(F125::PacketSessionData, m_gameMode), sizeof(F125::PacketSessionData::m_gameMode), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_ruleset, tvb, offsetof(F125::PacketSessionData, m_ruleSet), sizeof(F125::PacketSessionData::m_ruleSet), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_timeofday, tvb, offsetof(F125::PacketSessionData, m_timeOfDay), sizeof(F125::PacketSessionData::m_timeOfDay), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_sessionlength, tvb, offsetof(F125::PacketSessionData, m_sessionLength), sizeof(F125::PacketSessionData::m_sessionLength), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_speedunitsleadplayer, tvb, offsetof(F125::PacketSessionData, m_speedUnitsLeadPlayer), sizeof(F125::PacketSessionData::m_speedUnitsLeadPlayer), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_temperatureunitsleadplayer, tvb, offsetof(F125::PacketSessionData, m_temperatureUnitsLeadPlayer), sizeof(F125::PacketSessionData::m_temperatureUnitsLeadPlayer), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_speedunitssecondaryplayer, tvb, offsetof(F125::PacketSessionData, m_speedUnitsSecondaryPlayer), sizeof(F125::PacketSessionData::m_speedUnitsSecondaryPlayer), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_temperatureunitssecondaryplayer, tvb, offsetof(F125::PacketSessionData, m_temperatureUnitsSecondaryPlayer), sizeof(F125::PacketSessionData::m_temperatureUnitsSecondaryPlayer), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_numsafetycarperiods, tvb, offsetof(F125::PacketSessionData, m_numSafetyCarPeriods), sizeof(F125::PacketSessionData::m_numSafetyCarPeriods), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_numvirtualsafetycarperiods, tvb, offsetof(F125::PacketSessionData, m_numVirtualSafetyCarPeriods), sizeof(F125::PacketSessionData::m_numVirtualSafetyCarPeriods), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_numredflagperiods, tvb, offsetof(F125::PacketSessionData, m_numRedFlagPeriods), sizeof(F125::PacketSessionData::m_numRedFlagPeriods), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_equalcarperformance, tvb, offsetof(F125::PacketSessionData, m_equalCarPerformance), sizeof(F125::PacketSessionData::m_equalCarPerformance), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_recoverymode, tvb, offsetof(F125::PacketSessionData, m_recoveryMode), sizeof(F125::PacketSessionData::m_recoveryMode), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_flashbacklimit, tvb, offsetof(F125::PacketSessionData, m_flashbackLimit), sizeof(F125::PacketSessionData::m_flashbackLimit), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_surfacetype, tvb, offsetof(F125::PacketSessionData, m_surfaceType), sizeof(F125::PacketSessionData::m_surfaceType), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_lowfuelmode, tvb, offsetof(F125::PacketSessionData, m_lowFuelMode), sizeof(F125::PacketSessionData::m_lowFuelMode), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_racestarts, tvb, offsetof(F125::PacketSessionData, m_raceStarts), sizeof(F125::PacketSessionData::m_raceStarts), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_tyretemperature, tvb, offsetof(F125::PacketSessionData, m_tyreTemperature), sizeof(F125::PacketSessionData::m_tyreTemperature), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitlanetyresim, tvb, offsetof(F125::PacketSessionData, m_pitLaneTyreSim), sizeof(F125::PacketSessionData::m_pitLaneTyreSim), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_cardamage, tvb, offsetof(F125::PacketSessionData, m_carDamage), sizeof(F125::PacketSessionData::m_carDamage), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_cardamagerate, tvb, offsetof(F125::PacketSessionData, m_carDamageRate), sizeof(F125::PacketSessionData::m_carDamageRate), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_collisions, tvb, offsetof(F125::PacketSessionData, m_collisions), sizeof(F125::PacketSessionData::m_collisions), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_collisionsoffforfirstlaponly, tvb, offsetof(F125::PacketSessionData, m_collisionsOffForFirstLapOnly), sizeof(F125::PacketSessionData::m_collisionsOffForFirstLapOnly), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_mpunsafepitrelease, tvb, offsetof(F125::PacketSessionData, m_mpUnsafePitRelease), sizeof(F125::PacketSessionData::m_mpUnsafePitRelease), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_mpoffforgriefing, tvb, offsetof(F125::PacketSessionData, m_mpOffForGriefing), sizeof(F125::PacketSessionData::m_mpOffForGriefing), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_cornercuttingstringency, tvb, offsetof(F125::PacketSessionData, m_cornerCuttingStringency), sizeof(F125::PacketSessionData::m_cornerCuttingStringency), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_parcfermerules, tvb, offsetof(F125::PacketSessionData, m_parcFermeRules), sizeof(F125::PacketSessionData::m_parcFermeRules), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_pitstopexperience, tvb, offsetof(F125::PacketSessionData, m_pitStopExperience), sizeof(F125::PacketSessionData::m_pitStopExperience), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_safetycar, tvb, offsetof(F125::PacketSessionData, m_safetyCar), sizeof(F125::PacketSessionData::m_safetyCar), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_safetycarexperience, tvb, offsetof(F125::PacketSessionData, m_safetyCarExperience), sizeof(F125::PacketSessionData::m_safetyCarExperience), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_formationlap, tvb, offsetof(F125::PacketSessionData, m_formationLap), sizeof(F125::PacketSessionData::m_formationLap), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_formationlapexperience, tvb, offsetof(F125::PacketSessionData, m_formationLapExperience), sizeof(F125::PacketSessionData::m_formationLapExperience), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_redflags, tvb, offsetof(F125::PacketSessionData, m_redFlags), sizeof(F125::PacketSessionData::m_redFlags), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_affectslicencelevelsolo, tvb, offsetof(F125::PacketSessionData, m_affectsLicenceLevelSolo), sizeof(F125::PacketSessionData::m_affectsLicenceLevelSolo), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_affectslicencelevelmp, tvb, offsetof(F125::PacketSessionData, m_affectsLicenceLevelMP), sizeof(F125::PacketSessionData::m_affectsLicenceLevelMP), ENC_LITTLE_ENDIAN);

		uint32_t num_sessions_in_weekend;
		auto num_sessions_in_weekend_ti = proto_tree_add_item_ret_uint(tree, hf_eaf1_session_numsessionsinweekend, tvb, offsetof(F125::PacketSessionData, m_numSessionsInWeekend), sizeof(F125::PacketSessionData::m_numSessionsInWeekend), ENC_LITTLE_ENDIAN, &num_sessions_in_weekend);
		auto num_sessions_in_weekend_tree = proto_item_add_subtree(num_sessions_in_weekend_ti, ett_eaf1_session_numsessionsinweekend);

		for (uint32_t session = 0; session < num_sessions_in_weekend; session++)
		{
			auto session_offset = offsetof(F125::PacketSessionData, m_weekendStructure) + session * sizeof(F125::PacketSessionData::m_weekendStructure[0]);
			proto_tree_add_item(num_sessions_in_weekend_tree, hf_eaf1_session_sessionsinweekend_sessiontype, tvb, session_offset, sizeof(F125::PacketSessionData::m_weekendStructure[0]), ENC_LITTLE_ENDIAN);
		}

		proto_tree_add_item(tree, hf_eaf1_session_sector2lapdistancestart, tvb, offsetof(F125::PacketSessionData, m_sector2LapDistanceStart), sizeof(F125::PacketSessionData::m_sector2LapDistanceStart), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_eaf1_session_sector3lapdistancestart, tvb, offsetof(F125::PacketSessionData, m_sector3LapDistanceStart), sizeof(F125::PacketSessionData::m_sector3LapDistanceStart), ENC_LITTLE_ENDIAN);

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_cardamage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketCarDamageData))
	{
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Car damage"));

		for (std::remove_const<decltype(F125::cs_maxNumCarsInUDPData)>::type participant = 0; participant < F125::cs_maxNumCarsInUDPData; participant++)
		{
			auto participant_offset = offsetof(F125::PacketCarDamageData, m_carDamageData) + participant * sizeof(F125::CarDamageData);

			auto driver_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_cardamage_drivername, pinfo, tvb, participant);
			auto driver_name_tree = proto_item_add_subtree(driver_name_ti, ett_eaf1_cardamage_drivername);

			auto tyre_wear_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyrewear, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_wear_tree = proto_item_add_subtree(tyre_wear_ti, ett_eaf1_cardamage_tyrewear);

			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_rearleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresWear) + 0 * sizeof(F125::CarDamageData::m_tyresWear[0]), sizeof(F125::CarDamageData::m_tyresWear[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_rearright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresWear) + 1 * sizeof(F125::CarDamageData::m_tyresWear[0]), sizeof(F125::CarDamageData::m_tyresWear[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_frontleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresWear) + 2 * sizeof(F125::CarDamageData::m_tyresWear[0]), sizeof(F125::CarDamageData::m_tyresWear[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_wear_tree, hf_eaf1_cardamage_tyrewear_frontright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresWear) + 3 * sizeof(F125::CarDamageData::m_tyresWear[0]), sizeof(F125::CarDamageData::m_tyresWear[0]), ENC_LITTLE_ENDIAN);

			auto tyre_damage_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyredamage, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_damage_tree = proto_item_add_subtree(tyre_damage_ti, ett_eaf1_cardamage_tyredamage);

			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_rearleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresDamage) + 0 * sizeof(F125::CarDamageData::m_tyresDamage[0]), sizeof(F125::CarDamageData::m_tyresDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_rearright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresDamage) + 1 * sizeof(F125::CarDamageData::m_tyresDamage[0]), sizeof(F125::CarDamageData::m_tyresDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_frontleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresDamage) + 2 * sizeof(F125::CarDamageData::m_tyresDamage[0]), sizeof(F125::CarDamageData::m_tyresDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_damage_tree, hf_eaf1_cardamage_tyredamage_frontright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyresDamage) + 3 * sizeof(F125::CarDamageData::m_tyresDamage[0]), sizeof(F125::CarDamageData::m_tyresDamage[0]), ENC_LITTLE_ENDIAN);

			auto brakes_damage_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_brakesdamage, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto brakes_damage_tree = proto_item_add_subtree(brakes_damage_ti, ett_eaf1_cardamage_brakesdamage);

			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_rearleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_brakesDamage) + 0 * sizeof(F125::CarDamageData::m_brakesDamage[0]), sizeof(F125::CarDamageData::m_brakesDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_rearright, tvb, participant_offset + offsetof(F125::CarDamageData, m_brakesDamage) + 1 * sizeof(F125::CarDamageData::m_brakesDamage[0]), sizeof(F125::CarDamageData::m_brakesDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_frontleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_brakesDamage) + 2 * sizeof(F125::CarDamageData::m_brakesDamage[0]), sizeof(F125::CarDamageData::m_brakesDamage[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(brakes_damage_tree, hf_eaf1_cardamage_brakesdamage_frontright, tvb, participant_offset + offsetof(F125::CarDamageData, m_brakesDamage) + 3 * sizeof(F125::CarDamageData::m_brakesDamage[0]), sizeof(F125::CarDamageData::m_brakesDamage[0]), ENC_LITTLE_ENDIAN);

			auto tyre_blisters_ti = proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_tyreblisters, tvb, 0, 0, ENC_LITTLE_ENDIAN);
			auto tyre_blisters_tree = proto_item_add_subtree(tyre_blisters_ti, ett_eaf1_cardamage_tyreblisters);

			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_rearleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyreBlisters) + 0 * sizeof(F125::CarDamageData::m_tyreBlisters[0]), sizeof(F125::CarDamageData::m_tyreBlisters[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_rearright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyreBlisters) + 1 * sizeof(F125::CarDamageData::m_tyreBlisters[0]), sizeof(F125::CarDamageData::m_tyreBlisters[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_frontleft, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyreBlisters) + 2 * sizeof(F125::CarDamageData::m_tyreBlisters[0]), sizeof(F125::CarDamageData::m_tyreBlisters[0]), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_blisters_tree, hf_eaf1_cardamage_tyreblisters_frontright, tvb, participant_offset + offsetof(F125::CarDamageData, m_tyreBlisters) + 3 * sizeof(F125::CarDamageData::m_tyreBlisters[0]), sizeof(F125::CarDamageData::m_tyreBlisters[0]), ENC_LITTLE_ENDIAN);

			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_frontleftwingdamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_frontLeftWingDamage), sizeof(F125::CarDamageData::m_frontLeftWingDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_frontrightwingdamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_frontRightWingDamage), sizeof(F125::CarDamageData::m_frontRightWingDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_rearwingdamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_rearWingDamage), sizeof(F125::CarDamageData::m_rearWingDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_floordamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_floorDamage), sizeof(F125::CarDamageData::m_floorDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_diffuserdamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_diffuserDamage), sizeof(F125::CarDamageData::m_diffuserDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_sidepoddamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_sidepodDamage), sizeof(F125::CarDamageData::m_sidepodDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_drsfault, tvb, participant_offset + offsetof(F125::CarDamageData, m_drsFault), sizeof(F125::CarDamageData::m_drsFault), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_ersfault, tvb, participant_offset + offsetof(F125::CarDamageData, m_ersFault), sizeof(F125::CarDamageData::m_ersFault), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_gearboxdamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_gearBoxDamage), sizeof(F125::CarDamageData::m_gearBoxDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginedamage, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineDamage), sizeof(F125::CarDamageData::m_engineDamage), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginemguhwear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineMGUHWear), sizeof(F125::CarDamageData::m_engineMGUHWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineeswear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineESWear), sizeof(F125::CarDamageData::m_engineESWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginecewear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineCEWear), sizeof(F125::CarDamageData::m_engineCEWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineicewear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineICEWear), sizeof(F125::CarDamageData::m_engineICEWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginemgukwear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineMGUKWear), sizeof(F125::CarDamageData::m_engineMGUKWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_enginetcwear, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineTCWear), sizeof(F125::CarDamageData::m_engineTCWear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineblown, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineBlown), sizeof(F125::CarDamageData::m_engineBlown), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(driver_name_tree, hf_eaf1_cardamage_engineseized, tvb, participant_offset + offsetof(F125::CarDamageData, m_engineSeized), sizeof(F125::CarDamageData::m_engineSeized), ENC_LITTLE_ENDIAN);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_tyresets(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketTyreSetsData))
	{
		auto tyresets_data = (F125::PacketTyreSetsData *)tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));
		auto vehicle_index = tyresets_data->m_carIdx;

		auto vehicle_index_ti = add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_tyresets_vehicleindex, pinfo, tvb, offsetof(F125::PacketTyreSetsData, m_carIdx));
		auto vehicle_index_tree = proto_item_add_subtree(vehicle_index_ti, ett_eaf1_tyresets_vehicleindex);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Tyre sets (%s)", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index)));

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_tyresets_fittedindex, tvb, offsetof(F125::PacketTyreSetsData, m_fittedIdx), sizeof(F125::PacketTyreSetsData::m_fittedIdx), ENC_LITTLE_ENDIAN);

		for (std::remove_const<decltype(F125::cs_maxNumTyreSets)>::type tyre_set = 0; tyre_set < F125::cs_maxNumTyreSets; tyre_set++)
		{
			auto tyreset_ti = proto_tree_add_string(vehicle_index_tree, hf_eaf1_tyresets_tyreset, tvb, 0, 0, wmem_strdup_printf(pinfo->pool, "Set %d", tyre_set));
			auto tyreset_tree = proto_item_add_subtree(tyreset_ti, ett_eaf1_tyresets_tyreset);

			auto tyreset_offset = offsetof(F125::PacketTyreSetsData, m_tyreSetData) + tyre_set * sizeof(F125::TyreSetData);

			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_actualtyrecompound, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_actualTyreCompound), sizeof(F125::TyreSetData::m_actualTyreCompound), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_visualtyrecompound, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_visualTyreCompound), sizeof(F125::TyreSetData::m_actualTyreCompound), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_wear, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_wear), sizeof(F125::TyreSetData::m_wear), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_available, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_available), sizeof(F125::TyreSetData::m_available), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_recommendedsession, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_recommendedSession), sizeof(F125::TyreSetData::m_recommendedSession), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_lifespan, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_lifeSpan), sizeof(F125::TyreSetData::m_lifeSpan), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_usablelife, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_usableLife), sizeof(F125::TyreSetData::m_usableLife), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_lapdeltatime, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_lapDeltaTime), sizeof(F125::TyreSetData::m_lapDeltaTime), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyreset_tree, hf_eaf1_tyresets_tyreset_fitted, tvb, tyreset_offset + offsetof(F125::TyreSetData, m_fitted), sizeof(F125::TyreSetData::m_fitted), ENC_LITTLE_ENDIAN);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_lappositions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketLapPositionsData))
	{
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Lap positions"));

		uint32_t num_laps;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_lappositions_numlaps, tvb, offsetof(F125::PacketLapPositionsData, m_numLaps), sizeof(F125::PacketLapPositionsData::m_numLaps), ENC_LITTLE_ENDIAN, &num_laps);

		uint32_t lap_start;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_lappositions_lapstart, tvb, offsetof(F125::PacketLapPositionsData, m_lapStart), sizeof(F125::PacketLapPositionsData::m_lapStart), ENC_LITTLE_ENDIAN, &lap_start);

		for (std::remove_const<decltype(F125::cs_maxNumLapsInLapPositionsHistoryPacket)>::type lap = 0; lap < num_laps; lap++)
		{
			auto lap_offset = offsetof(F125::PacketLapPositionsData, m_positionForVehicleIdx) + lap * sizeof(F125::PacketLapPositionsData::m_positionForVehicleIdx[0]);

			auto lap_ti = proto_tree_add_string(tree,
												hf_eaf1_lappositions_lap,
												tvb,
												lap_offset,
												sizeof(F125::PacketLapPositionsData::m_positionForVehicleIdx[0]),
												wmem_strdup_printf(pinfo->pool, "Lap %d", lap_start + lap + 1));
			auto lap_tree = proto_item_add_subtree(lap_ti, ett_eaf1_lappositions_lap);

			for (std::remove_const<decltype(F125::cs_maxNumCarsInUDPData)>::type vehicle_index = 0; vehicle_index < F125::cs_maxNumCarsInUDPData; vehicle_index++)
			{
				auto position = tvb_get_uint8(tvb, lap_offset + vehicle_index * sizeof(F125::PacketLapPositionsData::m_positionForVehicleIdx[0][0]));

				proto_tree_add_string(lap_tree,
									  hf_eaf1_lappositions_position,
									  tvb,
									  lap_offset + vehicle_index * sizeof(F125::PacketLapPositionsData::m_positionForVehicleIdx[0][0]),
									  sizeof(F125::PacketLapPositionsData::m_positionForVehicleIdx[0][0]),
									  wmem_strdup_printf(pinfo->pool, "%s: %d", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index), position));
			}
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_sessionhistory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketSessionHistoryData))
	{
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session history"));

		auto sessionhistory_data = (F125::PacketSessionHistoryData *)tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));
		auto vehicle_index = sessionhistory_data->m_carIdx;

		auto vehicle_index_ti = add_vehicle_index_and_name(proto_eaf1, tree, hf_eaf1_sessionhistory_caridx, pinfo, tvb, offsetof(F125::PacketSessionHistoryData, m_carIdx));
		auto vehicle_index_tree = proto_item_add_subtree(vehicle_index_ti, ett_eaf1_sessionhistory_vehicleindex);

		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Session history (%s)", lookup_driver_name(proto_eaf1, pinfo->num, pinfo->src, pinfo->srcport, vehicle_index)));

		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestlaptimelapnum, tvb, offsetof(F125::PacketSessionHistoryData, m_bestLapTimeLapNum), sizeof(F125::PacketSessionHistoryData::m_bestLapTimeLapNum), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector1lapnum, tvb, offsetof(F125::PacketSessionHistoryData, m_bestSector1LapNum), sizeof(F125::PacketSessionHistoryData::m_bestSector1LapNum), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector2lapnum, tvb, offsetof(F125::PacketSessionHistoryData, m_bestSector2LapNum), sizeof(F125::PacketSessionHistoryData::m_bestSector2LapNum), ENC_LITTLE_ENDIAN);
		proto_tree_add_item(vehicle_index_tree, hf_eaf1_sessionhistory_bestsector3lapnum, tvb, offsetof(F125::PacketSessionHistoryData, m_bestSector3LapNum), sizeof(F125::PacketSessionHistoryData::m_bestSector3LapNum), ENC_LITTLE_ENDIAN);

		uint32_t num_laps;
		auto num_laps_ti = proto_tree_add_item_ret_uint(vehicle_index_tree, hf_eaf1_sessionhistory_numlaps, tvb, offsetof(F125::PacketSessionHistoryData, m_numLaps), sizeof(F125::PacketSessionHistoryData::m_numLaps), ENC_LITTLE_ENDIAN, &num_laps);
		auto num_laps_tree = proto_item_add_subtree(num_laps_ti, ett_eaf1_sessionhistory_numlaps);

		for (uint32_t lap_number = 0; lap_number < num_laps; lap_number++)
		{
			auto lap_base = offsetof(F125::PacketSessionHistoryData, m_lapHistoryData) + lap_number * sizeof(F125::LapHistoryData);

			auto lap_ti = proto_tree_add_string(num_laps_tree,
												hf_eaf1_sessionhistory_lap,
												tvb,
												lap_base,
												sizeof(F125::PacketSessionHistoryData::m_lapHistoryData[0]),
												wmem_strdup_printf(pinfo->pool, "Lap %d", lap_number + 1));

			auto lap_tree = proto_item_add_subtree(lap_ti, ett_eaf1_sessionhistory_lap);

			proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_laptime, tvb, lap_base + offsetof(F125::LapHistoryData, m_lapTimeInMS), sizeof(F125::LapHistoryData::m_lapTimeInMS), ENC_LITTLE_ENDIAN);

			add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector1time, hf_eaf1_sessionhistory_sector1timemspart, hf_eaf1_sessionhistory_sector1timeminutespart, ett_eaf1_sessionhistory_sector1time, pinfo, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector1TimeMSPart), lap_base + offsetof(F125::LapHistoryData, m_sector1TimeMinutesPart));
			add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector2time, hf_eaf1_sessionhistory_sector2timemspart, hf_eaf1_sessionhistory_sector2timeminutespart, ett_eaf1_sessionhistory_sector2time, pinfo, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector2TimeMSPart), lap_base + offsetof(F125::LapHistoryData, m_sector2TimeMinutesPart));
			add_sector_time(lap_tree, hf_eaf1_sessionhistory_sector3time, hf_eaf1_sessionhistory_sector3timemspart, hf_eaf1_sessionhistory_sector3timeminutespart, ett_eaf1_sessionhistory_sector3time, pinfo, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector3TimeMSPart), lap_base + offsetof(F125::LapHistoryData, m_sector3TimeMinutesPart));

			proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_sector2timemspart, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector2TimeMSPart), sizeof(F125::LapHistoryData::m_sector2TimeMSPart), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_sector2timeminutespart, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector2TimeMinutesPart), sizeof(F125::LapHistoryData::m_sector2TimeMinutesPart), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_sector3timemspart, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector3TimeMSPart), sizeof(F125::LapHistoryData::m_sector3TimeMSPart), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(lap_tree, hf_eaf1_sessionhistory_sector3timeminutespart, tvb, lap_base + offsetof(F125::LapHistoryData, m_sector3TimeMinutesPart), sizeof(F125::LapHistoryData::m_sector3TimeMinutesPart), ENC_LITTLE_ENDIAN);

			static int *const valid_status_fields[] = {
				&hf_eaf1_sessionhistory_lapvalidbitflags_lap,
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector1,
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector2,
				&hf_eaf1_sessionhistory_lapvalidbitflags_sector3,
				NULL,
			};

			proto_tree_add_bitmask(lap_tree, tvb, lap_base + offsetof(F125::LapHistoryData, m_lapValidBitFlags), hf_eaf1_sessionhistory_lapvalidbitflags,
								   ett_eaf1_sessionhistory_lapvalidbitflags, valid_status_fields, ENC_LITTLE_ENDIAN);
		}

		uint32_t num_tyre_stints;
		auto num_tyre_stints_ti = proto_tree_add_item_ret_uint(vehicle_index_tree, hf_eaf1_sessionhistory_numtyrestints, tvb, offsetof(F125::PacketSessionHistoryData, m_numTyreStints), sizeof(F125::PacketSessionHistoryData::m_numTyreStints), ENC_LITTLE_ENDIAN, &num_tyre_stints);
		auto num_tyre_stints_tree = proto_item_add_subtree(num_tyre_stints_ti, ett_eaf1_sessionhistory_numtyrestints);

		for (uint32_t tyre_stint_number = 0; tyre_stint_number < num_tyre_stints; tyre_stint_number++)
		{
			auto tyre_stint_base = offsetof(F125::PacketSessionHistoryData, m_tyreStintsHistoryData) + tyre_stint_number * sizeof(F125::TyreStintHistoryData);

			auto tyre_stint_ti = proto_tree_add_string(num_tyre_stints_tree,
													   hf_eaf1_sessionhistory_tyrestint,
													   tvb,
													   tyre_stint_base,
													   sizeof(F125::PacketSessionHistoryData::m_tyreStintsHistoryData[0]),
													   wmem_strdup_printf(pinfo->pool, "Tyre stint %d", tyre_stint_number + 1));

			auto tyre_stint_tree = proto_item_add_subtree(tyre_stint_ti, ett_eaf1_sessionhistory_tyrestint);

			proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_endlap, tvb, tyre_stint_base + offsetof(F125::TyreStintHistoryData, m_endLap), sizeof(F125::TyreStintHistoryData::m_endLap), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_tyreactualcompound, tvb, tyre_stint_base + offsetof(F125::TyreStintHistoryData, m_tyreActualCompound), sizeof(F125::TyreStintHistoryData::m_tyreActualCompound), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tyre_stint_tree, hf_eaf1_sessionhistory_tyrevisualcompound, tvb, tyre_stint_base + offsetof(F125::TyreStintHistoryData, m_tyreVisualCompound), sizeof(F125::TyreStintHistoryData::m_tyreVisualCompound), ENC_LITTLE_ENDIAN);
		}

		return tvb_captured_length(tvb);
	}

	return 0;
}

static int dissect_eaf1_2025_finalclassification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
	if (tvb_captured_length(tvb) >= sizeof(F125::PacketFinalClassificationData))
	{
		col_set_str(pinfo->cinfo, COL_INFO, wmem_strdup_printf(pinfo->pool, "Final classification"));

		uint32_t num_cars;
		proto_tree_add_item_ret_uint(tree, hf_eaf1_finalclassification_numcars, tvb, offsetof(F125::PacketFinalClassificationData, m_numCars), sizeof(F125::PacketFinalClassificationData::m_numCars), ENC_LITTLE_ENDIAN, &num_cars);

		for (uint32_t car = 0; car < num_cars; car++)
		{
			auto car_offset = offsetof(F125::PacketFinalClassificationData, m_classificationData) + car * sizeof(F125::FinalClassificationData);

			auto player_name_ti = add_driver_name(proto_eaf1, tree, hf_eaf1_finalclassification_drivername, pinfo, tvb, car);
			proto_tree *player_name_tree = proto_item_add_subtree(player_name_ti, ett_eaf1_finalclassification_drivername);

			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_position, tvb, car_offset + offsetof(F125::FinalClassificationData, m_position), sizeof(F125::FinalClassificationData::m_position), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numlaps, tvb, car_offset + offsetof(F125::FinalClassificationData, m_numLaps), sizeof(F125::FinalClassificationData::m_numLaps), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_gridposition, tvb, car_offset + offsetof(F125::FinalClassificationData, m_gridPosition), sizeof(F125::FinalClassificationData::m_gridPosition), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_points, tvb, car_offset + offsetof(F125::FinalClassificationData, m_points), sizeof(F125::FinalClassificationData::m_points), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numpitstops, tvb, car_offset + offsetof(F125::FinalClassificationData, m_numPitStops), sizeof(F125::FinalClassificationData::m_numPitStops), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_resultstatus, tvb, car_offset + offsetof(F125::FinalClassificationData, m_resultStatus), sizeof(F125::FinalClassificationData::m_resultStatus), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_resultreason, tvb, car_offset + offsetof(F125::FinalClassificationData, m_resultReason), sizeof(F125::FinalClassificationData::m_resultReason), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_bestlaptimeinms, tvb, car_offset + offsetof(F125::FinalClassificationData, m_bestLapTimeInMS), sizeof(F125::FinalClassificationData::m_bestLapTimeInMS), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_totalracetime, tvb, car_offset + offsetof(F125::FinalClassificationData, m_totalRaceTime), sizeof(F125::FinalClassificationData::m_totalRaceTime), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_penaltiestime, tvb, car_offset + offsetof(F125::FinalClassificationData, m_penaltiesTime), sizeof(F125::FinalClassificationData::m_penaltiesTime), ENC_LITTLE_ENDIAN);
			proto_tree_add_item(player_name_tree, hf_eaf1_finalclassification_numpenalties, tvb, car_offset + offsetof(F125::FinalClassificationData, m_numPenalties), sizeof(F125::FinalClassificationData::m_numPenalties), ENC_LITTLE_ENDIAN);

			uint32_t num_stints;
			auto num_stints_ti = proto_tree_add_item_ret_uint(player_name_tree, hf_eaf1_finalclassification_numtyrestints, tvb, car_offset + offsetof(F125::FinalClassificationData, m_numTyreStints), sizeof(F125::FinalClassificationData::m_numTyreStints), ENC_LITTLE_ENDIAN, &num_stints);
			proto_tree *num_stints_tree = proto_item_add_subtree(num_stints_ti, ett_eaf1_finalclassification_numstints);

			for (uint32_t stint = 0; stint < num_stints; stint++)
			{
				auto tyre_stint_ti = proto_tree_add_string(num_stints_tree,
														   hf_eaf1_finalclassification_tyrestint,
														   tvb,
														   0,
														   0,
														   wmem_strdup_printf(pinfo->pool, "Tyre stint %d", stint + 1));
				auto tyre_stint_tree = proto_item_add_subtree(tyre_stint_ti, ett_eaf1_sessionhistory_tyrestint);

				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_actual, tvb, car_offset + offsetof(F125::FinalClassificationData, m_tyreStintsActual) + stint * sizeof(F125::FinalClassificationData::m_tyreStintsActual[0]), sizeof(F125::FinalClassificationData::m_tyreStintsActual[0]), ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_visual, tvb, car_offset + offsetof(F125::FinalClassificationData, m_tyreStintsVisual) + stint * sizeof(F125::FinalClassificationData::m_tyreStintsVisual[0]), sizeof(F125::FinalClassificationData::m_tyreStintsVisual[0]), ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tyre_stint_tree, hf_eaf1_finalclassification_tyrestint_endlaps, tvb, car_offset + offsetof(F125::FinalClassificationData, m_tyreStintsEndLaps) + stint * sizeof(F125::FinalClassificationData::m_tyreStintsEndLaps[0]), sizeof(F125::FinalClassificationData::m_tyreStintsEndLaps[0]), ENC_LITTLE_ENDIAN);
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

			{
				&hf_eaf1_participants_aicontrolled,
				{
					"Participants AI controlled",
					"eaf1.participants.aicontrolled",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Participants AI controlled",
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
					"Participants driver id",
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
					"Participants network id",
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
					"Participants team id",
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
					"Participants my team",
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
					"Participants race number",
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
					"Participants nationality",
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
					"Participants name",
					HFILL,
				},
			},

			{
				&hf_eaf1_participants_yourtelemetry,
				{
					"Participants your tTelemetry",
					"eaf1.participants.yourtelemetry",
					FT_UINT8,
					BASE_DEC,
					NULL,
					0x0,
					"Participants your telemetry",
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
					"Participants show online names",
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
					"Participants tech level",
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
					"Participants platform",
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
					"Participants num livery colours",
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
					"Participants livery colour",
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
					"Participants livery colour red",
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
					"Participants livery colour green",
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
					"Participants livery colour blue",
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
					"Session weather",
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
					"Session track temperature",
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
					"Session air temperature",
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
					"Session total laps",
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
					"Session track length",
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
					"Session type",
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
					"Session track id",
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
					"Session formula",
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
					"Session time left",
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
					"Session duration",
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
					"pitSpeedLimit",
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
					"Session game paused",
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
					"Session is spectating",
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
					"Session spectator car index",
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
					"Session SLI Pro native support",
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
					"Session num marshal zones",
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
					"Session marshal zone",
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
					"Session marshal zone start",
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
					"Session marshal zone flag",
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
					"Session safety car status",
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
					"Session network game",
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
					"Session num weather forecast samples",
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
					"Session weather forecast sample",
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
					"sessionType",
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
					"timeOffset",
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
					"weather",
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
					"trackTemperature",
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
					"trackTemperatureChange",
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
					"airTemperature",
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
					"airTemperatureChange",
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
					"rainPercentage",
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
					"Session forecast accuracy",
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
					"Session AI difficulty",
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
					"Session season link identifier",
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
					"Session weekend link identifier",
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
					"Session session link identifier",
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
					"Session pit stop window ideal lap",
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
					"Session pit stop window latest lap",
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
					"Session pit stop rejoin position",
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
					"Session steering assist",
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
					"Session braking assist",
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
					"Session gearbox assist",
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
					"Session pit assist",
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
					"Session pit release assist",
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
					"Session ERS assist",
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
					"Session DRS assist",
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
					"Session dynamic racing line",
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
					"Session dynamic racing line type",
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
					"Session game mode",
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
					"Session rule set",
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
					"Session time of day",
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
					"Session session length",
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
					"Session speed units lead player",
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
					"Session temperature units lead player",
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
					"Session speed units secondary player",
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
					"Session temperature units secondary player",
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
					"Session num safety car periods",
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
					"Session num virtual safety car periods",
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
					"Session num red flag periods",
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
					"Session equal car performance",
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
					"Session recovery mode",
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
					"Session flashback limit",
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
					"Session surface type",
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
					"Session low fuel mode",
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
					"Session race starts",
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
					"Session tyre temperature",
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
					"Session pit lane tyre sim",
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
					"Session car damage",
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
					"Session car damage rate",
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
					"Session collisions",
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
					"Session collisions off for first lap only",
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
					"Session MP unsafe pit release",
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
					"Session MP off for griefing",
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
					"Session corner cutting stringency",
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
					"Session parc ferme rules",
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
					"Session pit stop experience",
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
					"Session safety car",
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
					"Session safety car experience",
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
					"Session formation lap",
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
					"Session formation lap experience",
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
					"Session red flags",
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
					"Session affects licence level solo",
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
					"Session affects licence level MP",
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
					"Session num sessions in weekend",
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
					"Session session in weekend session type",
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
					"Session sector 2 lap distance start",
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
					"Session sector 3 lap distance start",
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
					"Car damage driver name",
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
					"Car damage tyre wear",
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
					"Car damage tyre wear rear left",
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
					"Car damage tyre wear rear right",
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
					"Car damage tyre wear front left",
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
					"Car damage tyre wear front right",
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
					"Car damage tyre damage",
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
					"Car damage tyre damage rear left",
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
					"Car damage tyre damage rear right",
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
					"Car damage tyre damage front left",
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
					"Car damage tyre damage front right",
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
					"Car damage brakes damage",
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
					"Car damage brakes damage rear left",
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
					"Car damage brakes damage rear right",
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
					"Car damage brakes damage front left",
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
					"Car damage brakes damage front right",
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
					"Car damage tyre blisters",
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
					"Car damage tyre blisters rear left",
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
					"Car damage tyre blisters rear right",
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
					"Car damage tyre blisters front left",
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
					"Car damage tyre blisters front right",
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
					"Car damage front left wing damage",
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
					"Car damage front right wing damage",
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
					"Car damage rear wing damage",
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
					"Car damage floor damage",
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
					"Car damage diffuser damage",
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
					"Car damage sidepod damage",
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
					"Car damage DRS fault",
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
					"Car damage ERS fault",
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
					"Car damage gearbox damage",
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
					"Car damage engine damage",
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
					"Car damage engine MGUH wear",
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
					"Car damage engine ES wear",
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
					"Car damage engine CE wear",
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
					"Car damage engine ICE wear",
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
					"Car damage engine MGUK wear",
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
					"Car damage engine TC wear",
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
					"Car damage engine blown",
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
					"Car damage engine seized",
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
					"Tyresets vehicle index",
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
					"Tyresets fitted index",
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
					"Tyresets tyreset",
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
					"Tyresets tyreset actual tyre compound",
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
					"Tyresets tyreset visual tyre compound",
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
					"Tyresets tyreset wear",
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
					"Tyresets tyreset available",
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
					"Tyresets tyreset recommended session",
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
					"Tyresets tyreset life span",
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
					"Tyresets tyreset usable life",
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
					"Tyresets tyreset lap delta time",
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
					"Tyresets tyreset fitted",
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
					"Lap positions num laps",
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
					"Lap positions lap start",
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
					"Lap positions lap",
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
					"Lap positions position",
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
					"Session history vehicle index",
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
					"Session history num laps",
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
					"Session history num tyre stints",
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
					"Session history bestLapTimeLapNum",
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
					"Session history best sector 1 lap num",
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
					"Session history best sector 2 lap num",
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
					"Session history best sector 3 lap num",
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
					"Session history lap",
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
					"Session history lap time",
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
					"Session history lap sector 1 time",
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
					"Session history lap sector 1 time mS part",
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
					"Session history lap sector 1 time minutes part",
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
					"Session history lap sector 2 time",
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
					"Session history lap sector 2 time mS part",
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
					"Session history lap sector 2 time minutes part",
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
					"Session history lap sector 3 time",
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
					"Session history lap sector 3 time mS part",
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
					"Session history lap sector 3 time minutes part",
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
					"Session history lap lap valid bit flags",
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
					"Lap",
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
					"Sector 1",
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
					"Sector 2",
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
					"Sector 3",
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
					"Session history tyre stint",
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
					"Session history end lap",
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
					"Session history tyre actual compound",
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
					"Session history tyre visual compound",
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
					"Final classification num cars",
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
					"Final classification driver name",
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
					"Final classification position",
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
					"Final classification num laps",
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
					"Final classification grid position",
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
					"Final classification points",
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
					"Final classification num pit stops",
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
					"Final classification result status",
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
					"Final classification result reason",
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
					"Final classification best lap time in mS",
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
					"Final classification total race time",
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
					"Final classification penalties time",
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
					"Final classification num penalties",
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
					"Final classification num tyre stints",
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
					"Final classification tyre stint",
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
					"Final classification tyre stint actual",
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
					"Final classification tyre stint visual",
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
					"Final classification tyre stint end laps",
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
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdSession, create_dissector_handle(dissect_eaf1_2025_session, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdCarDamage, create_dissector_handle(dissect_eaf1_2025_cardamage, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdTyreSets, create_dissector_handle(dissect_eaf1_2025_tyresets, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdLapPositions, create_dissector_handle(dissect_eaf1_2025_lappositions, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdSessionHistory, create_dissector_handle(dissect_eaf1_2025_sessionhistory, proto_eaf1));
		dissector_add_uint("eaf1.f125packetid", F125::ePacketIdFinalClassification, create_dissector_handle(dissect_eaf1_2025_finalclassification, proto_eaf1));
	}
}
