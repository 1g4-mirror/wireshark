/* packet-quakeworld.c
 * Routines for QuakeWorld packet dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.idsoftware.com/q1source/q1source.zip
 *
 * $Id: packet-quakeworld.c,v 1.11 2002/01/24 09:20:50 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include <string.h>
#include <epan/packet.h>
#include "prefs.h"

static int proto_quakeworld = -1;

static int hf_quakeworld_s2c = -1;
static int hf_quakeworld_c2s = -1;
static int hf_quakeworld_connectionless = -1;
static int hf_quakeworld_game = -1;
static int hf_quakeworld_connectionless_marker = -1;
static int hf_quakeworld_connectionless_text = -1;
static int hf_quakeworld_connectionless_command = -1;
static int hf_quakeworld_connectionless_arguments = -1;
static int hf_quakeworld_connectionless_connect_version = -1;
static int hf_quakeworld_connectionless_connect_qport = -1;
static int hf_quakeworld_connectionless_connect_challenge = -1;
static int hf_quakeworld_connectionless_connect_infostring = -1;
static int hf_quakeworld_connectionless_connect_infostring_key_value = -1;
static int hf_quakeworld_connectionless_connect_infostring_key = -1;
static int hf_quakeworld_connectionless_connect_infostring_value = -1;
static int hf_quakeworld_connectionless_rcon_password = -1;
static int hf_quakeworld_connectionless_rcon_command = -1;
static int hf_quakeworld_game_seq1 = -1;
static int hf_quakeworld_game_rel1 = -1;
static int hf_quakeworld_game_seq2 = -1;
static int hf_quakeworld_game_rel2 = -1;
static int hf_quakeworld_game_qport = -1;

static gint ett_quakeworld = -1;
static gint ett_quakeworld_connectionless = -1;
static gint ett_quakeworld_connectionless_text = -1;
static gint ett_quakeworld_connectionless_arguments = -1;
static gint ett_quakeworld_connectionless_connect_infostring = -1;
static gint ett_quakeworld_connectionless_connect_infostring_key_value = -1;
static gint ett_quakeworld_game = -1;
static gint ett_quakeworld_game_seq1 = -1;
static gint ett_quakeworld_game_seq2 = -1;
static gint ett_quakeworld_game_clc = -1;
static gint ett_quakeworld_game_svc = -1;

static dissector_handle_t data_handle;

/*
   helper functions, they may ave to go somewhere else
   they are mostly copied without change from
	quakeworldsource/client/cmd.c
	quakeworldsource/client/common.c
*/

static	char		com_token[1024];
static	int		com_token_start;
static	int		com_token_length;

char *
COM_Parse (char *data)
{
	int	c;
	int	len;

	len = 0;
	com_token[0] = 0;
	com_token_start = 0;
	com_token_length = 0;

	if (data == NULL)
		return NULL;

	/* skip whitespace */
skipwhite:
	while ( (c = *data) <= ' ') {
		if (c == 0)
			return NULL;	/* end of file; */
		data++;
		com_token_start++;
	}

	/* skip // comments */
	if (c=='/' && data[1] == '/') {
		while (*data && *data != '\n')
			data++;
			com_token_start++;
		goto skipwhite;
	}

	/* handle quoted strings specially */
	if (c == '\"') {
		data++;
		com_token_start++;
		while (1) {
			c = *data++;
			if (c=='\"' || c==0) {
				com_token[len] = 0;
				return data;
			}
			com_token[len] = c;
			len++;
			com_token_length++;
		}
	}

	/* parse a regular word */
	do {
		com_token[len] = c;
		data++;
		len++;
		com_token_length++;
		c = *data;
	} while (c>32);

	com_token[len] = 0;
	return data;
}


#define			MAX_ARGS 80
static	int		cmd_argc = 0;
static	char		*cmd_argv[MAX_ARGS];
static	char		*cmd_null_string = "";
static	int		cmd_argv_start[MAX_ARGS];
static	int		cmd_argv_length[MAX_ARGS];



int
Cmd_Argc(void)
{
	return cmd_argc;
}


char*
Cmd_Argv(int arg)
{
	if ( arg >= cmd_argc )
		return cmd_null_string;
	return cmd_argv[arg];
}


int
Cmd_Argv_start(int arg)
{
	if ( arg >= cmd_argc )
		return 0;
	return cmd_argv_start[arg];
}


int
Cmd_Argv_length(int arg)
{
	if ( arg >= cmd_argc )
		return 0;
	return cmd_argv_length[arg];
}


void
Cmd_TokenizeString(char* text)
{
	int i;
	int start;
	int length;
	

	/* clear the args from the last string */
	for (i=0 ; i<cmd_argc ; i++)
		g_free(cmd_argv[i]);

	cmd_argc = 0;

	start = 0;
	while (TRUE) {

		/* skip whitespace up to a \n */
		while (*text && *text <= ' ' && *text != '\n') {
			text++;
			start++;
		}

		length = 0;

		if (*text == '\n') {
			/* a newline seperates commands in the buffer */
			text++;
			break;
		}

		if (!*text)
			return;
			
		text = COM_Parse (text);
		if (!text)
			return;

		if (cmd_argc < MAX_ARGS) {
			cmd_argv[cmd_argc] = g_strdup(com_token);
			cmd_argv_start[cmd_argc] = start + com_token_start;
			cmd_argv_length[cmd_argc] = com_token_length;
			cmd_argc++;
		}

		start += com_token_start + com_token_length;
	}
}

			
void
dissect_id_infostring(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, 
	int offset, char* infostring,
	gint ett_key_value, int hf_key_value, int hf_key, int hf_value)
{
	char * newpos = infostring;
	int end_of_info = FALSE;

	/* to look at all the key/value pairs, we destroy infostring */
	while(!end_of_info) {
		char* keypos;
		char* valuepos;
		int keylength;
		char* keyvaluesep;
		int valuelength;
		char* valueend;

		keypos = newpos;
		if (*keypos == 0) break;
		if (*keypos == '\\') keypos++;

		for (keylength = 0
			;
			*(keypos + keylength) != '\\' && 
			*(keypos + keylength) != 0
			;
			keylength++) ;
		keyvaluesep = keypos + keylength;
		if (*keyvaluesep == 0) break;
		valuepos = keyvaluesep+1;
		for (valuelength = 0
			;
			*(valuepos + valuelength) != '\\' && 
			*(valuepos + valuelength) != 0
			;
			valuelength++) ;
		valueend = valuepos + valuelength;
		if (*valueend == 0) {
			end_of_info = TRUE;
		}
		*(keyvaluesep) = '=';
		*(valueend) = 0;
		
		if (tree) {
			proto_item* sub_item = NULL;
			proto_tree* sub_tree = NULL;

			sub_item = proto_tree_add_string(tree,
				hf_key_value,
				tvb,
				offset + (keypos-infostring),
				keylength + 1 + valuelength, keypos);
			if (sub_item) 
				sub_tree =
					proto_item_add_subtree(
					sub_item,
					ett_key_value);
			*(keyvaluesep) = 0;
			if (sub_tree) {
				proto_tree_add_string(sub_tree,
					hf_key,
					tvb,
					offset + (keypos-infostring),
					keylength, keypos);
				proto_tree_add_string(sub_tree,
					hf_value,
					tvb,
					offset + (valuepos-infostring),
					valuelength, valuepos);
			}
		}
		newpos = valueend + 1;
	}
}


static const value_string names_direction[] = {
#define DIR_C2S 0
	{ DIR_C2S, "Client to Server" },
#define DIR_S2C 1
	{ DIR_S2C, "Server to Client" },
	{ 0, NULL }
};


/* I took this name and value directly out of the QW source. */
#define PORT_MASTER 27500
static unsigned int gbl_quakeworldServerPort=PORT_MASTER;


/* out of band message id bytes (taken out of quakeworldsource/client/protocol.h */
 
/* M = master, S = server, C = client, A = any */
/* the second character will allways be \n if the message isn't a single */
/* byte long (?? not true anymore?) */
 
#define S2C_CHALLENGE		'c'
#define S2C_CONNECTION		'j'
#define A2A_PING		'k'	/* respond with an A2A_ACK */
#define A2A_ACK			'l'	/* general acknowledgement without info */
#define A2A_NACK		'm'	/* [+ comment] general failure */
#define A2A_ECHO		'e'	/* for echoing */
#define A2C_PRINT		'n'	/* print a message on client */
 
#define S2M_HEARTBEAT		'a'	/* + serverinfo + userlist + fraglist */
#define A2C_CLIENT_COMMAND	'B'	/* + command line */
#define S2M_SHUTDOWN		'C'


static void
dissect_quakeworld_ConnectionlessPacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*cl_tree = NULL;
	proto_item	*cl_item = NULL;
	proto_item	*text_item = NULL;
	proto_tree	*text_tree = NULL;
	guint8		text[2048];
	int		maxbufsize = 0;
	int		len;
	int		offset;
	guint32 marker;
	int command_len;
	char command[2048];
	int command_finished = FALSE;

	marker = tvb_get_ntohl(tvb, 0);
	if (tree) {
		cl_item = proto_tree_add_text(tree, tvb,
				0, -1, "Connectionless");
		if (cl_item)
			cl_tree = proto_item_add_subtree(
				cl_item, ett_quakeworld_connectionless);
	}

	if (cl_tree) {
		proto_tree_add_uint(cl_tree, hf_quakeworld_connectionless_marker,
				tvb, 0, 4, marker);
	}

	/* all the rest of the packet is just text */
        offset = 4;

        maxbufsize = MIN((gint)sizeof(text), tvb_length_remaining(tvb, offset));
        len = tvb_get_nstringz0(tvb, offset, maxbufsize, text);
	/* actually, we should look for a eol char and stop already there */

        if (cl_tree) {
                text_item = proto_tree_add_string(cl_tree, hf_quakeworld_connectionless_text,
                        tvb, offset, len + 1, text);
		if (text_item) {
			text_tree = proto_item_add_subtree(
				text_item, ett_quakeworld_connectionless_text);
		}
        }

	if (direction == DIR_C2S) {
		/* client to sever commands */
		char *c;

		Cmd_TokenizeString(text);
		c = Cmd_Argv(0);
		
		/* client to sever commands */
		if (strcmp(c,"ping") == 0) {
			strcpy(command, "Ping");
			command_len = 4;
		} else if (strcmp(c,"status") == 0) {
			strcpy(command, "Status");
			command_len = 6;
		} else if (strcmp(c,"log") == 0) {
			strcpy(command, "Status");
			command_len = 3;
		} else if (strcmp(c,"connect") == 0) {
			int version;
			int qport;
			int challenge;
			char *infostring;
			proto_item *argument_item = NULL;
			proto_tree *argument_tree = NULL;
			proto_item *info_item = NULL;
			proto_tree *info_tree = NULL;
			strcpy(command, "Connect");
			command_len = Cmd_Argv_length(0);
			if (text_tree) {
				proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
					tvb, offset, command_len, command);
				argument_item = proto_tree_add_string(text_tree,
					hf_quakeworld_connectionless_arguments,
					tvb, offset + Cmd_Argv_start(1), len + 1 - Cmd_Argv_start(1), 
					text + Cmd_Argv_start(1));
				if (argument_item) {
					argument_tree =
						proto_item_add_subtree(argument_item,	
							ett_quakeworld_connectionless_arguments);
				}
				command_finished=TRUE;
			}
			version = atoi(Cmd_Argv(1));
			qport = atoi(Cmd_Argv(2));
			challenge = atoi(Cmd_Argv(3));
			infostring = Cmd_Argv(4);
			if (argument_tree) {
				proto_tree_add_uint(argument_tree,
					hf_quakeworld_connectionless_connect_version,
					tvb,
					offset + Cmd_Argv_start(1),
					Cmd_Argv_length(1), version);
				proto_tree_add_uint(argument_tree,
					hf_quakeworld_connectionless_connect_qport,
					tvb,
					offset + Cmd_Argv_start(2),
					Cmd_Argv_length(2), qport);
				proto_tree_add_int(argument_tree,
					hf_quakeworld_connectionless_connect_challenge,
					tvb,
					offset + Cmd_Argv_start(3),
					Cmd_Argv_length(3), challenge);
				info_item = proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_connect_infostring,
					tvb,
					offset + Cmd_Argv_start(4),
					Cmd_Argv_length(4), infostring);
				if (info_item)
					info_tree = proto_item_add_subtree(
						info_item, ett_quakeworld_connectionless_connect_infostring);
				dissect_id_infostring(tvb, pinfo, info_tree, offset + Cmd_Argv_start(4),
					infostring,
					ett_quakeworld_connectionless_connect_infostring_key_value,
					hf_quakeworld_connectionless_connect_infostring_key_value,
					hf_quakeworld_connectionless_connect_infostring_key,
					hf_quakeworld_connectionless_connect_infostring_value);
			}
		} else if (strcmp(c,"getchallenge") == 0) {
			strcpy(command, "Get Challenge");
			command_len = Cmd_Argv_length(0);
		} else if (strcmp(c,"rcon") == 0) {
			char* password;
			int i;
			char remaining[1024];
			proto_item *argument_item = NULL;
			proto_tree *argument_tree = NULL;
			strcpy(command, "Remote Command");
			command_len = Cmd_Argv_length(0);
			if (text_tree) {
				proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
					tvb, offset, command_len, command);
				argument_item = proto_tree_add_string(text_tree,
					hf_quakeworld_connectionless_arguments,
					tvb, offset + Cmd_Argv_start(1), len + 1 - Cmd_Argv_start(1), 
					text + Cmd_Argv_start(1));
				if (argument_item) {
					argument_tree =
						proto_item_add_subtree(argument_item,	
							ett_quakeworld_connectionless_arguments);
				}
				command_finished=TRUE;
			}
			password = Cmd_Argv(1);
			if (argument_tree) {
				proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_rcon_password,
					tvb,
					offset + Cmd_Argv_start(1),
					Cmd_Argv_length(1), password);
			}
			for (i=2; i<Cmd_Argc() ; i++) {
				remaining[0] = 0;
				strcat (remaining, Cmd_Argv(i) );
				strcat (remaining, " ");
			}
			if (text_tree) {
				proto_tree_add_string(argument_tree,
					hf_quakeworld_connectionless_rcon_command,
					tvb, offset + Cmd_Argv_start(2),
					Cmd_Argv_start(Cmd_Argc()-1) + Cmd_Argv_length(Cmd_Argc()-1) -
					Cmd_Argv_start(2),
					remaining);
			}
		} else if (c[0]==A2A_PING && ( c[1]==0 || c[1]=='\n')) {
			strcpy(command, "Ping");
			command_len = 1;
		} else if (c[0]==A2A_ACK && ( c[1]==0 || c[1]=='\n')) {
			strcpy(command, "Ack");
			command_len = 1;
		} else {
			strcpy(command, "Unknown");
			command_len = len;
		}
	}
	else {
		/* server to client commands */
		if (text[0] == S2C_CONNECTION) {
			strcpy(command, "Connected");
			command_len = 1;
		} else if (text[0] == A2C_CLIENT_COMMAND) {
			strcpy(command, "Client Command");
			command_len = 1;
			/* stringz (command), stringz (localid) */
		} else if (text[0] == A2C_PRINT) {
			strcpy(command, "Print");
			command_len = 1;
			/* string */
		} else if (text[0] == A2A_PING) {
			strcpy(command, "Ping");
			command_len = 1;
		} else if (text[0] == S2C_CHALLENGE) {
			strcpy(command, "Challenge");
			command_len = 1;
			/* string, atoi */
		} else {
			strcpy(command, "Unknown");
			command_len = len;
		}
	}
		
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", command);
	}
		
	if (text_tree && !command_finished) {
		proto_tree_add_string(text_tree, hf_quakeworld_connectionless_command,
			tvb, offset, command_len, command);
	}
        offset += len + 1;
}


static void
dissect_quakeworld_client_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	call_dissector(data_handle,tvb, pinfo, tree);
}


static void
dissect_quakeworld_server_commands(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree)
{
	/* If I have too much time at hand, I'll fill it with all
	   the information from my QWD specs:
		http://www.planetquake.com/demospecs/qwd/
	*/
	call_dissector(data_handle,tvb, pinfo, tree);
}


static const value_string names_reliable[] = {
        { 0, "Non Reliable" },
        { 1, "Reliable" },
        { 0, NULL }
};


static void
dissect_quakeworld_GamePacket(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, int direction)
{
	proto_tree	*game_tree = NULL;
	proto_item	*game_item = NULL;
	guint32 seq1;
	guint32 seq2;
	int rel1;
	int rel2;
	int offset;
	guint		rest_length;

	direction = (pinfo->destport == gbl_quakeworldServerPort) ?
			DIR_C2S : DIR_S2C;

	if (tree) {
		game_item = proto_tree_add_text(tree, tvb,
				0, -1, "Game");
		if (game_item)
			game_tree = proto_item_add_subtree(
				game_item, ett_quakeworld_game);
	}

	offset = 0;

	seq1 = tvb_get_letohl(tvb, offset);
	rel1 = seq1 & 0x80000000 ? 1 : 0;
	seq1 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq1_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Current Sequence: %u (%s)",
			seq1, val_to_str(rel1,names_reliable,"%u"));
		if (seq1_item) {
			proto_tree *seq1_tree = proto_item_add_subtree(
				seq1_item, ett_quakeworld_game_seq1);
			proto_tree_add_uint(seq1_tree, hf_quakeworld_game_seq1,
					tvb, offset, 4, seq1);
			proto_tree_add_boolean(seq1_tree, hf_quakeworld_game_rel1,
					tvb, offset+3, 1, rel1);
		}
	}
	offset += 4;

	seq2 = tvb_get_letohl(tvb, offset);
	rel2 = seq2 & 0x80000000 ? 1 : 0;
	seq2 &= ~0x80000000;
	if (game_tree) {
		proto_item *seq2_item = proto_tree_add_text(game_tree,
			tvb, offset, 4, "Acknowledge Sequence: %u (%s)",
			seq2, val_to_str(rel2,names_reliable,"%u"));;
		if (seq2_item) {
			proto_tree *seq2_tree = proto_item_add_subtree(
				seq2_item, ett_quakeworld_game_seq2);
			proto_tree_add_uint(seq2_tree, hf_quakeworld_game_seq2,
					tvb, offset, 4, seq2);
			proto_tree_add_boolean(seq2_tree, hf_quakeworld_game_rel2,
					tvb, offset+3, 1, rel2);
		}
	}
	offset += 4;

	if (direction == DIR_C2S) {
		/* client to server */
		guint16 qport = tvb_get_letohs(tvb, offset);
		if (game_tree) {
			proto_tree_add_uint(game_tree, hf_quakeworld_game_qport, 
				tvb, offset, 2, qport);
		}
		offset +=2;
	}

	/* all the rest is pure game data */
	rest_length = tvb_reported_length(tvb) - offset;
	if (rest_length) {
		tvbuff_t *next_tvb =
		tvb_new_subset(tvb, offset, rest_length , rest_length);

		if (direction == DIR_C2S) {
			proto_item *c_item = NULL;
			proto_tree *c_tree = NULL;
			if (tree) {
				c_item = proto_tree_add_text(game_tree, next_tvb,
				0, -1, "Client Commands");
				if (c_item) {
					c_tree = proto_item_add_subtree(
						c_item, ett_quakeworld_game_clc);
				}
			}
			dissect_quakeworld_client_commands(next_tvb, pinfo, c_tree);
		}
		else {
			proto_item *c_item = NULL;
			proto_tree *c_tree = NULL;
			if (tree) {
				c_item = proto_tree_add_text(game_tree, next_tvb,
				0, -1, "Server Commands");
				if (c_item) {
					c_tree = proto_item_add_subtree(
					c_item, ett_quakeworld_game_svc);
				}
			}
			dissect_quakeworld_server_commands(next_tvb, pinfo, c_tree);
		}
	}
}


static void
dissect_quakeworld(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*quakeworld_tree = NULL;
	proto_item	*quakeworld_item = NULL;
	int		direction;

	direction = (pinfo->destport == gbl_quakeworldServerPort) ?
			DIR_C2S : DIR_S2C;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "QUAKEWORLD");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, val_to_str(direction,
			names_direction, "%u"));

	if (tree) {
		quakeworld_item = proto_tree_add_item(tree, proto_quakeworld,
				tvb, 0, -1, FALSE);
		if (quakeworld_item)
			quakeworld_tree = proto_item_add_subtree(
				quakeworld_item, ett_quakeworld);
			if (quakeworld_tree) {
				proto_tree_add_uint_format(quakeworld_tree,
					direction == DIR_S2C ?
					hf_quakeworld_s2c :
					hf_quakeworld_c2s,
					tvb, 0, 0, 1,
					"Direction: %s", val_to_str(direction, names_direction, "%u"));
			}
	}

	if (tvb_get_ntohl(tvb, 0) == 0xffffffff) {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, " Connectionless");
		}
		if (quakeworld_tree)
			proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_connectionless,
				tvb, 0, 0, 1,
				"Type: Connectionless");
		dissect_quakeworld_ConnectionlessPacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
	else {
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_str(pinfo->cinfo, COL_INFO, " Game");
		}
		if (quakeworld_tree)
			proto_tree_add_uint_format(quakeworld_tree,
				hf_quakeworld_game,
				tvb, 0, 0, 1,
				"Type: Game");
		dissect_quakeworld_GamePacket(
			tvb, pinfo, quakeworld_tree, direction);
	}
}


void
proto_reg_handoff_quakeworld(void)
{
	static int Initialized=FALSE;
	static dissector_handle_t quakeworld_handle;
	static int ServerPort=0;
 
	if (!Initialized) {
		quakeworld_handle = create_dissector_handle(dissect_quakeworld,
				proto_quakeworld);
		Initialized=TRUE;
	} else {
		dissector_delete("udp.port", ServerPort, quakeworld_handle);
	}
 
        /* set port for future deletes */
        ServerPort=gbl_quakeworldServerPort;
 
	dissector_add("udp.port", gbl_quakeworldServerPort, quakeworld_handle);
	data_handle = find_dissector("data");
}


void
proto_register_quakeworld(void)
{
	static hf_register_info hf[] = {
		{ &hf_quakeworld_c2s,
			{ "Client to Server", "quakeworld.c2s",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Client to Server", HFILL }},
		{ &hf_quakeworld_s2c,
			{ "Server to Client", "quakeworld.s2c",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Server to Client", HFILL }},
		{ &hf_quakeworld_connectionless,
			{ "Connectionless", "quakeworld.connectionless",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Connectionless", HFILL }},
		{ &hf_quakeworld_game,
			{ "Game", "quakeworld.game",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Game", HFILL }},
		{ &hf_quakeworld_connectionless_marker,
			{ "Marker", "quakeworld.connectionless.marker",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Marker", HFILL }},
		{ &hf_quakeworld_connectionless_text,
			{ "Text", "quakeworld.connectionless.text",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Text", HFILL }},
		{ &hf_quakeworld_connectionless_command,
			{ "Command", "quakeworld.connectionless.command",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Command", HFILL }},
		{ &hf_quakeworld_connectionless_arguments,
			{ "Arguments", "quakeworld.connectionless.arguments",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Arguments", HFILL }},
		{ &hf_quakeworld_connectionless_connect_version,
			{ "Version", "quakeworld.connectionless.connect.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Protocol Version", HFILL }},
		{ &hf_quakeworld_connectionless_connect_qport,
			{ "QPort", "quakeworld.connectionless.connect.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"QPort of the client", HFILL }},
		{ &hf_quakeworld_connectionless_connect_challenge,
			{ "Challenge", "quakeworld.connectionless.connect.challenge",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"Challenge from the server", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring,
			{ "Infostring", "quakeworld.connectionless.connect.infostring",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Infostring with additional variables", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_key_value,
			{ "Key/Value", "quakeworld.connectionless.connect.infostring.key_value",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Key and Value", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_key,
			{ "Key", "quakeworld.connectionless.connect.infostring.key",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Infostring Key", HFILL }},
		{ &hf_quakeworld_connectionless_connect_infostring_value,
			{ "Value", "quakeworld.connectionless.connect.infostring.value",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Infostring Value", HFILL }},
		{ &hf_quakeworld_connectionless_rcon_password,
			{ "Password", "quakeworld.connectionless.rcon.password",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Rcon Password", HFILL }},
		{ &hf_quakeworld_connectionless_rcon_command,
			{ "Command", "quakeworld.connectionless.rcon.command",
			FT_STRING, BASE_DEC, NULL, 0x0,
			"Command", HFILL }},
		{ &hf_quakeworld_game_seq1,
			{ "Sequence Number", "quakeworld.game.seq1",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the current packet", HFILL }},
		{ &hf_quakeworld_game_rel1,
			{ "Reliable", "quakeworld.game.rel1",
			FT_BOOLEAN, BASE_DEC, NULL, 0x0,
			"Packet is reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_seq2,
			{ "Sequence Number", "quakeworld.game.seq2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sequence number of the last received packet", HFILL }},
		{ &hf_quakeworld_game_rel2,
			{ "Reliable", "quakeworld.game.rel2",
			FT_BOOLEAN, BASE_DEC, NULL, 0x0,
			"Packet was reliable and may be retransmitted", HFILL }},
		{ &hf_quakeworld_game_qport,
			{ "QPort", "quakeworld.game.qport",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"QuakeWorld Client Port", HFILL }}
	};
	static gint *ett[] = {
		&ett_quakeworld,
		&ett_quakeworld_connectionless,
		&ett_quakeworld_connectionless_text,
		&ett_quakeworld_connectionless_arguments,
		&ett_quakeworld_connectionless_connect_infostring,
		&ett_quakeworld_connectionless_connect_infostring_key_value,
		&ett_quakeworld_game,
		&ett_quakeworld_game_seq1,
		&ett_quakeworld_game_seq2,
		&ett_quakeworld_game_clc,
		&ett_quakeworld_game_svc
	};
	module_t *quakeworld_module;

	proto_quakeworld = proto_register_protocol("QuakeWorld Network Protocol",
						"QUAKEWORLD", "quakeworld");
	proto_register_field_array(proto_quakeworld, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	quakeworld_module = prefs_register_protocol(proto_quakeworld,
		proto_reg_handoff_quakeworld);
	prefs_register_uint_preference(quakeworld_module, "udp.port",
					"QuakeWorld Server UDP Port",
					"Set the UDP port for the QuakeWorld Server",
					10, &gbl_quakeworldServerPort);
}

