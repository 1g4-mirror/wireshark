/* packet-dcc-rails.c
 * Routines for model railroad digital protocols packet dissection
 * Digital Command Control (DCC) Home: 
 *
 * Copyright 2024, Olivier Châtelain-Gmür <olivier.chatelain@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#define WS_LOG_DOMAIN "dcc-rails"

#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/tfs.h>

void proto_reg_handoff_dcc_rails(void);
void proto_register_dcc_rails(void);

static int proto_dcc_rails;

static int hf_dcc_rails_addr_type;
static int hf_dcc_rails_dir_type;
static int hf_dcc_rails_speed_type;
static int hf_dcc_rails_func_type;
static int hf_dcc_rails_cv_addr_type;
static int hf_dcc_rails_cv_value_type;

static dissector_handle_t dcc_rails_handle;

static int ett_dcc_rails;
#define DCC_RAILS_MIN_LENGTH 2

static int
dissect_dcc_rails(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item *ti; // , *expert_ti;
    proto_tree *dcc_rails_tree;

    unsigned offset = 0;
    // int      len    = 0;

    if (tvb_reported_length(tvb) < DCC_RAILS_MIN_LENGTH)
        return 0;    

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCC-RAILS");
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_dcc_rails, tvb, 0, -1, ENC_NA);
    dcc_rails_tree = proto_item_add_subtree(ti, ett_dcc_rails);

    if(pinfo->p2p_dir == P2P_DIR_SENT) {

        proto_item_append_text(ti, " - Outbound Stuff");
        
        guint32 dcc_address = 0;
        bool is_loco        = false;
        bool is_accessory   = false;

        //
        // Broadcast - RCN-211 - 4.1 Rücksetzpaket
        // - 0000-0000 0000-0000 0000-0000
        //
        if(0x000000 == tvb_get_uint24(tvb, 0, ENC_BIG_ENDIAN)) {
            offset += 3;
        }

        //
        // Broadcast - RCN-211 - 4.2 Leerlaufpaket 
        // - 1111-1111 0000-0000 1111-1111
        //
        else if(0xFF00FF == tvb_get_uint24(tvb, 0, ENC_BIG_ENDIAN)) {
            offset += 3;
        }

        //
        // Broadcast - RCN-211 - 5.1 Zeitbefehl
        // - 0000-0000 1100-0001 CCxx-xxxx xxxx-xxxxx xxxx-xxxx
        //
        else if(0x00C1 == tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN)) {
            offset += 5;
        }

        //
        // Loco - Short address - RCN-212 - Chapter 2 Befehlspakete für Fahrzeugdecoder
        // - 0AAA-AAAA {Befehlsbytes}
        //
        #define dcc_cmd_loco_short_val  0x0 // 0b0.......
        #define dcc_cmd_loco_short_len    1

        else if(dcc_cmd_loco_short_val == tvb_get_bits8(tvb, 0, dcc_cmd_loco_short_len)) {

            is_loco = true;
            dcc_address = tvb_get_bits8(tvb, 1, 8 - dcc_cmd_loco_short_len);
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset++, 1, dcc_address );
        }

        //
        // Loco - Long address - RCN-213 - Chapter 2 Befehlspakete für Fahrzeugdecoder 
        // - 11AA-AAAA AAAA-AAAA {Befehlsbytes}
        //
        #define dcc_cmd_loco_long_val 0x3 // 0b11......
        #define dcc_cmd_loco_long_len   2

        else if(dcc_cmd_loco_long_val == tvb_get_bits8(tvb, 0, dcc_cmd_loco_long_len)) {

            is_loco = true;
            dcc_address = tvb_get_bits16(tvb, 2, 14, ENC_BIG_ENDIAN);
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 2, dcc_address );
            offset += 2;
        }
        //
        // Accessory address - RCN-213 - Chapter 2.1 Paketformat für Einfache Zubehördecoder
        // - 10AA-AAAA xAAA-xAAx {Befehlsbytes}
        //
        #define dcc_cmd_accessory_val 0x2 // 0b10......
        #define dcc_cmd_accessory_len   2

        else if(dcc_cmd_accessory_val == tvb_get_bits8(tvb, 0, dcc_cmd_accessory_len)) {

            is_accessory = true;

            dcc_address  =  tvb_get_bits16( tvb,  2, 2, ENC_BIG_ENDIAN ) << 6;
            dcc_address |=  tvb_get_bits16( tvb,  5, 4, ENC_BIG_ENDIAN ) << 2;
            dcc_address |=  tvb_get_bits16( tvb,  9, 3, ENC_BIG_ENDIAN ) << 8;
            dcc_address |=  tvb_get_bits16( tvb, 13, 2, ENC_BIG_ENDIAN );
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 2, dcc_address );
        }

        if(is_loco) {

            while(tvb_reported_length_remaining(tvb, offset) >= 1) {

                //
                // Loco - RCN-212 - 2.2.1 Basis Geschwindigkeits- und Richtungsbefehl
                // - 01RG-GGGG
                //
                #define dcc_cmd_loco_speed7_val 0x1 // 0b01......
                #define dcc_cmd_loco_speed7_len   2

                if(tvb_get_bits8(tvb, 8 * offset, dcc_cmd_loco_speed7_len) == dcc_cmd_loco_speed7_val) {
                    // Direction
                    proto_tree_add_boolean ( dcc_rails_tree, hf_dcc_rails_dir_type,   tvb, offset + 1, 1
                                           , tvb_get_bits16(tvb, 8 * offset + dcc_cmd_loco_speed7_len    , 1, ENC_BIG_ENDIAN));
                    // Speed
                    proto_tree_add_uint(     dcc_rails_tree, hf_dcc_rails_speed_type, tvb, offset + 1, 2
                                           , tvb_get_bits16(tvb, 8 * offset + dcc_cmd_loco_speed7_len + 1, 7, ENC_BIG_ENDIAN));
                    offset++;
                }

                //
                // Loco - RCN-212 - Chapter 2.2.2 128 Geschwindigkeitsstufen-Befehl 
                // - 0011-1111 RGGG-GGGG
                //
                #define dcc_cmd_loco_speed128_val 0x3F // 0b00111111

                if(tvb_get_uint8(tvb, 8 * offset) == dcc_cmd_loco_speed128_val) {

                    // Direction
                    proto_tree_add_boolean ( dcc_rails_tree, hf_dcc_rails_dir_type,   tvb, offset + 1, 1, tvb_get_bits16(tvb, 8 * offset + 8, 1, ENC_BIG_ENDIAN));
                    // Speed
                    proto_tree_add_uint(     dcc_rails_tree, hf_dcc_rails_speed_type, tvb, offset + 1, 2, tvb_get_bits16(tvb, 8 * offset + 9, 7, ENC_BIG_ENDIAN))   ;
                    offset += 2;
                } 

                //
                // Loco - RCN-213 - Chapter 2.2.3 Sonderbetriebsarten-Befehl
                // - 0011-1110 DDDD-DD00
                //
                #define dcc_cmd_loco_special_val 0x3E // 0b0011-1110

                if(tvb_get_uint8(tvb, 8 * offset) == dcc_cmd_loco_special_val) {

                    // Bits 3 und 2: Traktionsbits – Information zur Position in einer Mehrfachtraktion.
                    #define dcc_cmd_loco_trac_msk 0x30 // 0b00TT-xxxx

                    int traction = dcc_cmd_loco_trac_msk & tvb_get_uint8(tvb, 8 * offset);
                    
                    // - 00 Nicht Teil einer Mehrfachtraktion
                    #define dcc_cmd_loco_trac_standalone 0x00
                    if( traction == dcc_cmd_loco_trac_standalone ) {
                        // tbd: enum traction standalone
                    }

                    // Mehrfachtraktion
                    // - 10 Führende Lok
                    #define dcc_cmd_loco_trac_leading    0x20
                    if( traction == dcc_cmd_loco_trac_leading) {
                        // tbd: enum traction leading
                    }
                    // - 01 Mittel-Lok
                    #define dcc_cmd_loco_trac_middle     0x10
                    if( traction == dcc_cmd_loco_trac_middle) {
                        // tbd: enum traction middle
                    }
                    // - 11 Schluss-Lok
                    #define dcc_cmd_loco_trac_trailing   0x30
                    if( traction == dcc_cmd_loco_trac_trailing) {
                        // tbd: enum traction trailing
                    }


                    #define dcc_cmd_loco_rank_msk 0x01 // 0b00xx-Rxxx
                    #define dcc_cmd_loco_rank_len    1
                    // <boolean>

                    offset++;
                }
                //
                // Loco - RCN-213 - Chapter 2.3.1 Funktionssteuerung F0-F4
                // - 100D-DDDD
                //
                #define dcc_loco_func_cmd 0x4 // 0b100x-Rxxx
                #define dcc_loco_func_len   3

                else if( dcc_loco_func_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_func_len)) {

                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 3, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );
                    offset += 1;
                }

                //
                // Loco - RCN-213 - Chapter 2.3.2 Funktionssteuerung F5-F8
                // - 1011-DDDD
                //
                #define dcc_loco_func58_cmd 0xB // 0b1011
                #define dcc_loco_func58_len   4

                else if( dcc_loco_func58_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_func58_len)) {

                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );

                    offset += 1;
                }

                //
                // Loco - RCN-213 - 2.3.3 Funktionssteuerung F9-F12 
                // - 1010-DDDD
                //
                #define dcc_loco_func912_cmd 0xA // 0b1010
                #define dcc_loco_func912_len   4

                else if( dcc_loco_func912_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_func912_len)) {

                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );

                    offset += 1;
                }
                //
                // Loco - RCN-213 - 2.3.4 Funktionssteuerung F13-F68
                // - F13-F20: 1101-1110 DDDD-DDDD
                // - F21-F28: 1101-1111 DDDD-DDDD

                // - F29-F36: 1101-1000 DDDD-DDDD
                // - F37-F44: 1101-1001 DDDD-DDDD
                // - F45-F52: 1101-1010 DDDD-DDDD
                // - F53-F60: 1101-1011 DDDD-DDDD
                // - F61-F68: 1101-1100 DDDD-DDDD
                //
                #define dcc_loco_func1368_cmd 0x1B // 0b11011
                #define dcc_loco_func1368_len    5

                else if( dcc_loco_func1368_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_func1368_len)) {

                    #define dcc_loco_func1320_cmd 0x6 // 0b110
                    #define dcc_loco_func1320_len   3
                    if( dcc_loco_func1320_cmd == tvb_get_bits8(tvb, 8 * offset + dcc_loco_func1368_len, dcc_loco_func1320_cmd)) {
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                        proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );

                        offset += 2;
                    }

                    #define dcc_loco_func2028_cmd 0x7 // 0b111
                    #define dcc_loco_func2028_len   3
                    else if( dcc_loco_func2028_cmd == tvb_get_bits8(tvb, 8 * offset + dcc_loco_func1368_len, dcc_loco_func2028_len)) {
                        offset += 2;
                    }

                    // - F29-F36: 1101-1000 DDDD-DDDD
                    // - F37-F44: 1101-1001 DDDD-DDDD
                    // - F45-F52: 1101-1010 DDDD-DDDD
                    // - F53-F60: 1101-1011 DDDD-DDDD
                    // - F61-F68: 1101-1100 DDDD-DDDD
                    #define dcc_loco_func2968_len   3
                    else {
                        // int block = tvb_get_bits8(tvb, 8 * offset + dcc_loco_func1368_len, dcc_loco_func2968_len);
                        // F(29+block*8)..F(29+block*8 +7)

                        offset += 2;
                    }
                }

                //
                // Loco - RCN-213 - 2.3.5 Binärzustandssteuerungsbefehl kurze Form
                // - 1101-1101 DLLL-LLLL
                //
                #define dcc_loco_bin_short_cmd 0xDD // 0b11011101
                else if(dcc_loco_bin_short_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    offset += 1;
                }

                //
                // Loco - RCN-213 - 2.3.6 Binärzustandssteuerungsbefehl lange Form
                // -  1100-0000 DLLL-LLLL HHHH-HHHH
                //
                #define dcc_loco_bin_long_cmd 0xC0 // 0b11000000
                else if(dcc_loco_bin_long_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    offset += 3;
                }

                //
                // Loco - RCN-213 - 2.3.7 Geschwindigkeit, Richtung und Funktionen
                // - 0011-1100 RGGG-GGGG DDDD-DDDD {DDDD-DDDD {DDDD-DDDD {DDDD-DDDD}}}
                //
                #define dcc_loco_spddrfnc_cmd 0x3C // 0b00111100
                else if(dcc_loco_spddrfnc_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    offset += 3;
                    // ???
                    // tbd: check if more byte or "checksum"
                }
                
                //
                // Loco - RCN-213 - 2.3.8 Analogfunktionsgruppe
                // - 0011-1101 SSSS-SSSS DDDD-DDDD
                //   * SSSS-SSSS = 0000-0001 - Lautstärkesteuerung
                //   * SSSS-SSSS = 0001-0000 bis 0001-1111 - Positionssteuerung
                //   * 0111-1111 sind reserviert
                //   * 1000-0000 bis 1111-1111 können beliebig verwendet werden
                #define dcc_loco_analog_cmd 0x3D // 0b00111100
                else if(dcc_loco_analog_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    // tbd: implementation
                    offset += 3;
                }

                //
                // Loco - RCN-213 - 2.4.1 Mehrfachtraktionsadresse setzen
                // - 0001-001R 0AAA-AAAA (Die Adresse wird in CV19:0..6 gespeichert)
                //
                #define dcc_loco_trac_addr_cmd 0x09 // 0b1001
                #define dcc_loco_trac_addr_len    7

                else if( dcc_loco_trac_addr_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_trac_addr_len)) {
                    // tbd: implementation
                    offset += 2;
                }

                //
                // Loco - RCN-213 - 2.5.1 Rücksetzbefehl
                // - 0000-0000
                //
                #define dcc_loco_reset_cmd 0x0 // 0b00000000
                else if( dcc_loco_reset_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    // tbd: implementation
                    offset += 1;                    
                }

                //
                // Loco - RCN-213 - 2.5.2 Decoder Hard Reset
                // - 0000-0001 (19, 29, 31 und 32 werden zurückgesetzt)
                //
                #define dcc_loco_factory_cmd 0x01 // 0b00000001
                else if( dcc_loco_factory_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    // tbd: implementation
                    offset += 1;                    
                }

                //
                // Loco - RCN-213 - 2.5.4 Setze erweiterte Adressierung (CV #29 Bit 5)
                // - 0000-101D (CV29:0)
                //
                #define dcc_loco_ext_addr_cmd 0x05 // 0b0000101
                #define dcc_loco_ext_addr_len    7

                else if( dcc_loco_ext_addr_cmd == tvb_get_bits8(tvb, 8 * offset, dcc_loco_ext_addr_len)) {
                    // tbd: implementation
                    offset += 1;                    
                }

                //
                // Loco - RCN-213 - 2.5.5 Decoderquittungsanforderung (RailCom)
                // - 0000-1111
                //
                #define dcc_loco_ack_cmd 0x0F // 0b00001111
                else if(dcc_loco_ack_cmd == tvb_get_uint8(tvb, 8 * offset)) {
                    // tbd: implementation
                    offset += 1;                    
                }
                else offset++;
            }
        }

        if(is_accessory) {
            
            //
            // Accessory address - RCN-213 - Chapter 2.1 Paketformat für Einfache Zubehördecoder
            // - 10AA-AAAA 1AAA-DAAR
            //
            if( 1 == tvb_get_bits8(tvb, 8 * offset + 9, 1)) {

                // D
                tvb_get_bits8(tvb, 8 * offset + 12, 1);

                // R
                tvb_get_bits8(tvb, 8 * offset + 15, 1);
                offset += 2;
            }

            //
            // Accessory address - RCN-213 - Chapter 2.2 Paketformat für Erweiterte Zubehördecoder
            // - 10AA-AAAA 0AAA-0AA1 DDDD-DDDD (drei Byte Format) 
            //
            else if(   0 == tvb_get_bits8(tvb, 8 * offset +  9, 1)
                    || 0 == tvb_get_bits8(tvb, 8 * offset + 13, 1) 
                    || 1 == tvb_get_bits8(tvb, 8 * offset + 16, 1) ) {
                offset += 3;
            }

            //
            // Accessory address - RCN-213 - Chapter 2.3 NOP Befehl für einfache und erweiterte Zubehördecoder
            // - 10AA-AAAA 0AAA-1AAT
            else if(   0 == tvb_get_bits8(tvb, 8 * offset +  9, 1)
                    || 1 == tvb_get_bits8(tvb, 8 * offset + 13, 1) ) {
                offset += 2;
            }

        }

        while(tvb_reported_length_remaining(tvb, offset) >= 1) {

            //
            // CV Read/Write long - RCN-214 - 2 Konfigurationsvariablen Zugriffsbefehl - Lange Form 
            //
            if(tvb_get_bits8(tvb, offset * 8, 8) == 0b1110) {
                // CV Address
                proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 1,tvb_get_bits16(tvb, offset * 8 + 4, 12, ENC_BIG_ENDIAN));
                offset += 2;                
                // CV Value
                proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 1,tvb_get_bits16(tvb, offset * 8 + 4, 12, ENC_BIG_ENDIAN));
                offset += 2;                
            }

            //
            // CV Read/Write short - RCN-214 - 3 Konfigurationsvariablen Zugriffsbefehl - Kurze Form 
            //
            else if(tvb_get_bits8(tvb, offset * 8, 8) == 0b1111) {
                // CV Address
                proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 1,tvb_get_bits16(tvb, offset * 8 + 4, 12, ENC_BIG_ENDIAN));
                offset += 2;                
                // CV Value
                proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 1,tvb_get_bits16(tvb, offset * 8 + 4, 12, ENC_BIG_ENDIAN));
                offset += 2;           

                // https://normen.railcommunity.de/RCN-225.pdf
                // https://www.nmra.org/sites/default/files/s-9.2.2_2012_10.pdf
            } else {
                offset += 2;
            }
        }
    }

#if 0    
    if(pinfo->p2p_dir == P2P_DIR_RECV) {

        proto_item_append_text(ti, " - Inbound Stuff (Railcom)");

        /*
         * tbd: Railcom Decoding
         */

    }
#endif    

    return tvb_captured_length(tvb);
}

void
proto_register_dcc_rails(void)
{

    static hf_register_info hf[] = {
        { &hf_dcc_rails_addr_type,
            { "Address", "dcc-rails.addr",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_speed_type,
            { "Speed", "dcc-rails.speed",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_dir_type,
            { "Direction", "dcc-rails.dir",
            FT_BOOLEAN, 8,
            TFS(&tfs_forward_backward), 0x1,
            NULL, HFILL }
        },
        { &hf_dcc_rails_func_type,
            { "Function", "dcc-rails.func",
            FT_BOOLEAN, 8,
            TFS(&tfs_on_off), 0x1,
            NULL, HFILL }
        },
        { &hf_dcc_rails_cv_addr_type,
            { "CV address", "dcc-rails.cv.addr",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_cv_value_type,
            { "CV value", "dcc-rails.cv.value",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_dcc_rails
    };

    proto_dcc_rails = proto_register_protocol ("DCC Rails",  "DCC_RAILS", "dcc-rails");

    proto_register_field_array(proto_dcc_rails, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dcc_rails_handle = register_dissector("dcc-rails", dissect_dcc_rails, proto_dcc_rails);
}

void
proto_reg_handoff_dcc_rails(void)
{
    dcc_rails_handle = create_dissector_handle(dissect_dcc_rails, proto_dcc_rails);

	// Use temporary "WTAP_ENCAP_USER13" until final protocol is accepted
	dissector_add_uint("wtap_encap", WTAP_ENCAP_USER13, dcc_rails_handle);
}

