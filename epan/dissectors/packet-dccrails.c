 #include "config.h"
#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/tfs.h>

#define DCC_RAILSPORT 1234

static int proto_dcc_rails;
static dissector_handle_t dcc_rails_handle;


// === Glossary ===
//
// - EPAN Tree Type (ETT)
// - Header Type (HF)
// - Protocol Data Unit (PDU)
static int hf_dcc_rails_addr_type;
static int hf_dcc_rails_dir_type;
static int hf_dcc_rails_speed_type;
static int hf_dcc_rails_func_type;
static int hf_dcc_rails_cv_addr_type;
static int hf_dcc_rails_cv_value_type;

static int ett_dcc_rails;

/*
static const value_string dccrails_address_type[] = {
    //
    // RCN-212 - Chapter "2 Befehlspakete für Fahrzeugdecoder"
    //
    { 0b0,  "Locomotive Short" }, //  7-bit address,  '0' prefix on first byte
    { 0b11, "Locomotive Long" },  // 14-bit address, '11' prefix on first byte
    //
    // RCN-213 - Chapter "2.1 Paketformat für Einfache Zubehördecoder"
    //
    { 0b10, "Accessory" },  // 14-bit address, '11' prefix on first byte
    { 0, NULL }
};

//
// RCN-212 - Chapter "2.1 Befehlscodierung"
//
static const value_string dccrails_loco_groups[] = {
    { 0b0000, "Decodersteuerungsbefehl" }, 
    { 0b0001, "Mehrfachtraktionssteuerungsbefehle" }, 
    { 0b001,  "Erweiterte Betriebsbefehle" }, 
    { 0b01,   "Basis Geschwindigkeits- und Richtungsbefehl" }, 
    { 0b10,   "Funktionsgruppen" },
    { 0, NULL }
};

//
// RCN-212 - Chapter "2.2.1 Basis Geschwindigkeits- und Richtungsbefehl"
//
static const value_string dccrails_loco_direction[] = {
    { 0b0,  "Rückwärts" }, 
    { 0b10, "Vorwärts" },
    { 0, NULL }
};

//
// RCN-212 - Chapter "2.3.x Funktionssteuerung Fx-Fy"
// - TWo bytes
//
static const value_string dccrails_loco_function_groups[] = {
    { 0b100,       "F0  bis F4"   }, // 5-bit payload (F0, F4, F3, F2, F1)
    { 0b1011,      "F5  bis F8"   }, // 4-bit payload (F5..F8)
    { 0b1010,      "F9  bis F12"  }, // 4-bit payload (F9..F12)
    { 0b11011110,  "F13 bis F20"  }, // 8-bit payload (F13..F20)
    { 0b11011111,  "F21 bis F28"  }, // 8-bit payload (F21..F28)
    { 0b11011000,  "F29 bis F36"  }, // 8-bit payload (F29..F36)
    { 0b11011001,  "F37 bis F44"  }, // 8-bit payload (F37..F44)
    { 0b11011010,  "F45 bis F52"  }, // 8-bit payload (F45..F52)
    { 0b11011011,  "F53 bis F60"  }, // 8-bit payload (F53..F60)
    { 0b11011100,  "F61 bis F68"  }, // 8-bit payload (F61..F68)
    { 0, NULL }
};
*/

static int
dissect_dcc_rails(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    proto_item *ti; // , *expert_ti;
    proto_tree *dcc_rails_tree;

    unsigned offset = 0;
    // int      len    = 0;

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
        // Loco - Short address - RCN-212 - Chapter 2 Befehlspakete für Fahrzeugdecoder
        //
        if(tvb_get_bits8(tvb, 0, 1) == 0b0 ) { // https://www.wireshark.org/docs/wsar_html/tvbuff_8h.html
    
            is_loco = true;
            dcc_address = tvb_get_bits8(tvb, 1, 7);
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset++, 1, dcc_address );
        } 

        //
        // Loco - Long address - RCN-213 - Chapter 2 Befehlspakete für Fahrzeugdecoder 
        //
        else if(tvb_get_bits8(tvb, 0, 2) == 0b11 ) {

            is_loco = true;
            dcc_address = tvb_get_bits16(tvb, 2, 14, ENC_BIG_ENDIAN);
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 2, dcc_address );
            offset += 2;
        }

        //
        // Accessory address - RCN-213 - Chapter 2.1 Paketformat für Einfache Zubehördecoder
        //
        else if(tvb_get_bits8(tvb, 0, 2) == 0b10 ) {

            is_accessory = true;
            dcc_address  =  tvb_get_bits16( tvb,  2, 2, ENC_BIG_ENDIAN ) << 6;
            dcc_address |=  tvb_get_bits16( tvb,  5, 4, ENC_BIG_ENDIAN ) << 2;
            dcc_address |=  tvb_get_bits16( tvb,  9, 3, ENC_BIG_ENDIAN ) << 8;
            dcc_address |=  tvb_get_bits16( tvb, 13, 2, ENC_BIG_ENDIAN );
            proto_tree_add_uint(dcc_rails_tree, hf_dcc_rails_addr_type, tvb, offset, 2, dcc_address );
            offset += 2;
        }

        if(is_loco) {

            while(tvb_reported_length_remaining(tvb, offset) >= 1) {

                //
                // Loco - RCN-213 - Chapter 2.2.2 128 Geschwindigkeitsstufen-Befehl 
                //
                if(tvb_get_bits8(tvb, 8 * offset, 8) == 0b00111111) {

                    // Direction
                    proto_tree_add_boolean ( dcc_rails_tree, hf_dcc_rails_dir_type,   tvb, offset + 1, 1, tvb_get_bits16(tvb, 8 * offset + 8, 1, ENC_BIG_ENDIAN));
                    // Speed
                    proto_tree_add_uint(     dcc_rails_tree, hf_dcc_rails_speed_type, tvb, offset + 1, 2, tvb_get_bits16(tvb, 8 * offset + 1, 7, ENC_BIG_ENDIAN));
                    offset += 2;
                } 

                //
                // Loco - RCN-213 - Chapter 2.3.1 Funktionssteuerung F0-F4
                //
                else if(tvb_get_bits8(tvb, 8 * offset, 3) == 0b100) {

                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 3, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 7, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 6, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 5, 1) );
                    proto_tree_add_boolean (dcc_rails_tree, hf_dcc_rails_func_type, tvb, offset, 1, tvb_get_bits8(tvb, 8 * offset + 4, 1) );
                    offset += 1;
                }

                else offset++;
            }
        }

        if(is_accessory) {

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
            }
        }
     }
    if(pinfo->p2p_dir == P2P_DIR_RECV) {

        proto_item_append_text(ti, " - Inbound Stuff (Railcom)");

        /*
         * tbd: Railcom Decoding
         */

    }

    return tvb_captured_length(tvb);
}

static const true_false_string dcc_rails_map_direction_bool_val  = {
    "Forward",
    "Backward"
};

static const true_false_string dcc_rails_map_function_bool_val  = {
    "On",
    "Off"
};

void
proto_register_dcc_rails(void)
{

    static hf_register_info hf[] = {
        { &hf_dcc_rails_addr_type,
            { "Address", "dcc.type",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_speed_type,
            { "Speed", "dcc.speed",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_dir_type,
            { "Direction", "dcc.dir",
            FT_BOOLEAN, 8,
            TFS(&dcc_rails_map_direction_bool_val), 0x1,
            NULL, HFILL }
        },
        { &hf_dcc_rails_func_type,
            { "Function", "dcc.func",
            FT_BOOLEAN, 8,
            TFS(&dcc_rails_map_function_bool_val), 0x1,
            NULL, HFILL }
        },
        { &hf_dcc_rails_cv_addr_type,
            { "CV address", "dcc.cv.addr",
            FT_UINT8, 
            BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_dcc_rails_cv_value_type,
            { "CV value", "dcc.cv.value",
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

    proto_dcc_rails = proto_register_protocol (
        "DCC Rails", /* name        */
        "DCC_RAILS", /* short_name  */
        "dcc-rails"  /* filter_name */
        );
    register_dissector("dcc-rails", dissect_dcc_rails, proto_dcc_rails);

    proto_register_field_array(proto_dcc_rails, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcc_rails(void)
{
    dcc_rails_handle = create_dissector_handle(dissect_dcc_rails, proto_dcc_rails);

	// Use temporary "WTAP_ENCAP_USER13" until final protocol is accepted
	dissector_add_uint("wtap_encap", WTAP_ENCAP_USER13, dcc_rails_handle);
}

