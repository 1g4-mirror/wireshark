#ifndef _EAF1_HELPERS_H
#define _EAF1_HELPERS_H

#include <cstdint>

#include <epan/epan.h>
#include <epan/address.h>
#include <epan/packet.h>

void add_vehicle_index_and_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, int offset);

#endif
