#ifndef _EAF1_HELPERS_H
#define _EAF1_HELPERS_H

#include <cstdint>

#include <epan/epan.h>
#include <epan/address.h>
#include <epan/packet.h>

const char *lookup_driver_name(int proto, uint32_t packet_number, const address &src_addr, uint32_t src_port, uint8_t vehicle_index);
proto_item *add_vehicle_index_and_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, int offset);
proto_item *add_driver_name(int proto, proto_tree *tree, int header_field, packet_info *pinfo, tvbuff_t *tvb, uint8_t participant_index);
void add_sector_time(proto_tree *tree, int header_field_time, int header_field_timems, int header_field_timemin, int ett, packet_info *pinfo, tvbuff_t *tvb, size_t msoffset, size_t minoffset);

#endif
