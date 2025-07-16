#ifndef TRACKER_H
#define TRACKER_H

#include <stdint.h>

int register_to_tracker(uint8_t my_id, const char* my_ip, uint16_t my_port, const uint8_t* public_key);
int update_peer_list_from_tracker();

#endif
