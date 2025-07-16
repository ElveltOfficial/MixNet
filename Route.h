#ifndef ROUTE_H
#define ROUTE_H

#include <stdint.h>
#include "Peer.h"

#define MAX_ROUTE_LEN 10

int generate_random_route(const Peer* peers, int peer_count,
    uint8_t src_id, uint8_t dst_id,
    uint8_t out_route[MAX_ROUTE_LEN], uint8_t* out_len);

#endif
