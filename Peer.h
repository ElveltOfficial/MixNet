#ifndef PEER_H
#define PEER_H

#include <stdint.h>

#define MAX_PEERS 50
#define PUBLIC_KEY_BYTES 32

typedef struct {
    uint8_t id;
    char ip[64];
    uint16_t port;
    uint8_t public_key[PUBLIC_KEY_BYTES];
} Peer;

extern Peer g_peers[MAX_PEERS];
extern int g_peer_count;

Peer* get_peer_by_id(uint8_t id);

#endif
