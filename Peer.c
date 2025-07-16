#include "Peer.h"
#include <string.h>

Peer g_peers[MAX_PEERS];
int g_peer_count = 0;

Peer* get_peer_by_id(uint8_t id) {
    for (int i = 0; i < g_peer_count; ++i) {
        if (g_peers[i].id == id) {
            return &g_peers[i];
        }
    }
    return NULL;
}
