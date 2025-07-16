#include "Route.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static int contains(const uint8_t* arr, int len, uint8_t val) {
    for (int i = 0; i < len; ++i) {
        if (arr[i] == val) return 1;
    }
    return 0;
}

int generate_random_route(const Peer* peers, int peer_count,
    uint8_t src_id, uint8_t dst_id,
    uint8_t out_route[MAX_ROUTE_LEN], uint8_t* out_len) {

    if (peer_count <= 0 || !out_route || !out_len) return -1;

    if (src_id == dst_id) {
        out_route[0] = src_id;
        *out_len = 1;
        return 0;
    }

    uint8_t used[MAX_ROUTE_LEN] = { 0 };
    int used_len = 0;

    out_route[0] = src_id;
    used[used_len++] = src_id;

    int max_hops = (rand() % (MAX_ROUTE_LEN - 2)) + 2;

    int current_len = 1;

    while (current_len < max_hops - 1) {
        int candidate_found = 0;
        for (int attempts = 0; attempts < 10; ++attempts) {
            int idx = rand() % peer_count;
            uint8_t candidate_id = peers[idx].id;

            if (candidate_id == src_id || candidate_id == dst_id) continue;
            if (contains(used, used_len, candidate_id)) continue;

            out_route[current_len++] = candidate_id;
            used[used_len++] = candidate_id;
            candidate_found = 1;
            break;
        }

        if (!candidate_found) {
            break;
        }
    }

    out_route[current_len++] = dst_id;

    *out_len = (uint8_t)current_len;

    printf("[Route] Generated route: ");
    for (int i = 0; i < *out_len; ++i) {
        printf("%d ", out_route[i]);
    }
    printf("\n");

    return 0;
}
