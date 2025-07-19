#include "Crypto.h"
#include "Peer.h"
#include "Packet.h"
#include "Route.h"
#include "Network.h"
#include "Tracker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <pthread.h>
#endif

#define PORT_MIN 27000
#define PORT_MAX 28000

static uint16_t my_port = 0;
static uint8_t my_id = 0;
static uint8_t my_public_key[PUBLIC_KEY_BYTES];
static uint8_t my_private_key[PRIVATE_KEY_BYTES];

extern Peer g_peers[];
extern int g_peer_count;

Peer* get_peer_by_eid(const char* eid_hex) {
    uint8_t eid_bin[PUBLIC_KEY_BYTES];
    if (strlen(eid_hex) != PUBLIC_KEY_BYTES * 2) return NULL;

    for (int i = 0; i < PUBLIC_KEY_BYTES; i++) {
        if (sscanf(eid_hex + i * 2, "%2hhx", &eid_bin[i]) != 1) return NULL;
    }

    for (int i = 0; i < g_peer_count; i++) {
        if (memcmp(g_peers[i].public_key, eid_bin, PUBLIC_KEY_BYTES) == 0) {
            return &g_peers[i];
        }
    }
    return NULL;
}

#ifdef _WIN32
unsigned __stdcall receiver_thread(void* arg) {
    start_receiver(my_id, my_private_key);
    return 0;
}
#else
void* receiver_thread(void* arg) {
    start_receiver(my_id, my_private_key);
    return NULL;
}
#endif

int main() {
    srand((unsigned)time(NULL));
    my_port = (uint16_t)(PORT_MIN + rand() % (PORT_MAX - PORT_MIN + 1));

    if (crypto_init() != 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }

    if (generate_keypair(my_public_key, my_private_key) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return -1;
    }

    const char* my_ip = "127.0.0.1";

    int assigned_id = register_to_tracker(0, my_ip, my_port, my_public_key);
    if (assigned_id <= 0) {
        fprintf(stderr, "Tracker registration failed\n");
        return -1;
    }
    my_id = (uint8_t)assigned_id;
    printf("Assigned my_id: %d\n", my_id);

    if (update_peer_list_from_tracker() != 0) {
        fprintf(stderr, "Tracker peer list fetch failed\n");
        return -1;
    }

#ifdef _WIN32
    uintptr_t hThread = _beginthreadex(NULL, 0, receiver_thread, NULL, 0, NULL);
    if (hThread == 0) {
        fprintf(stderr, "Receiver thread creation failed\n");
        return -1;
    }
#else
    pthread_t tid;
    if (pthread_create(&tid, NULL, receiver_thread, NULL) != 0) {
        fprintf(stderr, "Receiver thread creation failed\n");
        return -1;
    }
#endif

    char line[1024];
    while (1) {
        printf("Enter command (SEND <EID> <MESSAGE>): ");
        if (!fgets(line, sizeof(line), stdin)) break;

        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        if (strncmp(line, "SEND ", 5) == 0) {
            char eid_hex[PUBLIC_KEY_BYTES * 2 + 1] = { 0 };
            char message[1024] = { 0 };
            const char* p = line + 5;

            if (strlen(p) < PUBLIC_KEY_BYTES * 2) {
                fprintf(stderr, "Invalid SEND command: EID too short\n");
                continue;
            }

            strncpy(eid_hex, p, PUBLIC_KEY_BYTES * 2);
            eid_hex[PUBLIC_KEY_BYTES * 2] = '\0';

            const char* msg_start = p + PUBLIC_KEY_BYTES * 2;
            while (*msg_start == ' ') msg_start++;

            if (*msg_start == '\0') {
                fprintf(stderr, "Invalid SEND command: message missing\n");
                continue;
            }
            strncpy(message, msg_start, sizeof(message) - 1);

            Peer* dest_peer = get_peer_by_eid(eid_hex);
            if (!dest_peer) {
                fprintf(stderr, "Target peer with EID %s not found\n", eid_hex);
                if (update_peer_list_from_tracker() == 0) {
                    dest_peer = get_peer_by_eid(eid_hex);
                    if (!dest_peer) {
                        fprintf(stderr, "Still not found after update.\n");
                        continue;
                    }
                }
                else {
                    fprintf(stderr, "Failed to update peer list from tracker\n");
                    continue;
                }
            }

            uint8_t route[MAX_ROUTE_LEN];
            uint8_t route_len = 0;
            if (generate_random_route(g_peers, g_peer_count, my_id, dest_peer->id, route, &route_len) != 0) {
                fprintf(stderr, "Failed to generate route\n");
                continue;
            }

            printf("[Send] Generated route (len=%d): ", route_len);
            for (int i = 0; i < route_len; ++i) {
                printf("%d ", route[i]);
            }
            printf("\n");

            if (route_len < 2 || route[0] != my_id) {
                fprintf(stderr, "Invalid route\n");
                continue;
            }

            Peer* next_hop = get_peer_by_id(route[1]);
            if (!next_hop) {
                fprintf(stderr, "Next hop peer not found\n");
                continue;
            }

            uint8_t shared_key[SHARED_KEY_BYTES];
            if (generate_shared_key(shared_key, my_private_key, next_hop->public_key) != 0) {
                fprintf(stderr, "Failed to generate shared key\n");
                continue;
            }

            size_t msg_len = strlen(message);
            EncryptedPacket packets[16];
            ssize_t pkt_count = create_encrypted_packets(
                (const uint8_t*)message, msg_len, shared_key, (uint32_t)rand(),
                packets, 16, my_id, route, route_len);

            if (pkt_count < 0) {
                fprintf(stderr, "Packet creation failed\n");
                continue;
            }
            if (pkt_count == 0) {
                fprintf(stderr, "No packets created\n");
                continue;
            }

            for (int i = 0; i < pkt_count; ++i) {
                packets[i].hop_index = 1;
            }

            for (int i = 0; i < pkt_count; ++i) {
                int ret = send_packet(next_hop, &packets[i]);
                if (ret < 0) {
                    fprintf(stderr, "Failed to send packet %d to next hop\n", i);
                }
            }

            printf("Sent %zd packets to next hop ID %d\n", pkt_count, next_hop->id);
        }
    }

    return 0;
}
