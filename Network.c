#include "Network.h"
#include "Peer.h"
#include "Crypto.h"
#include "Packet.h"
#include "Tracker.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
#pragma comment(lib, "ws2_32.lib")
typedef SSIZE_T ssize_t;
typedef int socklen_t;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

static int create_udp_socket(uint16_t port) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return -1;
    }
#endif

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        perror("bind");
        return -1;
    }

    return sock;
}

int send_packet(const Peer* to, const EncryptedPacket* packet) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(to->port);
    inet_pton(AF_INET, to->ip, &addr.sin_addr);

    int ret = sendto(sock, (const char*)packet, sizeof(EncryptedPacket), 0,
        (struct sockaddr*)&addr, sizeof(addr));

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    return ret;
}

void start_receiver(uint8_t my_id, const uint8_t my_private_key[32]) {
    Peer* self = get_peer_by_id(my_id);
    if (!self) {
        fprintf(stderr, "My ID not found in peers\n");
        return;
    }

    int sock = create_udp_socket(self->port);
    if (sock < 0) {
        fprintf(stderr, "Failed to open socket\n");
        return;
    }

    printf("[Node %d] Listening on port %d...\n", my_id, self->port);

    time_t last_update = 0;

    while (1) {
        EncryptedPacket packet;
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);

        ssize_t len = recvfrom(sock, (char*)&packet, sizeof(packet), 0,
            (struct sockaddr*)&src, &slen);
        if (len <= 0) continue;

        printf("[Node %d] Received packet: msg_id=%u seq=%d total=%d sender_id=%d hop_index=%d hop_count=%d\n",
            my_id, packet.message_id, packet.seq, packet.total,
            packet.sender_id, packet.hop_index, packet.hop_count);
        printf("[Node %d] Checking packet route[%d] = %d\n", my_id, packet.hop_index, packet.route[packet.hop_index]);

        if (packet.hop_index >= packet.hop_count) {
            printf("[Node %d] Invalid hop_index, ignoring packet\n", my_id);
            continue;
        }

        if (packet.route[packet.hop_index] != my_id) {
            printf("[Node %d] Packet not for this node, ignoring\n", my_id);
            continue;
        }

        Peer* sender = get_peer_by_id(packet.sender_id);
        if (!sender) {
            printf("[Node %d] Sender peer unknown, updating peer list...\n", my_id);
            if (time(NULL) - last_update > 5) {
                update_peer_list_from_tracker();
                last_update = time(NULL);
            }
            sender = get_peer_by_id(packet.sender_id);
            if (!sender) {
                printf("[Node %d] Still unknown. Cannot decrypt.\n", my_id);
                continue;
            }
        }

        if (packet.hop_index == packet.hop_count - 1) {
            if (packet.hop_index == 0) {
                uint8_t shared_key[32];
                generate_shared_key(shared_key, my_private_key, sender->public_key);

                printf("[Node %d] Final hop decryption key: ", my_id);
                for (int i = 0; i < 32; ++i) printf("%02x", shared_key[i]);
                printf("\n");

                uint8_t decrypted[1024];
                int decrypted_len = decrypt_packet(&packet, shared_key, decrypted, sizeof(decrypted));
                if (decrypted_len > 0) {
                    if (decrypted_len < sizeof(decrypted)) {
                        decrypted[decrypted_len] = '\0';
                    }
                    else {
                        decrypted[sizeof(decrypted) - 1] = '\0';
                    }
                    printf("[Node %d] Decrypted message: %s\n", my_id, decrypted);
                }
                else {
                    printf("[Node %d] Failed to decrypt packet\n", my_id);
                }
            }
            else {
                uint8_t prev_hop_id = packet.route[packet.hop_index - 1];
                Peer* prev_hop = get_peer_by_id(prev_hop_id);
                if (!prev_hop) {
                    printf("[Node %d] Previous hop peer %d not found\n", my_id, prev_hop_id);
                    continue;
                }
                uint8_t shared_key[32];
                generate_shared_key(shared_key, my_private_key, prev_hop->public_key);

                printf("[Node %d] Final hop decryption key: ", my_id);
                for (int i = 0; i < 32; ++i) printf("%02x", shared_key[i]);
                printf("\n");

                uint8_t decrypted[1024];
                int decrypted_len = decrypt_packet(&packet, shared_key, decrypted, sizeof(decrypted));
                if (decrypted_len > 0) {
                    if (decrypted_len < sizeof(decrypted)) {
                        decrypted[decrypted_len] = '\0';
                    }
                    else {
                        decrypted[sizeof(decrypted) - 1] = '\0';
                    }
                    printf("[Node %d] Decrypted message: %s\n", my_id, decrypted);
                }
                else {
                    printf("[Node %d] Failed to decrypt packet\n", my_id);
                }
            }
        }
        else {
            if (packet.hop_index == 0) {
                printf("[Node %d] Unexpected hop_index=0 at relay, ignoring\n", my_id);
                continue;
            }
            uint8_t prev_hop_id = packet.route[packet.hop_index - 1];
            Peer* prev_hop = get_peer_by_id(prev_hop_id);
            if (!prev_hop) {
                printf("[Node %d] Previous hop peer %d not found\n", my_id, prev_hop_id);
                continue;
            }

            uint8_t next_hop_id = packet.route[packet.hop_index + 1];
            Peer* next_hop = get_peer_by_id(next_hop_id);
            if (!next_hop) {
                printf("[Node %d] Next hop peer %d not found\n", my_id, next_hop_id);
                continue;
            }

            uint8_t shared_key[32];
            generate_shared_key(shared_key, my_private_key, prev_hop->public_key);

            printf("[Node %d] Relay decryption key: ", my_id);
            for (int i = 0; i < 32; ++i) printf("%02x", shared_key[i]);
            printf("\n");

            uint8_t decrypted[MAX_PAYLOAD_SIZE];
            int decrypted_len = decrypt_packet(&packet, shared_key, decrypted, sizeof(decrypted));
            if (decrypted_len <= 0) {
                printf("[Node %d] Failed to decrypt packet\n", my_id);
                continue;
            }

            uint8_t next_shared_key[32];
            generate_shared_key(next_shared_key, my_private_key, next_hop->public_key);

            printf("[Node %d] Relay encryption key for next hop %d: ", my_id, next_hop_id);
            for (int i = 0; i < 32; ++i) printf("%02x", next_shared_key[i]);
            printf("\n");

            EncryptedPacket forward_pkt = packet;
            forward_pkt.hop_index++;
            randombytes_buf(forward_pkt.nonce, sizeof(forward_pkt.nonce));
            chacha20_encrypt(forward_pkt.encrypted, decrypted, decrypted_len,
                next_shared_key, forward_pkt.nonce);

            forward_pkt.payload_len = (uint16_t)decrypted_len;

            if (send_packet(next_hop, &forward_pkt) < 0) {
                printf("[Node %d] Failed to forward packet to %d\n", my_id, next_hop_id);
            }
            else {
                printf("[Node %d] Forwarded packet to %d\n", my_id, next_hop_id);
            }
        }
    }
}
