#include "Tracker.h"
#include "Peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define TRACKER_IP "127.0.0.1"
#define TRACKER_PORT 9000

int my_id = -1;

static int connect_to_tracker() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[Client] WSAStartup failed\n");
        return -1;
    }
#endif
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TRACKER_PORT);
    addr.sin_addr.s_addr = inet_addr(TRACKER_IP);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return -1;
    }

    return sock;
}

int register_to_tracker(uint8_t my_id, const char* my_ip, uint16_t my_port, const uint8_t* public_key) {
    int sock = connect_to_tracker();
    if (sock < 0) {
        fprintf(stderr, "[Client] connect_to_tracker() failed\n");
        return -1;
    }

    char pubkey_hex[65] = { 0 };
    for (int i = 0; i < 32; ++i) {
        sprintf(pubkey_hex + i * 2, "%02x", public_key[i]);
    }

    char message[256];
    snprintf(message, sizeof(message), "REGISTER %d %s %d %s\n", my_id, my_ip, my_port, pubkey_hex);
    printf("[Client] Sending to tracker: %s", message);

    int sent = send(sock, message, (int)strlen(message), 0);
    if (sent <= 0) {
        fprintf(stderr, "[Client] Failed to send registration message\n");
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return -1;
    }

    char buffer[64] = { 0 };
    int len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (len <= 0) {
        fprintf(stderr, "[Client] Failed to receive assign message\n");
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return -1;
    }
    buffer[len] = '\0';

    int assigned_id = -1;
    if (sscanf(buffer, "ASSIGN %d", &assigned_id) != 1) {
        fprintf(stderr, "[Client] Unexpected assign message format: %s\n", buffer);
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return -1;
    }

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif

    printf("[Client] Assigned ID from tracker: %d\n", assigned_id);
    return assigned_id;
}

static int hexstr_to_bytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        sscanf(hex + 2 * i, "%2hhx", &out[i]);
    }
    return 0;
}

int update_peer_list_from_tracker() {
    int sock = connect_to_tracker();
    if (sock < 0) {
        fprintf(stderr, "Failed to connect to tracker\n");
        return -1;
    }

    const char* msg = "GET\n";
    if (send(sock, msg, strlen(msg), 0) <= 0) {
        fprintf(stderr, "Failed to send GET to tracker\n");
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return -1;
    }

    char buffer[4096];
    int len = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (len <= 0) {
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        fprintf(stderr, "Failed to receive peer list from tracker\n");
        return -1;
    }

    buffer[len] = '\0';
    g_peer_count = 0;

    char* line = strtok(buffer, "\n");
    while (line) {
        if (strncmp(line, "PEERS", 5) == 0 || strncmp(line, "END", 3) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        int id, port;
        char ip[64], hexkey[65];
        if (sscanf(line, "%d %63s %d %64s", &id, ip, &port, hexkey) == 4) {
            if (g_peer_count >= MAX_PEERS) break;
            Peer* p = &g_peers[g_peer_count++];
            p->id = (uint8_t)id;
            strncpy(p->ip, ip, sizeof(p->ip) - 1);
            p->ip[sizeof(p->ip) - 1] = '\0';
            p->port = (uint16_t)port;
            if (hexstr_to_bytes(hexkey, p->public_key, 32) != 0) {
                fprintf(stderr, "Invalid hex key from tracker for peer %d\n", id);
            }
        }
        else {
            fprintf(stderr, "Invalid peer line format: %s\n", line);
        }

        line = strtok(NULL, "\n");
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    fprintf(stderr, "Peer list updated. Peer count: %d\n", g_peer_count);

    return 0;
}

