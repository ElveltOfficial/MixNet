#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include "Peer.h"
#include "Packet.h"
#include "Route.h"

int send_packet(const Peer* to, const EncryptedPacket* packet);

int forward_packet(uint8_t my_id, const uint8_t my_private_key[32],
    const EncryptedPacket* packet);

void start_receiver(uint8_t my_id, const uint8_t my_private_key[32]);

#endif