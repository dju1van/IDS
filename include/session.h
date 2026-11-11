#ifndef SESSION_H
#define SESSION_H

#include "decoder.h"
#include <stddef.h>
#include <sys/time.h>
// Representation of a one session, which tracks the state of a communication between two endpoints
typedef struct session{
    uint32_t id; // Unique session identifier
    uint8_t protocol; // Session protocol
    uint8_t src_ip[4]; // Packet's metadata
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t packet_count; // Number of packets in the session
    uint64_t payload_bytes; // Total payload bytes in the session
    struct timeval first_seen; // Timestamp of the first packet in the session
    struct timeval last_seen; // Timestamp of the last packet in the session
    struct session *next; // Pointer to the next session in the linked list
} session;

void session_handle_packet(const decoded_packet *packet, const struct timeval *timestamp);

#endif