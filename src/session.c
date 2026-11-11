#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "session.h"

static session *session_list_head = NULL;

static session *find_existing_session(const decoded_packet *packet) {
    // Iterate through the list of known sessions to find a match
    for(session *s = session_list_head; s != NULL; s = s->next) {
        if(s->protocol == packet->protocol) {
            if((memcmp(s->src_ip, packet->src_ip, 4) == 0 &&
               memcmp(s->dst_ip, packet->dst_ip, 4) == 0 &&
               s->src_port == packet->src_port &&
               s->dst_port == packet->dst_port) ||
               (memcmp(s->src_ip, packet->dst_ip, 4) == 0 &&
               memcmp(s->dst_ip, packet->src_ip, 4) == 0 &&
               s->src_port == packet->dst_port &&
               s->dst_port == packet->src_port)) {
                return s; // Found a session
            }
        }
    }
    return NULL; // No matching session found
}

static void update_session(session *existing_session, const decoded_packet *packet, const struct timeval *timestamp) {
    existing_session->packet_count++;
    existing_session->payload_bytes += packet->payload_length;
    existing_session->last_seen = *timestamp;
}

static int create_new_session(const decoded_packet *packet, const struct timeval *timestamp) {
    // Allocate memory for a new session
    session *new_session = malloc(sizeof(session));
    // Create static session identifier counter
    static uint32_t session_id_counter = 0;
    if(new_session == NULL) {
        fprintf(stderr, "Error: Failed to allocate memory for new session\n");
        return -1;
    }
    // Initialize the new session with the packet's metadata
    new_session->id = session_id_counter++; // Assign a unique ID
    new_session->protocol = packet->protocol;
    memcpy(new_session->src_ip, packet->src_ip, 4);
    memcpy(new_session->dst_ip, packet->dst_ip, 4);
    new_session->src_port = packet->src_port;
    new_session->dst_port = packet->dst_port;
    new_session->packet_count = 1;
    new_session->payload_bytes = packet->payload_length;
    new_session->first_seen = *timestamp;
    new_session->last_seen = *timestamp;
    // Add the new session to the list
    new_session->next = session_list_head;
    session_list_head = new_session;
    return 0;
}

static void free_inactive_sessions(const struct timeval *current_time) {
    session **indirect = &session_list_head;
    while(*indirect != NULL) {
        session *s = *indirect;
        // Get time difference in seconds
        double time_diff = (current_time->tv_sec - s->last_seen.tv_sec) +
                           (current_time->tv_usec - s->last_seen.tv_usec) / 1000000.0;
        if(time_diff > 300.0) { // 5 minutes
            // Remove the session from the list and free memory
            *indirect = s->next;
            free(s);
        } else {
            indirect = &s->next; // Move to the next session
        }
    }
}

void session_handle_packet(const decoded_packet *packet, const struct timeval *timestamp) {
    // Free sessions that have been inactive for more than 5 minutes
    free_inactive_sessions(timestamp);
    // Try to find an existing session that matches the packet's metadata
    session *existing_session = find_existing_session(packet);
    if (existing_session) {
        // Update the existing session with the new packet information
        update_session(existing_session, packet, timestamp);
    } else {
        // Create a new session for this packet
        if(create_new_session(packet, timestamp) != 0) {
            fprintf(stderr, "Error: Failed to create new session\n");
        }
    }
}