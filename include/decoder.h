#ifndef DECODER_H
#define DECODER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    DECODE_OK,
    DECODE_UNSUPPORTED,
    DECODE_MALFORMED    
} decode_status;

typedef struct {
    uint8_t protocol; // Transport layer protocol number
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    size_t payload_offset; // Offset from start of the captured packet
    size_t payload_length;
} decoded_packet;

decode_status decode_packet(const uint8_t *data, size_t captured_length, int link_type, decoded_packet *out);

#endif