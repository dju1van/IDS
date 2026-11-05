#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include "decoder.h"

// Helper function to decode transport layer headers (TCP/UDP) and extract port information
static decode_status decode_transport(const uint8_t *data, size_t captured_length, decoded_packet *out, size_t *header_length_out, size_t *payload_length_out) {
    size_t header_length;
    size_t payload_length;
    // TCP
    if(out->protocol == 6) {
        if(captured_length < 20) {
            return DECODE_MALFORMED;
        }
        header_length = (size_t)(data[12] >> 4) * 4;
        if(header_length < 20 || header_length > captured_length) {
            return DECODE_MALFORMED;
        }
        payload_length = captured_length - header_length;
    } else if(out->protocol == 17) { // UDP
        if(captured_length < 8) {
            return DECODE_MALFORMED;
        }
        header_length = 8;
        size_t udp_length = ((size_t)data[4] << 8) | data[5];
        if(udp_length < header_length || udp_length > captured_length) {
            return DECODE_MALFORMED;
        }
        payload_length = udp_length - header_length;
    } else {
        return DECODE_UNSUPPORTED;
    }

    out->src_port = ((uint16_t)data[0] << 8) | data[1];
    out->dst_port = ((uint16_t)data[2] << 8) | data[3];
    *header_length_out = header_length;
    *payload_length_out = payload_length;
    return DECODE_OK;
}
// Helper function to decode IPv4 packets and extract transport layer information
static decode_status decode_ipv4(const uint8_t *data, size_t captured_length, decoded_packet *out, size_t *header_length_out, size_t *total_length_out) {
    if(captured_length < 20) {
        return DECODE_MALFORMED;
    }

    uint8_t version = data[0] >> 4;
    uint8_t ihl = data[0] & 0x0F;
    size_t ip_header_length = (size_t)ihl * 4;
    size_t ip_total_length = ((size_t)data[2] << 8) | data[3];
    uint16_t fragment_field = ((uint16_t)data[6] << 8) | data[7];

    if(version != 4 || ihl < 5 || ip_header_length > captured_length ||
       ip_total_length < ip_header_length || ip_total_length > captured_length) {
        return DECODE_MALFORMED;
    }
    if(fragment_field & 0x3FFF) {
        return DECODE_UNSUPPORTED;
    }

    out->protocol = data[9];
    memcpy(out->src_ip, &data[12], 4);
    memcpy(out->dst_ip, &data[16], 4);
    *header_length_out = ip_header_length;
    *total_length_out = ip_total_length;
    return DECODE_OK;
}
// Helper function to decode Ethernet frames and check for IPv4 packets
static decode_status decode_ethernet(const uint8_t *data, size_t captured_length) {
    if(captured_length < 14) {
        return DECODE_MALFORMED;
    }
    uint16_t ethertype = (data[12] << 8) | data[13];
    // Not an IPv4 packet
    if(ethertype != 0x0800) {
        return DECODE_UNSUPPORTED;
    }
    return DECODE_OK;
}

decode_status decode_packet(const uint8_t *data, size_t captured_length, int link_type, decoded_packet *out) {
    // Check for null pointers and unsupported link types
    if(data == NULL || out == NULL) {
        return DECODE_MALFORMED;
    }
    *out = (decoded_packet){0};
    if(link_type != DLT_EN10MB) {
        return DECODE_UNSUPPORTED;
    }
    // Parse the Ethernet frame to check for IPv4 packets
    decode_status status = decode_ethernet(data, captured_length);
    if(status != DECODE_OK) {
        return status;
    }
    size_t ethernet_header_length = 14;
    // Parse the IPv4 header
    size_t ip_header_length;
    size_t ip_total_length;
    status = decode_ipv4(data + ethernet_header_length,
                         captured_length - ethernet_header_length,
                         out, &ip_header_length, &ip_total_length);
    if(status != DECODE_OK) {
        return status;
    }

    size_t transport_header_length;
    size_t transport_payload_length;
    size_t ip_payload_length = ip_total_length - ip_header_length;
    status = decode_transport(data + ethernet_header_length + ip_header_length,
                              ip_payload_length, out,
                              &transport_header_length, &transport_payload_length);
    if(status != DECODE_OK) {
        return status;
    }

    out->payload_offset = ethernet_header_length + ip_header_length + transport_header_length;
    out->payload_length = transport_payload_length;
    
    return DECODE_OK;
}
