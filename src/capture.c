#include <pcap.h>
#include <stdio.h>
#include <string.h>

// Function to check if a network interface is up and running
static int is_interface_usable(const pcap_if_t *dev) {
    return dev != NULL && (dev->flags & (PCAP_IF_UP | PCAP_IF_RUNNING)) == (PCAP_IF_UP | PCAP_IF_RUNNING);
}

// Function to select a network interface for packet capture
int select_interface(char *out_name, size_t out_name_size) {
    pcap_if_t *all_devs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Retrieve the list of available network interfaces
    if(pcap_findalldevs(&all_devs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    // Report if no interfaces were found, because no interfaces still counts as success
    if(all_devs == NULL) {
        fprintf(stderr, "No interfaces found.\n");
        return -1;
    }

    printf("Available network interfaces:\n");
    size_t usable_count = 0;
    for(pcap_if_t *dev = all_devs; dev != NULL; dev = dev->next) {
        if(is_interface_usable(dev)) {
            // Display each interface that is up and running
            printf("%s\n", dev->name);
            usable_count++;
        }
    }

    if(!usable_count) {
        fprintf(stderr, "No network interfaces are up and running, IDS cannot start capture.\n");
        pcap_freealldevs(all_devs);
        return -1;
    }

    printf("Enter the name of the interface to capture packets from: ");
    if(fgets(out_name, out_name_size, stdin) == NULL) {
        fprintf(stderr, "Error reading input.\n");
        pcap_freealldevs(all_devs);
        return -1;
    }

    // Sanitize the input by truncating out_name to remove any trailing newline or space characters
    size_t len = strlen(out_name);
    if(len > 0 && (out_name[len - 1] == '\n' || out_name[len - 1] == ' ')) {
        out_name[len - 1] = '\0';
    }

    for(pcap_if_t *dev = all_devs; dev != NULL; dev = dev->next) {
        // If the selected interface is found and is up and running, free the device list and return success
        if(!strcmp(dev->name, out_name)) {
            if(is_interface_usable(dev)) {
                pcap_freealldevs(all_devs);
                return 0; // Interface is valid and ready for capture
            } else {
                fprintf(stderr, "Selected interface is not up or running.\n");
                pcap_freealldevs(all_devs);
                return -1;
            }
        }
    }

    // Free the device list
    pcap_freealldevs(all_devs);
    return -1;
}

// Function for packet callback, called for each captured packet
static void packet_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
    (void)user; // Unused parameter
    (void)bytes; // Unused parameter
    // Print the length of the captured packet
    printf("Captured a packet with length of %u bytes.\n", header->caplen);
}

// Function to start packet capture on the specified network interface
int start_capture(const char *dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the specified network interface for packet capture
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev_name, errbuf);
        return -1;
    }

    printf("Starting packet capture on interface: %s\n", dev_name);

    // Start capturing packets and call the packet_callback function for each captured packet
    if(pcap_loop(handle, 0, packet_callback, NULL) < 0) {
        fprintf(stderr, "Error during packet capture: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    // Close the handle after capturing is done
    pcap_close(handle);
    return 0;
}