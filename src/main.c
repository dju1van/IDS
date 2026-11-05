#include <stdio.h>
#include <stdlib.h>
#include "capture.h"

#define INTERFACE_NAME 256

int main() {
    char interface_name[INTERFACE_NAME];
    // Select the network interface to capture packets from
    if(select_interface(interface_name, INTERFACE_NAME)) {
        fprintf(stderr, "Failed to select a valid network interface.\n");
        return EXIT_FAILURE;
    }
    // Initialize packet capture on the selected interface
    if(start_capture(interface_name)) {
        fprintf(stderr, "Failed to initialize packet capture on interface: %s\n", interface_name);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}