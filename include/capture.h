#include <stddef.h>

#ifndef CAPTURE_H
#define CAPTURE_H

int start_capture(const char *dev_name);
int select_interface(char *out_name, size_t out_name_size);

#endif