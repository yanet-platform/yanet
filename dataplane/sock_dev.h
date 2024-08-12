#pragma once

#include <cstdint>
#include <string>

//#define SOCK_DEV_PREFIX "sock_dev:"
using namespace std::string_literals;
const std::string SOCK_DEV_PREFIX = "sock_dev:"s;

int sock_dev_create(const char* path, const char* name, uint8_t numa_node);
