#pragma once

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "IPHLPAPI.lib")
#include "Address.h"

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace address;

struct DeviceMacs
{
    addrMac self;
    addrMac router;
};

class NetworkUtils
{
public:
    // Get the MAC address of the device (self)
    static addrMac getSelfMac(const std::string& deviceName);

    // Get the router's MAC address (router)
    static addrMac getRouterMac(const std::string& deviceName);

    // Get both self and router MAC addresses
    static DeviceMacs getDeviceMacs(const std::string& deviceName);
};
