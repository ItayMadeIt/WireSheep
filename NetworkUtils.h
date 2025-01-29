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
    AddrMac host;
    AddrMac router;
};

struct DeviceIPv4
{
    AddrIPv4 host;
    AddrIPv4 router;
};

class NetworkUtils
{
public:
    // Get the MAC address of the device (self)
    static AddrMac getSelfMac(const std::string& deviceName);

    // Get the router's MAC address (router)
    static AddrMac getRouterMac(const std::string& deviceName);

    // Get both self and router MAC addresses
    static DeviceMacs getDeviceMacs(const std::string& deviceName);

};
