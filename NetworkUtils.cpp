#include "NetworkUtils.h"
#include <string.h>

AddrMac NetworkUtils::getSelfMac(const char* deviceName)
{
    const char* formattedDeviceName = nullptr;

    size_t len = strlen(deviceName);
    size_t from = 0;

    for (from = 0; from < len; ++from)
    {
        if (deviceName[from] == '{')
        {
            break;
        }
    }
    if (from == len)
    {
        from = 0;
    }

    size_t to = len > 0 ? len - 1 : 0; // last char

    // invalid range
    if (from >= to)
    {
        throw std::runtime_error("Invalid device name.");
    }

    // substr values
    formattedDeviceName = deviceName + from;
    size_t formattedLen = to - from;



    PIP_ADAPTER_ADDRESSES pAdapterAddresses = nullptr;
    ULONG outBufLen = 0;

    // First call to get the necessary size
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAdapterAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    }

    if (pAdapterAddresses == nullptr)
    {
        throw std::runtime_error("Failed to allocate memory for adapter addresses.");
    }

    // Retrieve adapter addresses
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, pAdapterAddresses, &outBufLen) != NO_ERROR)
    {
        free(pAdapterAddresses);
        throw std::runtime_error("Failed to get adapter addresses.");
    }

    // Iterate through adapters
    for (PIP_ADAPTER_ADDRESSES pCurrAdapter = pAdapterAddresses; pCurrAdapter != nullptr; pCurrAdapter = pCurrAdapter->Next)
    {
        if (pCurrAdapter->PhysicalAddressLength == ADDR_MAC_BYTES)
        {
            if (std::memcmp(formattedDeviceName, pCurrAdapter->AdapterName, formattedLen) != 0)
            {
                continue;
            }
            AddrMac mac;
            memcpy(mac.m_data, pCurrAdapter->PhysicalAddress, ADDR_MAC_BYTES);
            free(pAdapterAddresses);
            return mac;
        }
    }

    free(pAdapterAddresses);
    throw std::runtime_error("No matching network adapter found.");
}


AddrMac NetworkUtils::getRouterMac(const char* deviceName)
{

    const char* formattedDeviceName = nullptr;

    size_t len = strlen(deviceName);
    size_t from = 0;

    for (from = 0; from < len; ++from)
    {
        if (deviceName[from] == '{')
        {
            break;
        }
    }
    if (from == len)
    {
        throw std::runtime_error("No { found in MAC address");
    }

    size_t to = len > 0 ? len - 1 : 0; // last char

    // invalid range
    if (from >= to)
    {
        throw std::runtime_error("Invalid device name.");
    }

    // substr values
    formattedDeviceName = deviceName + from;
    size_t formattedLen = to - from;


    // Get the default gateway's IP address
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG outBufLen = sizeof(IP_ADAPTER_INFO);

    adapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
    if (adapterInfo == nullptr)
    {
        throw std::runtime_error("Failed to allocate memory for adapter info.");
    }

    if (GetAdaptersInfo(adapterInfo, &outBufLen) == ERROR_BUFFER_OVERFLOW)
    {
        free(adapterInfo);
        adapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
        if (adapterInfo == nullptr)
        {
            throw std::runtime_error("Failed to allocate memory for adapter info.");
        }
    }

    if (GetAdaptersInfo(adapterInfo, &outBufLen) != NO_ERROR)
    {
        free(adapterInfo);
        throw std::runtime_error("Failed to get adapter info.");
    }

    PIP_ADAPTER_INFO pCurrAdapter = adapterInfo;
    while (pCurrAdapter)
    {

        if (std::memcmp(formattedDeviceName, pCurrAdapter->AdapterName, formattedLen) != 0)
        {
            pCurrAdapter = pCurrAdapter->Next;
            continue;
        }
        
        // Default gateway IP
        IP_ADDR_STRING* gateway = &pCurrAdapter->GatewayList;
        if (gateway != nullptr && gateway->IpAddress.String[0] != '\0')
        {
            sockaddr_in destAddr;
            memset(&destAddr, 0, sizeof(destAddr));
            destAddr.sin_family = AF_INET;
            destAddr.sin_addr.s_addr = inet_addr(gateway->IpAddress.String);

            // Use SendARP to get MAC
            ULONG macAddr[2] = { 0 };
            ULONG macAddrLen = 6; // MAC address length
                
            memset(&macAddr, 0xff, sizeof(macAddr));

            unsigned long retVal = SendARP(destAddr.sin_addr.s_addr, 0, &macAddr, &macAddrLen);

            if (retVal == NO_ERROR)
            {
                AddrMac mac;
                memcpy(mac.m_data, macAddr, ADDR_MAC_BYTES);
                free(adapterInfo);
                return mac;
            }
            else {
                printf("Error: SendArp failed with error: %d", retVal);
                switch (retVal)
                {
                    case ERROR_GEN_FAILURE:
                        printf(" (ERROR_GEN_FAILURE)\n");
                        break;
                    case ERROR_INVALID_PARAMETER:
                        printf(" (ERROR_INVALID_PARAMETER)\n");
                        break;
                    case ERROR_INVALID_USER_BUFFER:
                        printf(" (ERROR_INVALID_USER_BUFFER)\n");
                        break;
                    case ERROR_BAD_NET_NAME:
                        printf(" (ERROR_GEN_FAILURE)\n");
                        break;
                    case ERROR_BUFFER_OVERFLOW:
                        printf(" (ERROR_BUFFER_OVERFLOW)\n");
                        break;
                    case ERROR_NOT_FOUND:
                        printf(" (ERROR_NOT_FOUND)\n");
                        break;
                    default:
                        printf("\n");
                        break;
                }
            }
        }
        pCurrAdapter = pCurrAdapter->Next;
    }

    free(adapterInfo);
    throw std::runtime_error("Failed to find router MAC address.");
}


DeviceMacs NetworkUtils::getDeviceMacs(const char* deviceName)
{
    DeviceMacs macs;
    macs.host = getSelfMac(deviceName);
    macs.router = getRouterMac(deviceName);
    return macs;
}
