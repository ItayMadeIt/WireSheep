#include "NetworkUtils.h"

addrMac NetworkUtils::getSelfMac(const std::string& deviceName)
{
    std::string formattedDeviceName = deviceName.substr(deviceName.find('{'), deviceName.size() - 1);

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
        if (pCurrAdapter->PhysicalAddressLength == ADDR_MAC_BYTES &&
            (formattedDeviceName.empty() || formattedDeviceName == pCurrAdapter->AdapterName))
        {
            addrMac mac;
            memcpy(mac.m_data, pCurrAdapter->PhysicalAddress, ADDR_MAC_BYTES);
            free(pAdapterAddresses);
            return mac;
        }
    }

    free(pAdapterAddresses);
    throw std::runtime_error("No matching network adapter found.");
}
addrMac NetworkUtils::getRouterMac(const std::string& deviceName)
{
    std::string formattedDeviceName = deviceName.substr(deviceName.find('{'), deviceName.size() - 1);

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

        if (formattedDeviceName.empty() || formattedDeviceName == pCurrAdapter->AdapterName)
        {
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
                    addrMac mac;
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
        }
        pCurrAdapter = pCurrAdapter->Next;
    }

    free(adapterInfo);
    throw std::runtime_error("Failed to find router MAC address.");
}


DeviceMacs NetworkUtils::getDeviceMacs(const std::string& deviceName)
{
    DeviceMacs macs;
    macs.self = getSelfMac(deviceName);
    macs.router = getRouterMac(deviceName);
    return macs;
}
