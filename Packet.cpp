#include "Packet.h"
#include <iomanip>

std::ostream& operator<<(std::ostream& os, const Packet& packet)
{
    os << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < packet.size(); ++i) 
    {
        os << std::setw(2) << static_cast<int>(packet.buffer()[i]) << " ";
        if ((i + 1) % 8 == 0)
            os << " ";
        if ((i + 1) % 16 == 0)
            os << "\n";
    }
    os << std::nouppercase << std::dec; // Reset to decimal
    return os;
}
