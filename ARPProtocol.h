#include "Protocol.h"
#include "EthernetProtocol.h" // can use it because it's a lower layer protocol
#include "Address.h"
#include "ARPHeader.h"

class ARP : public Protocol
{
public:
	enum class OperationCode
	{
		Reserved = 0,
		REQUEST = 1,
		REPLY = 2,
		REQUEST_RESERVE = 3,
		REPLY_REVERSE = 4,
		DRARP_REQUEST = 5,
		DRARP_REPLY = 6,
		DRARP_ERROR = 7,
		InARP_REQUEST = 8,
		InARP_REPLY = 9,
		ARP_NAK = 10,
		MARS_REQUEST = 11,
		MARS_MULTI = 12,
		MARS_MServ = 13,
		MARS_Join = 14,
		MARS_Leave = 15,
		MARS_NAK = 16,
		MARS_Unserv = 17,
		MARS_SJoin = 18,
		MARS_SLeave = 19,
		MARS_Grouplist_Request = 20,
		MARS_Grouplist_Reply = 21,
		MARS_Redierct_Map = 22,
		MAPOS_UNARP = 23,
		OP_EXP1 = 24,
		OP_EXP2 = 25
	};

	// Full list: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
	enum class HardwareType
	{
		Ether = 1,
		ExperEther = 2,
		Chaos = 5,
		IEEE802 = 6,
		ARPSEC = 30,
	};

	ARP(byte* data);
	ARP(byte* data, HardwareType hardwareType, Ethernet::Protocols protocolType);

	ARP& opcode(const byte2 value);
	ARP& opcode(const OperationCode value);
	byte2 opcode() const;
	
	ARP& hardwareType(const byte2 value);
	ARP& hardwareType(const HardwareType value);
	byte2 hardwareType() const;

	ARP& protocol(const byte2 value);
	ARP& protocol(const Ethernet::Protocols value);
	byte2 protocol() const;

	ARP& hardwareLength(const byte value);
	byte hardwareLength() const;
	ARP& protocolLength(const byte value);
	byte protocolLength() const;

	ARP& senderHardwareAddr(const address::AddrMac mac);
	ARP& senderHardwareAddr(const byte* addr);

	ARP& senderProtocolAddr(const address::AddrIPv4 ipv4);
	ARP& senderProtocolAddr(const byte* addr);

	ARP& targetHardwareAddr(const address::AddrMac mac);
	ARP& targetHardwareAddr(const byte* addr);

	ARP& targetProtocolAddr(const address::AddrIPv4 ipv4);
	ARP& targetProtocolAddr(const byte* addr);

	virtual size_t getSize() const override;

	// Size is the size without any length dependent attributes
	static constexpr int BASE_SIZE = 8;

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

protected:
	size_t m_size;

	void writeToBuffer(byte* buffer) const override;
	void readFromBuffer(const byte* buffer, const size_t size) override;

	byte* targetProtocolAddr() const;
	byte* senderProtocolAddr() const;
	byte* targetHardwareAddr() const;
	byte* senderHardwareAddr() const;

protected:
	ARPHeader* m_data;
};