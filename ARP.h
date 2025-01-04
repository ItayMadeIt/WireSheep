#include "Protocol.h"
#include "Ethernet.h" // can use it because it's a lower layer protocol
#include "Address.h"

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

	ARP();

	ARP& opcode(const byte2 value);
	ARP& opcode(const OperationCode value);
	byte2 opcode();
	
	ARP& hardwareType(const byte2 value);
	ARP& hardwareType(const HardwareType value);
	byte2 hardwareType();

	ARP& protocolType(const byte2 value);
	ARP& protocolType(const Ethernet::ProtocolTypes value);
	byte2 protocolType();

	ARP& hardwareLength(const byte value);
	byte hardwareLength();
	ARP& protocolLength(const byte value);
	byte protocolLength();

	ARP& senderHardwareAddr(const address::addrMac mac);
	ARP& senderHardwareAddr(const std::vector<byte> addr);
	std::vector<byte> senderHardwareAddr();

	ARP& senderProtocolAddr(const address::addrIPv4 ipv4);
	ARP& senderProtocolAddr(const std::vector<byte> addr);
	std::vector<byte> senderProtocolAddr();

	ARP& targetHardwareAddr(const address::addrMac mac);
	ARP& targetHardwareAddr(const std::vector<byte> addr);
	std::vector<byte> targetHardwareAddr();

	ARP& targetProtocolAddr(const address::addrIPv4 ipv4);
	ARP& targetProtocolAddr(const std::vector<byte> addr);
	std::vector<byte> targetProtocolAddr();

protected:
	void serializeArr(byte* ptr) const override;
	void deserializeArr(const byte* ptr) override;
	void serialize(std::vector<byte>& buffer) override;
	void serializeRaw(std::vector<byte>& buffer) const override;
	size_t getSize() const override;
	void serialize(std::vector<byte>& buffer, const size_t offset) override;
	void serializeRaw(std::vector<byte>& buffer, const size_t offset) const override;
	
protected:
	byte2 m_hardwareType;
	byte2 m_protocolType;

	byte m_hardwareLength;
	byte m_protocolLength;

	byte2 m_operation;

	std::vector<byte> m_senderHardwareAddr;
	std::vector<byte> m_senderProtocolAddr;

	std::vector<byte> m_targetHardwareAddr;
	std::vector<byte> m_targetProtocolAddr;
};