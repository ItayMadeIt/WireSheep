#pragma once

#include "Protocol.h"
#include "TCPHeader.h"

class TCP : public Protocol
{
public:
	
	enum class Flags : byte
	{
		FIN = 1 << 0,
		SYN = 1 << 1,
		RST = 1 << 2,
		PSH = 1 << 3,
		ACK = 1 << 4,
		URG = 1 << 5,
		ECE = 1 << 6,
		CWR = 1 << 7,
	};

	friend constexpr Flags operator|(Flags a, Flags b);
	friend constexpr Flags operator&(Flags a, Flags b);

	enum class OptionTypeValues : byte
	{
		EndOfOptionList = 0,
		NoOperation = 1,
		MaximumSegmentSize = 2,
		WindowScale = 3,
		SelectiveAckPermitted = 4,
		SelectiveAck = 5,
		TimeoutAndEcho = 8,
		UserTimeoutOption = 28,
		TCPAuthOption = 29,
		MultipathTCP = 30,
	};

	class OptionBase
	{
	public:
		// read+write optionbase
		OptionBase(byte* addr, MutablePacket* packet=nullptr);
		virtual ~OptionBase() = default;

		bool isReadOnly();

	private:
		byte* m_data;
		MutablePacket* m_packet;
	};

	// no implementation 
	class OptionEndList : OptionBase
	{
	};
	// no implementation 
	class OptionNOP : OptionBase
	{
	};
	// no implementation 
	class OptionMSS : OptionBase
	{
	};
	// no implementation 
	class OptionWindowScale : OptionBase
	{
	};
	// no implementation 
	class OptionSACK : OptionBase
	{
	};
	// CAN ADD MORE OPTIONS LATER

public:
	TCP(byte* data);

public:
	TCP& src(const byte2 value);
	byte2 src() const;

	TCP& dst(const byte2 value);
	byte2 dst() const;

	TCP& seq(const byte4 value);
	byte4 seq() const;

	TCP& ack(const byte4 value);
	byte4 ack() const;

	TCP& dataOffset(const byte value);
	byte dataOffset() const;

	TCP& reserved(const byte value);
	byte reserved() const;

	TCP& window(const byte2 value);
	byte2 window() const;

	TCP& checksum(const byte2 value);
	byte2 checksum() const;

	TCP& urgentPtr(const byte2 value);
	byte2 urgentPtr() const;

	TCP& flags(const byte value);
	byte flags();


	template<typename OptionType>
	TCP& addOption(const OptionType& option);

	template<typename OptionType, typename... Args>
	TCP& addOption(Args&&... args);

	size_t getSize() const override;

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

	virtual ProvidedProtocols protType() const;

	virtual void encodePre(MutablePacket& packet, const size_t index) override;
	virtual void encodePost(MutablePacket& packet, const size_t index)override;

public:
	const static size_t BASE_SIZE = 20; // header size: 20 bytes
protected:

	/// <summary>
	/// Adds (optionLength % rowSize) 0 bytes
	/// </summary>
	void addOptionsPadding(byte* ptr) const;

	size_t getOptionsSize() const;
	
	virtual void calculateChecksum(MutablePacket& packet, const size_t index);

protected:

	TCPHeader* m_data;

	byte2 m_optionsEndLoc;

};
