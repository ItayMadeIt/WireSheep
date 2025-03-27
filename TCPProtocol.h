#pragma once

#include "Protocol.h"
#include <type_traits> 
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

	struct OptionBase
	{
		static const byte BASE_LENGTH = 2;

		OptionBase(const byte optionType, const byte length = 0);
		virtual ~OptionBase() = default;

		virtual void encode(byte* ptr) const;
		virtual std::unique_ptr<OptionBase> clone() const = 0;

		byte m_optionType;
		byte m_length;
	};

	template <typename OptionType>
	struct Option : public OptionBase
	{
		Option(const byte optionType, const byte length = 0);

		Option(const OptionTypeValues optionType, const byte length = 0);

		virtual std::unique_ptr<TCP::OptionBase> clone() const override;
	};
	
	struct OptionEndList : public Option<OptionEndList>
	{
		static const byte BASE_LENGTH = 1;

		OptionEndList();

		virtual void encode(byte* ptr) const override;
	};

	struct OptionNoOperation : public Option<OptionNoOperation>
	{
		static const byte BASE_LENGTH = 1;

		OptionNoOperation();

		virtual void encode(byte* ptr) const override;
	};

	struct OptionMaxSegmentSize : public Option<OptionMaxSegmentSize>
	{
		static const byte BASE_LENGTH = 4; // 1 for type, 1 for length, 2 for maxSegmentSize

		OptionMaxSegmentSize(const byte2 maxSegmentSize);

		virtual void encode(byte* ptr) const override;

		byte2 m_maxSegmentSize;
	};

	struct OptionWindowScale : public Option<OptionWindowScale>
	{
		static const byte BASE_LENGTH = 3; // 1 for type, 1 for length, 1 for windowScale

		OptionWindowScale(const byte windowScale);

		virtual void encode(byte* ptr) const override;

		byte m_windowScale;
	};

	struct OptionSelectiveAckPermitted: public Option<OptionSelectiveAckPermitted>
	{
		OptionSelectiveAckPermitted();
	};

	// CAN ADD MORE OPTIONS LATER

public:
	TCP();
	TCP(const TCP& other);

public:
	virtual void calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol) override;

	TCP& srcPort(const byte2 value);
	byte2 srcPort() const;

	TCP& dstPort(const byte2 value);
	byte2 dstPort() const;

	TCP& seqNum(const byte4 value);
	byte4 seqNum() const;

	TCP& ackNum(const byte4 value);
	byte4 ackNum() const;

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

	template<typename OptionType>
	TCP& addOption(OptionType&& option);

	template<typename OptionType, typename... Args>
	TCP& addOption(Args&&... args);

	void encodeLayerPre(std::vector<byte>& buffer, const size_t offset) override;
	void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const override;

	size_t getSize() const override;

	void calculateOptionsSize();

	virtual void addr(byte* address) override;
	virtual byte* addr() const override;

protected:

	void writeToBuffer(byte* buffer) const override;
	void readFromBuffer(const byte* buffer, const size_t size) override;

	/// <summary>
	/// Adds (optionLength % rowSize) 0 bytes
	/// </summary>
	void addOptionsPadding(byte* ptr) const;

protected:
	const static size_t SIZE = 20; // header size: 20 bytes

	TCPHeader* m_data;

	byte2 m_srcPort;           // 16 bits
	byte2 m_dstPort;           // 16 bits
	
	byte4 m_seqNum;            // 32 bits
	byte4 m_ackNum;            // 32 bits

	byte m_dataOffset;         // 4 bits
	byte m_reserved;           // 4 bits
	
	byte m_flags;              // 8 bits
	
	byte2 m_window;            // 16 bits

	byte2 m_checksum;          // 16 bits
	byte2 m_urgentPtr;         // 16 bits

	byte2 m_optionsSize;

	std::vector< std::unique_ptr<TCP::OptionBase>> m_options; // all options

};

template<typename OptionType>
TCP::Option<OptionType>::Option(const byte optionType, const byte length)
	: OptionBase(optionType, length) 
{}

template<typename OptionType>
TCP::Option<OptionType>::Option(const OptionTypeValues optionType, const byte length)
	: OptionBase((byte)optionType, length) 
{}


template<typename OptionType>
std::unique_ptr<TCP::OptionBase> TCP::Option<OptionType>::clone() const
{
	return std::make_unique<OptionType>(static_cast<const OptionType&>(*this));
}

template<typename OptionType>
TCP& TCP::addOption(const OptionType& option)
{
	m_options.emplace_back(std::make_unique<OptionType>(option));

	calculateOptionsSize();

	return *this;
}

template<typename OptionType>
TCP& TCP::addOption(OptionType&& option)
{
	m_options.emplace_back(std::make_unique<OptionType>(std::move(option)));

	calculateOptionsSize();

	return *this;
}

template<typename OptionType, typename ...Args>
TCP& TCP::addOption(Args&&... args)
{

	m_options.emplace_back(
		std::make_unique<OptionType>(std::forward<Args>(args)...)
	);

	calculateOptionsSize();

	return *this;
}
