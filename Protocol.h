#pragma once

#include <memory>
#include <vector>
#include "WireDefs.h"

// forward decleration 
class MutablePacket;

class Protocol
{
public:
	Protocol(const AllProtocols protocol);
	Protocol(const Protocol& other);
	virtual ~Protocol() = default;
	Protocol(Protocol&& other);
	
	virtual void calculateChecksum(std::vector<byte>& buffer, const size_t offset, const Protocol* protocol);

	/// <summary>
	/// Encodes a layer, a buffer is given with all data from 
	/// previous layers. From [buffer.data() + offset] this 
	/// layer should be encoded.
	/// </summary>
	/// <param name="buffer">Buffer with all previous layers</param>
	/// <param name="offset">The index in the buffer that the data will be written into</param>
	virtual void encodeLayerPre(std::vector<byte>& buffer, const size_t offset);
	
	/// <summary>
	/// WILL BE REMOVED
	/// Encodes a layer, a buffer is given with all data from 
	/// previous layers. From [buffer.data() + offset] this 
	/// layer should be encoded.
	/// </summary>
	/// <param name="buffer">Buffer with all previous layers</param>
	/// <param name="offset">The index in the buffer that the data will be written into</param>
	virtual void encodeLayerRaw(std::vector<byte>& buffer, const size_t offset) const
	{
		// Empty implenetation
	};

	/// <summary>
	/// Optional function that will handle layer logic after all layers above 
	/// it are encoded.
	/// </summary>
	/// <param name="buffer">The buffer of the data</param>
	/// <param name="offset">Offset from buffer start</param>
	virtual void encodeLayerPost (std::vector<byte>& buffer, const size_t offset);
	
	/// <summary>
	/// Optional function that will handle layer logic after all layers above 
	/// it are encoded. (RAW OPTION)
	/// </summary>
	/// <param name="buffer">The buffer of the data</param>
	/// <param name="offset">Offset from buffer start</param>
	virtual void encodeLayerPostRaw(std::vector<byte>& buffer, const size_t offset) const;

	bool includesChecksum() const;


	virtual void encodePre(MutablePacket& packet, size_t protocolIndex);
	virtual void encodePost(MutablePacket& packet, size_t protocolIndex);


	AllProtocols getProtocol() const;
	virtual size_t getSize() const = 0;
	

protected:
	/// <summary>
	/// Serialize protocol data from the class into the array (ptr)
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void writeToBuffer(byte* buffer) const 
	{
		// Will be removed 
	};

	/// <summary>
	/// Deserialize protocol data from the array (ptr) into the class.
	/// This does not modify the original array.
	/// </summary>
	/// <param name="ptr">data start position</param>
	virtual void readFromBuffer(const byte* buffer, const size_t size) 
	{
		// Will be removed 
	};


	// Will be removed
	bool m_includesChecksum;

private:
	AllProtocols m_protocolType;
};
