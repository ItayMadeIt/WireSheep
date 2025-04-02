#include "MutablePacket.h"

MutablePacket::MutablePacket() :
    Packet(), m_protocolCount(0), m_protocolEndOffset(0), m_size(0), m_buffer{}
{}

byte* MutablePacket::getBuffer()
{
	return m_buffer;
}

byte4 MutablePacket::getSize()
{
	return m_size;
}

void MutablePacket::compile()
{
	prePass();

	postPass();
}

byte* MutablePacket::getPtrAtProtocol(byte4 index)
{
	return m_buffer + m_protocolEntries[index].dataOffset;
}

void MutablePacket::shiftFromOffset(byte4 index, byte4 amount)
{
	if (index > m_size)
	{
		// Act as though it has already shifted
		m_size += amount;
		return;
	}
	
	if (amount + m_size > MAX_PACKET_SIZE)
	{
		throw std::exception("Couldn't shift, shifting would cause an overflow");
	}

	byte4 shiftSize = m_size - index;

	// Will copy all bytes to the next `amount` bytes. (using memmove will do it backwards)
	std::memmove(&m_buffer[index + amount], &m_buffer[index], shiftSize);

	m_size += amount;

	for (byte4 i = 0; i < m_protocolCount; ++i) 
	{
		auto& entry = m_protocolEntries[i];
		if (entry.dataOffset >= index) 
		{
			entry.dataOffset -= amount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.objectOffset])
			);
			basePtr->addr(m_buffer + entry.dataOffset);
		}
	}
}

void MutablePacket::shiftFromAddr(byte* addr, byte4 amount)
{
	shiftFromOffset(static_cast<byte4>(addr - m_buffer), amount);
}

void MutablePacket::shrinkFromOffset(byte4 index, byte4 amount)
{
	if (index > m_size)
	{
		throw std::exception("Couldn't shift, index >= curSize");
	}

	if (amount + m_size > MAX_PACKET_SIZE)
	{
		throw std::exception("Couldn't shift, shifting would cause an overflow");
	}

	byte4 shiftSize = m_size - index;

	// Will copy all bytes to `index`, `amount` of bytes. (using memmove will do it backwards, memcpy will do it forwards)
	std::memcpy(&m_buffer[index], &m_buffer[index + amount], shiftSize);

	m_size -= amount;
	for (byte4 i = 0; i < m_protocolCount; ++i)
	{
		auto& entry = m_protocolEntries[i];
		if (entry.dataOffset >= index)
		{
			entry.dataOffset -= amount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.objectOffset])
			);
			
			basePtr->addr(m_buffer + entry.dataOffset);
		}
	}
}

void MutablePacket::shrinkFromAddr(byte* addr, byte4 amount)
{
	shrinkFromOffset(static_cast<byte4>(addr - m_buffer), amount);
}

void MutablePacket::replaceFromOffset(byte4 index, byte4 deleteAmount, const byte* dataPtr, byte4 dataAmount)
{
	if (deleteAmount == 0)
	{
		shiftFromOffset(index, dataAmount);
		std::memcpy(m_buffer + index, dataPtr, dataAmount);
		return;
	}

	if (index > m_size)
	{
		throw std::exception("Index out of bounds");
	}
	if (deleteAmount > m_size - index)
	{
		throw std::exception("Delete amount too large");
	}

	byte4 newSize = m_size - deleteAmount + dataAmount;
	if (newSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Replace would overflow packet");
	}

	byte4 tailSize = m_size - index - deleteAmount;

	// Expand or shrink the buffer in-place
	if (dataAmount != deleteAmount)
	{
		std::memmove(
			m_buffer + index + dataAmount,
			m_buffer + index + deleteAmount,
			tailSize
		);
	}

	// Copy new data into position
	if (dataAmount > 0 && dataPtr)
	{
		std::memcpy(m_buffer + index, dataPtr, dataAmount);
	}

	m_size = newSize;

	// Update protocol offsets
	for (byte4 i = 0; i < m_protocolCount; ++i)
	{
		auto& entry = m_protocolEntries[i];
		if (entry.dataOffset >= index)
		{
			entry.dataOffset += dataAmount - deleteAmount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.objectOffset])
				);
			basePtr->addr(m_buffer + entry.dataOffset);
		}
	}
}

void MutablePacket::replaceFromAddr(byte* addr, byte4 deleteAmount, const byte* dataPtr, byte4 dataAmount)
{
	replaceFromOffset(addr - reinterpret_cast<byte*>(m_buffer), deleteAmount, dataPtr, dataAmount);
}

void MutablePacket::insertBytes(const byte value, byte4 amount)
{
	if (amount == 0)
	{
		return;
	}

	byte4 offset = m_size;
	
	std::memset(m_buffer + offset, value, amount);

	m_size += amount;
}

void MutablePacket::insertByteArr(const byte* byteArr, byte4 amount)
{
	if (amount == 0)
	{
		return;
	}

	byte4 offset = m_size;

	std::memcpy(m_buffer + offset, byteArr, amount);

	m_size += amount;
}

byte4 MutablePacket::protocolCount() const
{
	return m_protocolCount;
}

void MutablePacket::prePass()
{
	for (byte4 i = 0; i < m_protocolCount; i++)
	{
		byte4 offset = m_protocolEntries[i].objectOffset;

		Protocol& proto = *reinterpret_cast<Protocol*>(
			static_cast<void*>(&m_protocolObjects[offset])
		);

		proto.encodePre(*this, i);
	}
}

void MutablePacket::postPass()
{
	for (signed long i = m_protocolCount - 1; i >= 0; i--)
	{
		byte4 offset = m_protocolEntries[i].objectOffset;

		Protocol& proto = *reinterpret_cast<Protocol*>(
			static_cast<void*>(&m_protocolObjects[offset])
		);

		proto.encodePost(*this, i);
	}
}

const byte* MutablePacket::buffer() const
{
	return m_buffer;
}

const byte4 MutablePacket::size() const
{
	return m_size ;
}

