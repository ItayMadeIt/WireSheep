#include "MutablePacket.h"

MutablePacket::MutablePacket() :
    Packet(), m_protocolCount(0), m_protocolEndOffset(0)
{}

void MutablePacket::compile()
{
	prePass();

	postPass();
}

byte* MutablePacket::getPtrAtProtocol(size_t index)
{
	return m_buffer + m_protocolEntries[index].m_dataOffset;
}

void MutablePacket::shiftFromOffset(size_t index, size_t amount)
{
	if (index > m_curSize)
	{
		// Act as though it has already shifted
		m_curSize += amount;
		return;
	}
	
	if (amount + m_curSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Couldn't shift, shifting would cause an overflow");
	}

	size_t shiftSize = m_curSize - index;

	// Will copy all bytes to the next `amount` bytes. (using memmove will do it backwards)
	std::memmove(&m_buffer[index + amount], &m_buffer[index], shiftSize);

	m_curSize += amount;

	for (size_t i = 0; i < m_protocolCount; ++i) 
	{
		auto& entry = m_protocolEntries[i];
		if (entry.m_dataOffset >= index) 
		{
			entry.m_dataOffset -= amount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.m_objectOffset])
			);
			basePtr->addr(m_buffer + entry.m_dataOffset);
		}
	}
}

void MutablePacket::shiftFromAddr(byte* addr, size_t amount)
{
	shiftFromOffset(static_cast<size_t>(addr - m_buffer), amount);
}

void MutablePacket::shrinkFromOffset(size_t index, size_t amount)
{
	if (index > m_curSize)
	{
		throw std::exception("Couldn't shift, index >= curSize");
	}

	if (amount + m_curSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Couldn't shift, shifting would cause an overflow");
	}

	size_t shiftSize = m_curSize - index;

	// Will copy all bytes to `index`, `amount` of bytes. (using memmove will do it backwards, memcpy will do it forwards)
	std::memcpy(&m_buffer[index], &m_buffer[index + amount], shiftSize);

	m_curSize -= amount;
	for (size_t i = 0; i < m_protocolCount; ++i)
	{
		auto& entry = m_protocolEntries[i];
		if (entry.m_dataOffset >= index)
		{
			entry.m_dataOffset -= amount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.m_objectOffset])
			);
			
			basePtr->addr(m_buffer + entry.m_dataOffset);
		}
	}
}

void MutablePacket::shrinkFromAddr(byte* addr, size_t amount)
{
	shrinkFromOffset(static_cast<size_t>(addr - m_buffer), amount);
}

void MutablePacket::replaceFromOffset(size_t index, size_t deleteAmount, const byte* dataPtr, size_t dataAmount)
{
	if (deleteAmount == 0)
	{
		shiftFromOffset(index, dataAmount);
		std::memcpy(m_buffer + index, dataPtr, dataAmount);
		return;
	}

	if (index > m_curSize)
	{
		throw std::exception("Index out of bounds");
	}
	if (deleteAmount > m_curSize - index)
	{
		throw std::exception("Delete amount too large");
	}

	size_t newSize = m_curSize - deleteAmount + dataAmount;
	if (newSize > MAX_PACKET_SIZE)
	{
		throw std::exception("Replace would overflow packet");
	}

	size_t tailSize = m_curSize - index - deleteAmount;

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

	m_curSize = newSize;

	// Update protocol offsets
	for (size_t i = 0; i < m_protocolCount; ++i)
	{
		auto& entry = m_protocolEntries[i];
		if (entry.m_dataOffset >= index)
		{
			entry.m_dataOffset += dataAmount - deleteAmount;

			Protocol* basePtr = reinterpret_cast<Protocol*>(
				static_cast<void*>(&m_protocolObjects[entry.m_objectOffset])
				);
			basePtr->addr(m_buffer + entry.m_dataOffset);
		}
	}
}

void MutablePacket::replaceFromAddr(byte* addr, size_t deleteAmount, const byte* dataPtr, size_t dataAmount)
{
	replaceFromOffset(addr - reinterpret_cast<byte*>(m_buffer), deleteAmount, dataPtr, dataAmount);
}

void MutablePacket::insertBytes(const byte value, size_t amount)
{
	if (amount == 0)
	{
		return;
	}

	std::size_t offset = m_curSize;
	
	std::memset(m_buffer + offset, value, amount);

	m_curSize += amount;
}

void MutablePacket::insertByteArr(const byte* byteArr, size_t amount)
{
	if (amount == 0)
	{
		return;
	}

	std::size_t offset = m_curSize;

	std::memcpy(m_buffer + offset, byteArr, amount);

	m_curSize += amount;
}

size_t MutablePacket::protocolCount() const
{
	return m_protocolCount;
}

void MutablePacket::prePass()
{
	for (size_t i = 0; i < m_protocolCount; i++)
	{
		size_t offset = m_protocolEntries[i].m_objectOffset;

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
		size_t offset = m_protocolEntries[i].m_objectOffset;

		Protocol& proto = *reinterpret_cast<Protocol*>(
			static_cast<void*>(&m_protocolObjects[offset])
		);

		proto.encodePost(*this, i);
	}
}

