#pragma once

#include "WireDefs.h"

#pragma pack(push)

struct TCPData
{
	byte2 m_src;
	byte2 m_dst;
	byte4 m_seq;
	byte4 m_ack;
	byte  m_dataOffset;
	byte  m_flags;
	byte2 m_window;
	byte2 m_checksum;
	byte2 m_urgPtr;
};

#pragma pack(pop)