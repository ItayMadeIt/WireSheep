#pragma once

#include "Protocol.h"

class ProtocolNode
{
public:
	ProtocolNode(ProtocolNode* prev, Protocol* self, ProtocolNode* next);


	ProtocolNode* prev();
	ProtocolNode* next();

	void insert(Protocol* newProtocol);

	Protocol* getSelf() const ;
	operator Protocol&() const;

	Protocol* operator->();

private:
	Protocol* m_self;

	ProtocolNode* m_next;
	ProtocolNode* m_prev;
};

