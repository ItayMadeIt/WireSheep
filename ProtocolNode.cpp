#include "ProtocolNode.h"

ProtocolNode::ProtocolNode(ProtocolNode* prev, Protocol* self, ProtocolNode* next)
	: m_prev(prev), m_self(self), m_next(next)
{
}

ProtocolNode* ProtocolNode::prev()
{
	return m_prev;
}

ProtocolNode* ProtocolNode::next()
{
	return m_next;
}

void ProtocolNode::insert(Protocol* newProtocol)
{
	ProtocolNode* last = this;

	while (last->m_next)
	{
		last = last->m_next;
	}

	ProtocolNode* newNode = new ProtocolNode(last, newProtocol, nullptr);
	last->m_next = newNode;
}

Protocol* ProtocolNode::getSelf() const
{
	return m_self;
}

ProtocolNode::operator Protocol& () const
{
	return *m_self;
}

Protocol* ProtocolNode::operator->()
{
	return m_self;
}