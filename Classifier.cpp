#include "Classifier.h"
#include "ClassifiedPacket.h"

Classifier::Classifier()
{

}

void Classifier::parse(ClassifiedPacket& packet)
{
	if (packet.isFull())
	{
		return;
	}

	byte4 protocolsCount = packet.protocolsCount();

	ProvidedProtocols lastProtocol = ProvidedProtocols::None;

	if (protocolsCount)
	{
		lastProtocol = packet.get<Protocol>(protocolsCount - 1).protType();
	}

	ProvidedProtocols newProtocol = ProvidedProtocols::None;

	// Will be modified from o(n) to o(1) :
	for (byte4 i = 0; i < m_rules.count(); i++)
	{
		if (m_rules[i].lastProtocol != lastProtocol)
		{
			continue;
		}
		
		if (m_rules[i].apply(packet))
		{
			// parse another layer
			parse(packet);
			break;
		}
	}
}

void Classifier::addRule(ClassifyRule& rule)
{
	m_rules.push_back(rule);
}

void Classifier::addRule(ProvidedProtocols lastProtocol, bool(*apply)(ClassifiedPacket&))
{
	m_rules.emplace_back(lastProtocol, apply);
}
