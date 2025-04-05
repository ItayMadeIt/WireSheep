#include "Classifier.h"
#include "ClassifiedPacket.h"
#include "EthernetProtocol.h"
#include "ARPProtocol.h"
#include "IPv4Protocol.h"
#include "TCPProtocol.h"
#include "UDPProtocol.h"
#include "DNSProtocol.h"
#include "ICMPProtocol.h"

Classifier Classifier::m_singleton;

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


bool Classifier::applyEther(ClassifiedPacket& packet)
{
	packet.add<Ethernet>();

	return true;
}

bool Classifier::applyARP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	Ethernet& ether = packet.get<Ethernet>(protocolIndex);

	if (ether.type() != (byte2)Ethernet::Protocols::ARP)
	{
		return false;
	}

	packet.add<ARP>();
	return true;
}

bool Classifier::applyIPv4(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	Ethernet& ether = packet.get<Ethernet>(protocolIndex);

	if (ether.type() != (byte2)Ethernet::Protocols::IPv4)
	{
		return false;
	}

	IPv4& ipv4 = packet.add<IPv4>();

	// valid ipv4 data
	if (ipv4.version() != 4 && ipv4.ihl() >= 5)
	{
		packet.pop();
		return false;
	}

	return true;
}

bool Classifier::applyUDP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	IPv4& ipv4 = packet.get<IPv4>(protocolIndex);
	if (ipv4.protocol() != (byte)IPv4::Protocols::UDP)
	{
		return false;
	}

	packet.add<UDP>();

	return true;
}

bool Classifier::applyICMP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;
	IPv4& ipv4 = packet.get<IPv4>(protocolIndex);
	if (ipv4.protocol() != (byte)IPv4::Protocols::ICMP)
	{
		return false;
	}

	packet.add<ICMP>();

	return true;
}

bool Classifier::applyTCP(ClassifiedPacket& packet)
{
	byte4 protocolIndex = packet.protocolsCount() - 1;

	IPv4& ipv4 = packet.get<IPv4>(protocolIndex);
	if (ipv4.protocol() != (byte)IPv4::Protocols::TCP)
	{
		return false;
	}

	packet.add<TCP>();

	return true;
}

bool Classifier::applyDNS(ClassifiedPacket& packet)
{
	DNS& dns = packet.add<DNS>();
	if (!dns.syncFields(packet.unidentifiedPacketSize() + DNS::BASE_SIZE))
	{
		packet.pop();
		return false; 
	}

	// We made DNS bigger (probably, because of queries and things)
	// so to make sure the packet knows the size of this protocol got
	// bigger we use update last size. (getSize function should return the new size)
	packet.updateLastSize();

	return true;
}

void Classifier::init()
{
	m_singleton.addRule(ProvidedProtocols::None, applyEther);
	m_singleton.addRule(ProvidedProtocols::Ethernet, applyIPv4);
	m_singleton.addRule(ProvidedProtocols::Ethernet, applyARP);
	m_singleton.addRule(ProvidedProtocols::IPv4, applyUDP);
	m_singleton.addRule(ProvidedProtocols::IPv4, applyTCP);
	m_singleton.addRule(ProvidedProtocols::IPv4, applyICMP);
	m_singleton.addRule(ProvidedProtocols::UDP, applyDNS);
}

Classifier& Classifier::basicClassifier()
{
	return m_singleton;
}
