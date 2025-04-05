#pragma once

#include "WireDefs.h"
#include "StaticVector.hpp"
#include "ClassifiedPacket.h"

struct ClassifyRule
{
	ClassifyRule(ProvidedProtocols lastProtocolParam, bool (*applyParam)(ClassifiedPacket&))
		: lastProtocol(lastProtocolParam), apply(applyParam)
	{}

	ProvidedProtocols lastProtocol;
	bool (*apply)(ClassifiedPacket&);
};

class Classifier
{
public:
	Classifier();

	void parse(ClassifiedPacket& packet);
	void addRule(ClassifyRule& rule);
	void addRule(ProvidedProtocols lastProtocol, bool (*apply)(ClassifiedPacket&));

	static void init();

	static Classifier& basicClassifier();

private:
	constexpr static const byte4 MAX_RULES = 0x100;
	
	/*Basic apply*/
	static bool applyEther(ClassifiedPacket& packet);
	static bool applyARP(ClassifiedPacket& packet);
	static bool applyIPv4(ClassifiedPacket& packet);
	static bool applyTCP(ClassifiedPacket& packet);
	static bool applyUDP(ClassifiedPacket& packet);
	static bool applyICMP(ClassifiedPacket& packet);
	static bool applyDNS(ClassifiedPacket& packet);

private:
	static Classifier m_singleton;

	StaticVector<ClassifyRule, MAX_RULES * sizeof(ClassifyRule)> m_rules;

};

