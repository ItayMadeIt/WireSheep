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

private:
	constexpr static const byte4 MAX_RULES = 0x100;

private:
	StaticVector<ClassifyRule, MAX_RULES * sizeof(ClassifyRule)> m_rules;

};

