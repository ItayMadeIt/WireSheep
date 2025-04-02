#pragma once

#include "WireDefs.h"
#include "StaticVector.hpp"

struct ClassifyRule
{
	ProvidedProtocols lastProtocol;
	bool (*apply)(ClassifiedPacket&);
};

class Classifier
{
public:
	Classifier();

	void parse(ClassifiedPacket& packet);

private:
	constexpr static const byte4 MAX_RULES = 0x100;

private:
	StaticVector<ClassifyRule, MAX_RULES * sizeof(ClassifyRule)> m_rules;

};

