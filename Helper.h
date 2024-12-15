#pragma once

#include "WireDefs.h"
#include <iostream>
#include <vector>
#include <iomanip>

void printByteArr(const byte* arr, size_t len);
std::ostream& operator<<(std::ostream& os, const std::vector<byte>& vector);

