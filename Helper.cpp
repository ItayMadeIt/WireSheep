#include "Helper.h"

std::ostream& operator<<(std::ostream& os, const std::vector<byte>& vector)
{
	constexpr size_t HEX_LEN = 2;

	os << std::hex << std::uppercase << std::setfill('0');

	for (size_t i = 0; i < vector.size(); i++)
	{
		os << std::setw(HEX_LEN) << (int)vector[i] << ' ';
	}

	std::cout << std::endl << std::setfill(' ') << std::dec;

	return os;
}

void printByteArr(byte* arr, size_t len)
{
	constexpr size_t HEX_LEN = 2;

	std::cout << std::hex << std::uppercase << std::setfill('0');

	for (size_t i = 0; i < len; i++)
	{
		std::cout << std::setw(HEX_LEN) << (int)arr[i] << ' ';
	}

	std::cout << std::endl << std::setfill(' ') << std::dec;
}
