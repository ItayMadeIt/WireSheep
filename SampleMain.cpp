#include <pcap.h>
#include <memory>
#include <iostream>
#include <vector>
#include "Ethernet.h"
#include "Helper.h"

int main()
{
	using namespace address;

	addrMac macDst = addrMac::fromString("E8:AD:A6:FB:FC:74");
	addrMac macSrc = addrMac::fromString("74:56:3C:73:67:B0");

	// Create ethernet and array
	Ethernet ether(macSrc, macDst, 0x0800);
	byte arr[14] = { 0 };

	// Print ethernet & empty array
	std::cout << ether << std::endl;
	printByteArr(arr, 14);

	// Serialize ether into the byte array
	ether.serialize(arr);

	// Print the new array after inputting ether var into it
	printByteArr(arr, 14);
	std::cout << std::endl;

	// create ether2
	Ethernet ether2;

	// print empty ether2
	std::cout << ether2 << std::endl;

	// Get the ethernet protocol into ether2
	ether2.deserialize(arr);

	// Print ether2 protocol
	std::cout << ether2 << std::endl;

}