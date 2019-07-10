// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <string>
#include <tlsh.h>

class trendcpp
{
public:
	trendcpp();
	~trendcpp();

	// Get the hash of file
	std::string hash_file_to_string(std::string file_location);

	// Get TLSH object
	const Tlsh* hash_file(std::string file_location);
};

