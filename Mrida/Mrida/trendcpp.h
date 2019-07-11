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

	// Bool add threat to database
	void add_threat_to_database(unsigned long int id, std::string tlsh_hash, std::string threat_name, unsigned long file_size, unsigned int file_type, unsigned int target_os);
};

