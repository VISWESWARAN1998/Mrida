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
	void add_threat_to_database(unsigned long int id, std::string tlsh_hash, std::string threat_name, unsigned long file_size, unsigned int file_type);

	// Getting the similarity distance
	int similarity_distance(std::string hash_one, std::string hash_two);

	// Mime Type to Id
	unsigned int mime_to_id(std::string mime_type);

	// Will get the similar hash matching id from threat db [returns -1 if nothing is matching]
	long matching_hash_from_threat_db(std::string tlsh_hash, std::string file_type, long file_size_minimum, unsigned long file_size_maximum);
};

