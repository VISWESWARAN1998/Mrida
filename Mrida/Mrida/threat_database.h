// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include "httplib.h"
#include <iostream>
#include <sqlite_modern_cpp.h>

class threat_database
{
public:
	threat_database();
	~threat_database();

	// Refactor the threat database -- will remove duplicates in the threat database
	void refactor();

	// Bool add threat to database
	void add_threat_to_database(std::string tlsh_hash, std::string threat_name, unsigned long file_size, std::string file_type);
	
	// Mime Type to Id
	unsigned int mime_to_id(std::string mime_type);

	// Will get the similar hash matching id from threat db [returns -1 if nothing is matching]
	long matching_hash_from_threat_db(std::string tlsh_hash, std::string file_type, long file_size_minimum, unsigned long file_size_maximum);
};

