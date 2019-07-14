// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <iostream>
#include <sqlite_modern_cpp.h>

class threat_database
{
public:
	threat_database();
	~threat_database();

	// Refactor the threat database -- will remove duplicates in the threat database
	void refactor();
};

