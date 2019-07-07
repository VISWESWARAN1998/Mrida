// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <set>
#include "sqlite_modern_cpp.h"


class web_blocker
{
private:
	std::mutex write_mutex;
	std::set<std::string> block_list;
public:
	web_blocker();
	~web_blocker();

	// This will add a domain to blocked list
	void add_domain_to_blocked(std::string domain_name);

	// Will return true if the domain is blocked
	bool is_domain_blocked(std::string domain_name);
};

