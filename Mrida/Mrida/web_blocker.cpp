// SWAMI KARUPPASWAMI THUNNAI

#include <experimental/filesystem>
#include "web_blocker.h"
#include "display.h"
#include "sqlite3.h"


web_blocker::web_blocker()
{
		
}


web_blocker::~web_blocker()
{
}

void web_blocker::add_domain_to_blocked(std::string domain_name)
{
	if (!is_domain_blocked(domain_name))
	{
		sqlite::database database("web_blocker.db");
		database << "insert into block_list(domain_name) values(?);" << domain_name;
	}
}

bool web_blocker::is_domain_blocked(std::string domain_name)
{
	sqlite::database database("web_blocker.db");
	database << "create table if not exists block_list(domain_name text primary key);";
	int count = 0;
	database << "select count(domain_name) from block_list where domain_name=?" << domain_name >> count;
	if (count > 0)
	{
		error_print(domain_name + " IS IN BLACKLIST\n");
		return true;
	}
	else
	{
		success_print(domain_name + " IS NOT IN BLACKLIST\n");
		return false;
	}
}
