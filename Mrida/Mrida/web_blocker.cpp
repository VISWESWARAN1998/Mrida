// SWAMI KARUPPASWAMI THUNNAI

#include <experimental/filesystem>
#include "web_blocker.h"
#include "display.h"



web_blocker::web_blocker()
{
	if (std::experimental::filesystem::exists("blocked.txt"))
	{
		std::ifstream file;
		file.open("blocked.txt");
		if (file.is_open())
		{
			while (!file.eof())
			{
				std::string domain;
				std::getline(file, domain);
				block_list.insert(domain);
			}
			file.close();
		}
	}
}


web_blocker::~web_blocker()
{
}

void web_blocker::add_domain_to_blocked(std::string domain_name)
{
	//write_mutex.lock();
	std::ofstream file;
	file.open("blocked.txt", std::ios::app);
	if (file.is_open())
	{
		file << domain_name << "\n";
		file.close();
	}
	//write_mutex.unlock();
}

bool web_blocker::is_domain_blocked(std::string domain_name)
{
	if (block_list.find(domain_name) != block_list.end()) 
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
