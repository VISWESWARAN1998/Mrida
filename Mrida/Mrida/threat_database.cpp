// SWAMI KARUPPASWAMI THUNNAI

#include <vector>
#include <map>
#include "threat_database.h"
#include "display.h"
#include "trendcpp.h"



threat_database::threat_database()
{
}


threat_database::~threat_database()
{
}

void threat_database::refactor()
{
	clear_screen();
	set_terminal_color(YELLOW);
	std::vector<std::string> hashes;
	std::map<std::string, std::vector<std::string>> matched_hashes;
	std::cout << "\t\tMRIDA - REFACTORING THREAT DATABASE\n";
	sqlite::database threat_db("threat_db.db");
	try {
		threat_db << "select threat_hash from threat"
			>> [&](std::string threat_hash)
		{
			set_terminal_color(GREEN);
			std::cout << "CHECKING: ";
			set_terminal_color(CYAN);
			std::cout << threat_hash << ": ";
			bool matched = false;
			for (std::string hash : hashes)
			{
				trendcpp tlsh;
				if (tlsh.similarity_distance(threat_hash, hash) < 20)
				{
					if (matched_hashes.find(hash) == matched_hashes.end())
					{
						std::vector<std::string> matches;
						matches.push_back(threat_hash);
						matched_hashes[hash] = matches;
					}
					else
					{
						matched_hashes[hash].push_back(threat_hash);
					}
					matched = true;
					break;
				}
			}
			if (matched)
			{
				set_terminal_color(GREEN);
				std::cout << "[MATCHED]\n";
			}
			else
			{
				set_terminal_color(LIGHTRED);
				std::cout << "[UNMATCHED]\n";
				hashes.push_back(threat_hash);
			}
		};
		clear_screen();
		set_terminal_color(YELLOW);
		std::cout << "\t\tMRIDA - REFACTORING THREAT DATABASE\n";
		for (auto i : matched_hashes)
		{
			set_terminal_color(CYAN);
			std::cout << "REMOVING ASSOCIATED HASH FOR: ";
			set_terminal_color(YELLOW);
			std::cout << i.first << "\n";
			std::vector<std::string> associated_hashes = i.second;
			for (std::string hash : associated_hashes)
			{
				set_terminal_color(LIGHTRED);
				std::cout << "[REMOVED]: ";
				set_terminal_color();
				threat_db << "delete from threat where threat_hash=?" << hash;
				std::cout << hash << "\n";
			}
		}
	}
	catch (std::exception &e)
	{
		error_print(e.what());
	}
	// Reset the terminal color to original
	set_terminal_color();
}
