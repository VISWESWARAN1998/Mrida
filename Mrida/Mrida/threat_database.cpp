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

void threat_database::add_threat_to_database(std::string tlsh_hash, std::string threat_name, unsigned long file_size, std::string file_type)
{
	unsigned int file_type_id = mime_to_id(file_type);
	try {
		sqlite::database _threat_database("threat_db.db");
		_threat_database << "create table if not exists threat(id unsigned bigint primary key, threat_hash text, threat_name text, threat_size unsigned int, threat_type unsigned int);";
		unsigned long max_id = 0;
		_threat_database << "select max(id) from threat" >> max_id;
		max_id++;
		_threat_database << "insert into threat(id, threat_hash, threat_name, threat_size, threat_type) values(?, ?, ?, ?, ?)" << max_id << tlsh_hash << threat_name << file_size << file_type_id;
	}
	catch (std::exception &e)
	{
		std::cout << e.what();
	}
}


unsigned int threat_database::mime_to_id(std::string mime_type)
{

	sqlite::database db("threat_db.db");
	db << "create table if not exists mime_table(mime text, id int)";
	int count = 0;
	db << "select count(id) from mime_table where mime=?" << mime_type >> count;
	int max = 0;
	db << "select max(id) from mime_table limit 1" >> max;
	if (count == 0)
	{
		max++;
		db << "insert into mime_table(mime, id) values(?, ?)" << mime_type << max;
		return max;
	}
	else
	{
		unsigned int id;
		db << "select id from mime_table where mime=? limit 1" << mime_type >> id;
		return id;
	}
	return 0;
}

long threat_database::matching_hash_from_threat_db(std::string tlsh_hash, std::string file_type, long file_size_minimum, unsigned long file_size_maximum)
{
	long matched_id = -1;
	sqlite::database threat_table("threat_db.db");
	threat_table << "create table if not exists threat(id unsigned bigint primary key, threat_hash text, threat_name text, threat_size unsigned int, threat_type unsigned int);";
	unsigned int file_id = mime_to_id(file_type);
	threat_table << "select id, threat_hash from threat where threat_size>=? and threat_size<=? and threat_type=?"
		<< file_size_minimum << file_size_maximum << file_id >> [&](unsigned long id, std::string threat_hash)
	{
		trendcpp trend;
		if (trend.similarity_distance(tlsh_hash, threat_hash) < 20)
		{
			matched_id = id;
		}
	};
	return matched_id;
}
