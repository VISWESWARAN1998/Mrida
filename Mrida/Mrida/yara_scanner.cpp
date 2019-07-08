// SWAMI KARUPPASWAMI THUNNAI

#include <iostream>
#include <string>
#include <fstream>
#include <experimental/filesystem>
#include "yara_scanner.h"
#include "display.h"



yara_scanner::yara_scanner(std::string target)
{
	if (target == "all")
	{
		load_yara_files_from_folder("windows");
		load_yara_files_from_folder("linux");
		load_yara_files_from_folder("mac");
		load_yara_files_from_folder("webserver");
	}
	else load_yara_files_from_folder(target);
}

std::vector<threat_info> yara_scanner::scan_file(std::string file_location)
{
	std::vector<threat_info> detected_signatures;
	if (this->yara.analyze(file_location))
	{
		// Get matched signatures
		for (yaracpp::YaraRule rule : yara.getDetectedRules())
		{
			std::string threat_name = rule.getName();
			std::string description = "UNKNOWN DESCRIPTION";
			std::string author = "UNKNOWN AUTHOR";
			std::vector<yaracpp::YaraMeta> meta_data = rule.getMetas();
			for (yaracpp::YaraMeta meta : meta_data)
			{
				if (meta.getId() == "description")
				{
					description = meta.getStringValue();
				}
				else if (meta.getId() == "author")
				{
					author = meta.getStringValue();
				}
			}
			threat_info signature;
			signature.set_threat_name(threat_name);
			signature.set_signature_author(author);
			signature.set_threat_description(description);
			detected_signatures.push_back(signature);
		}
	}
	return detected_signatures;
}

void yara_scanner::display_contributors(std::string target)
{
	if (!std::experimental::filesystem::exists("yara/" + target + ".txt")) return;
	std::ifstream file;
	file.open("yara/" + target + ".txt");
	if (file.is_open())
	{
		while (!file.eof())
		{
			std::string line;
			std::getline(file, line);
			print_terminal_info();
			set_terminal_color(CYAN);
			std::cout << "USING RULES FROM: ";
			set_terminal_color(YELLOW);
			std::cout << line << "\n";
			set_terminal_color();
		}
		file.close();
	}
}

void yara_scanner::load_yara_files_from_folder(std::string folder_name)
{
	display_contributors(folder_name);
	for (auto file : std::experimental::filesystem::recursive_directory_iterator("yara/" + folder_name))
	{
		std::string yara_file = file.path().u8string();
		this->yara.addRuleFile(yara_file);
	}
}
