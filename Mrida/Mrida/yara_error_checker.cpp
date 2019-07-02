// SWAMI KARUPPASWAMI THUNNAI

#include "yara_error_checker.h"

void check_error_in_yara_signatures()
{
	std::string directory_array[] = { "mac", "linux", "windows", "webserver" };
	print_terminal_info();
	for (std::string dir : directory_array)
	{
		success_print("Checking for Errors in " + dir + " directory.\n");
		for (auto file : std::experimental::filesystem::recursive_directory_iterator("yara/"+dir))
		{
			std::string file_location = file.path().u8string();
			yaracpp::YaraDetector yara;
			bool added = yara.addRuleFile(file_location);
			if (added)
			{
				print_terminal_info();
				success_print("YARA file is ok: " + file_location + ".\n");
			}
			else
			{
				print_terminal_info();
				error_print("Found error in file: " + file_location + ". [REMOVING]\n");
				std::remove(file_location.c_str());
			}
		}
	}
}
