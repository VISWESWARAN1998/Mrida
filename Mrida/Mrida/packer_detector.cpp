// SWAMI KARUPPASWAMI THUNNAI

#include <experimental/filesystem>
#include "packer_detector.h"
#include "display.h"



packer_detector::packer_detector()
{
	// print the display message
	set_terminal_color();
	print_terminal_info();
	std::cout << "\nUsing Packer Detection Yara Signatures By: ";
	set_terminal_color(LIGHTGREEEN);
	std::cout << "https://github.com/Xumeiquer/PEiD_to_Yara\n";
	set_terminal_color();
	std::cout << "Using Packer Detection Yara Signatures By: ";
	set_terminal_color(LIGHTGREEEN);
	std::cout << "https://raw.githubusercontent.com/horsicq/Detect-It-Easy/master/yara/packer.yar\n";
	set_terminal_color();
	if (std::experimental::filesystem::exists("packer_detector.yar"))
	{
		this->yara.addRuleFile("packer_detector.yar");
	}
	else
	{
		error_print("packer_detector.yar is missing.");
		std::cout << "\n";
	}
}


packer_detector::~packer_detector()
{
	std::cout << "[PACKER DETECTOR] Process completed!\n";
	print_terminal_info();
}

std::vector<std::string> packer_detector::get_detected_packers(std::string file_location)
{
	std::vector<std::string> packers;
	if (!std::experimental::filesystem::exists(file_location))
	{
		error_print("[Invalid Location]: " + file_location + "\n");
		return packers;
	}
	if (yara.analyze(file_location))
	{
		std::vector<yaracpp::YaraRule> matched_rules = yara.getDetectedRules();
		for (yaracpp::YaraRule rule : matched_rules)
		{
			error_print("[DETECTED]: " + rule.getName() + "\n");
			packers.push_back(rule.getName());
		}
	}
	return packers;
}
