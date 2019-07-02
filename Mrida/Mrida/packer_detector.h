// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <yaracpp/yaracpp.h>
#include <string>
#include <vector>

class packer_detector
{
private:
	yaracpp::YaraDetector yara;

public:
	packer_detector();
	~packer_detector();

	std::vector<std::string> get_detected_packers(std::string file_location);
};

