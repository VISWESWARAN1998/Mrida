// SWAMI KARUPPASWAMI THUNNAI

#include <vector>
#include <yaracpp/yaracpp.h>
#include "threat_info.h"


class yara_scanner
{

private:
	yaracpp::YaraDetector yara;

public:
	yara_scanner();

	std::vector<threat_info> scan_file(std::string file_location);
};

