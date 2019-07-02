// SWAMI KARUPPASWAMI THUNNAI

#include <fstream>
#include <vector>
#include "shannon_entropy.h"
#include "display.h"



shannon_entropy::shannon_entropy()
{
}


shannon_entropy::~shannon_entropy()
{
}

double shannon_entropy::shanon_entropy_for_file(std::string file_location)
{
	double entropy = 0.0;
	std::ifstream file;
	file.open(file_location, std::ios::binary);
	if (file.is_open())
	{
		std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
		length = buffer.size();
		for (unsigned char c : buffer)
		{
			if (dictionay.find(c) == dictionay.end()) dictionay[c] = 1;
			else dictionay[c] += 1;
		}
		file.close();
	}
	std::map<unsigned char, unsigned int>::iterator itr1 = dictionay.begin();
	std::map<unsigned char, unsigned int>::iterator itr2 = dictionay.end();
	for (std::map<unsigned char, unsigned int>::iterator itr = itr1; itr != itr2; ++itr)
	{
		double frequency = (double)itr->second / length;
		entropy -= frequency * (log(frequency) / log(2));
	}
	return entropy;
}


