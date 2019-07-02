// SWAMI KARUPPASWAMI THUNNAI

#pragma once

#include<iostream>
#include<string>
#include<map>

class shannon_entropy
{
private:
	std::map<unsigned char, unsigned int> dictionay;
	unsigned int length;
public:
	shannon_entropy();
	~shannon_entropy();

	double shanon_entropy_for_file(std::string file_location);
};

