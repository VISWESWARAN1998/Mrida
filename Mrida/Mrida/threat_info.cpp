// SWAMI KARUPPASWAMI THUNNAI

#include "threat_info.h"

void threat_info::set_threat_name(std::string threat_name)
{
	this->threat_name = threat_name;
}

void threat_info::set_signature_author(std::string author)
{
	this->threat_signature_author = author;
}

void threat_info::set_threat_description(std::string description)
{
	this->threat_description = description;
}

std::string threat_info::get_threat_name()
{
	return this->threat_name;
}

std::string threat_info::get_threat_signature_author()
{
	return this->threat_signature_author;
}

std::string threat_info::get_threat_description()
{
	return this->threat_description;
}

