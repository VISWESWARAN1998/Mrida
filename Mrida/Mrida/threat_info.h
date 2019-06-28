// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <string>

/*
A data-structure for holding information of detected yara signatures
*/
class threat_info
{
private:
	std::string threat_name;
	std::string threat_signature_author;
	std::string threat_description;

public:

	void set_threat_name(std::string threat_name);
	void set_signature_author(std::string author);
	void set_threat_description(std::string description);

	std::string get_threat_name();
	std::string get_threat_signature_author();
	std::string get_threat_description();

};