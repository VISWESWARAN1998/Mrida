// SWAMI KARUPPASWAMI THUNNAI

#pragma once

#include "json.h"
#include "threat_info.h"

/*
Contains the reponse messages which are sent by the server
*/

// Send action failed response
std::string send_failure_response();

std::string threat_info_vector_to_string(std::vector<threat_info> vec);

// Converts the detected packers to json
std::string packer_vector_to_json(std::vector<std::string> packers);

