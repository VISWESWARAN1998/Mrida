// SWAMI KARUPPASWAMI THUNNAI

#pragma once

#include "json.h"
#include "threat_info.h"

/*
Contains the reponse messages which are sent by the server
*/

// Send action failed response
std::string send_failure_response();

// Send action succeded response
std::string send_success_response();

std::string threat_info_vector_to_string(std::vector<threat_info> vec);

// Converts the detected packers to json
std::string packer_vector_to_json(std::vector<std::string> packers);

// Shanon Entropy
std::string shannon_rntropy_to_json(double entropy_value);

// Is Domain Blocked to JSON
std::string is_domain_blocked_json(bool blocked_status);

// Sending TLSH hash JSON
std::string tlsh_hash_to_json(std::string tlsh_hash);

// TLSH hash distance
std::string tlsh_hash_distance_to_json(int distance);
