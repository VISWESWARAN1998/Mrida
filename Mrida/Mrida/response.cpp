// SWAMI KARUPPASWAMI THUNNAI

#include "response.h"

using json = nlohmann::json;

std::string send_failure_response()
{
	json failed;
	failed["message"] = false;
	return failed.dump();
}

std::string send_success_response()
{
	json failed;
	failed["message"] = true;
	return failed.dump();
}

std::string threat_info_vector_to_string(std::vector<threat_info> vec)
{
	json threat_info_bucket;
	threat_info_bucket["message"] = true;
	json detection_list = json::array();
	for (threat_info info : vec)
	{
		//json detection = json::array();
		json threat;
		threat["name"] = info.get_threat_name();
		threat["description"] = info.get_threat_description();
		threat["author"] = info.get_threat_signature_author();
		//detection.push_back(threat);
		detection_list.push_back(threat);
	}
	threat_info_bucket["detections"] = detection_list;
	return threat_info_bucket.dump();
}

std::string packer_vector_to_json(std::vector<std::string> packers)
{
	json detected_packers;
	detected_packers["detected"] = packers;
	return detected_packers.dump();
}

std::string shannon_rntropy_to_json(double entropy_value)
{
	json entropy;
	entropy["entropy"] = entropy_value;
	return entropy.dump();
}

std::string is_domain_blocked_json(bool blocked_status)
{
	json blocked;
	blocked["message"] = blocked_status;
	return blocked.dump();
}

std::string tlsh_hash_to_json(std::string tlsh_hash)
{
	json tlsh;
	tlsh["message"] = tlsh_hash;
	return tlsh.dump();
}

std::string tlsh_hash_distance_to_json(int distance)
{
	json tlsh;
	tlsh["message"] = distance;
	return tlsh.dump();
}

std::string return_json(long value)
{
	json j;
	j["message"] = value;
	return j.dump();
}
