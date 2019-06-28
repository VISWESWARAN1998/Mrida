// SWAMI KARUPPASWAMI THUNNAI

#include "response.h"

using json = nlohmann::json;

std::string send_failure_response()
{
	json failed;
	failed["message"] = false;
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
