// SWAMI KARUPPASWAMI THUNNAI

#include "httplib.h"
#include <iostream>
#include <vector>
#include <experimental/filesystem>
#include <thread>
#include <yaracpp/yaracpp.h>
#include "yara_scanner.h"
#include "threat_info.h"
#include "response.h"
#include "display.h"
#include "packer_detector.h"
#include "shannon_entropy.h"
#include "yara_error_checker.h"
#include "web_blocker.h"
#include "trendcpp.h"
#include "threat_database.h"


int main(int argc, char** argv)
{
	set_terminal_color();
	std::cout << "MRIDA AV CONSOLE\n";
	set_terminal_color(CYAN);
	std::cout << "________________________________________\n";
	set_terminal_color();
	httplib::Server server;

	// SCAN INDIVIDUAL FILE FOR YARA SIGNATURES
	server.Post("/scan_file_for_yara", [](const httplib::Request& req, httplib::Response& res) {
		bool is_file_present = req.has_param("file");
		bool is_target_mentioned = req.has_param("target");
		print_terminal_info();
		std::cout << "REQUEST MADE TO SCAN FILE WITH YARA: ";
		if (!is_file_present)
		{
			res.set_content(send_failure_response(), "application/json");
			set_terminal_color(RED);
			std::cout << "[LOCATION NOT FOUND]\n";
			set_terminal_color();
		}
		else if (!is_target_mentioned)
		{
			res.set_content(send_failure_response(), "application/json");
			set_terminal_color(RED);
			std::cout << "[TARGET NOT MENTIONED!]\n";
			set_terminal_color();
		}
		else
		{
			std::string file_location = req.get_param_value("file");
			std::string target = req.get_param_value("target");
			std::cout << file_location << "\n";
			yara_scanner scanner(target);
			std::vector<threat_info> detections = scanner.scan_file(file_location);
			res.set_content(threat_info_vector_to_string(detections), "application/json");
		}
	});

	// DETECTING PACKERS IN A FILE
	server.Post("/scan_file_for_packer", [](const httplib::Request& req, httplib::Response& res) {
		print_terminal_info();
		set_terminal_color(YELLOW);
		std::cout << "REQUEST HAS BEEN MADE TO DETECT PACKERS.\n";
		set_terminal_color();
		bool is_param_present = req.has_param("file");
		if (is_param_present)
		{
			packer_detector detector;
			std::vector<std::string> packer_list = detector.get_detected_packers(req.get_param_value("file"));
			res.set_content(packer_vector_to_json(packer_list), "application/json");
		}
		else
		{
			res.set_content(send_failure_response(), "application/json");
		}
	});

	// ANAMOLY - SHANON ENTROPY
	server.Post("/shannon_entropy_for_file", [](const httplib::Request& req, httplib::Response& res) {
		print_terminal_info();
		set_terminal_color(CYAN);
		std::cout << "REQUEST HAS BEEN MADE TO CALCULATE SHANNON ENTROPY.\n";
		set_terminal_color();
		bool is_param_present = req.has_param("file");
		if (is_param_present)
		{
			std::string file_location = req.get_param_value("file");
			if (std::experimental::filesystem::exists(file_location))
			{
				shannon_entropy entropy;
				double entropy_value = entropy.shanon_entropy_for_file(file_location);
				print_terminal_info();
				std::cout << "SHANON ENTROPY OF FILE: " << entropy_value << "\n";
				res.set_content(shannon_rntropy_to_json(entropy_value), "application/json");
			}
			else
			{
				print_terminal_info();
				error_print("File Location does not exist!\n");
			}
		}
		else
		{
			res.set_content(send_failure_response(), "application/json");
		}
	});

	// Check all yara signatures whether they can be compiled are not
	server.Get("/check_yara", [](const httplib::Request& req, httplib::Response& res)
	{
		check_error_in_yara_signatures();
		res.set_content(send_success_response(), "application/json");
	});

	// Check whether a domain is blocked or not
	server.Get("/is_domain_blocked", [](const httplib::Request& req, httplib::Response& res)
	{
		bool is_param_present = req.has_param("host");
		if (is_param_present)
		{
			print_terminal_info();
			set_terminal_color(YELLOW);
			std::string domain = req.get_param_value("host");
			std::cout << "CHECKING DOMAIN FOR BLACKLISTS: ";
			set_terminal_color(CYAN);
			std::cout << domain << "\n";
			set_terminal_color();
			web_blocker domain_blocker;
			bool blocked = domain_blocker.is_domain_blocked(domain);
			res.set_header("Content-Type", "application/json");
			res.set_header("X-Content-Type-Options", "nosniff");
			res.set_header("Access-Control-Allow-Origin", "*");
			res.set_content(is_domain_blocked_json(blocked), "application/json");
		}
	});

	// Display blocked page
	server.Get("/blocked", [](const httplib::Request& req, httplib::Response& res) {
		print_terminal_info();
		set_terminal_color(LIGHTGREEEN);
		std::cout << "Serving blocked.html\n";
		set_terminal_color();
		std::string out;
		httplib::detail::read_file("templates/blocked.html", out);
		res.set_content(out, "text/html");
	});

	// Block a domain
	server.Post("/block_domain", [](const httplib::Request& req, httplib::Response& res) {
		print_terminal_info();
		bool is_param_present = req.has_param("host");
		if (is_param_present)
		{
			std::string domain = req.get_param_value("host");
			web_blocker block;
			block.add_domain_to_blocked(domain);
			res.set_content(send_success_response(), "application/json");
		}
	});

	// Scan all the process for virustotal
	server.Post("/proc_scan", [](const httplib::Request& req, httplib::Response& res) {
		bool is_api_key_present = req.has_param("api");
		bool is_type_present = req.has_param("type");
		if (is_api_key_present && is_type_present)
		{
			std::string api_key = req.get_param_value("api");
			std::string type = req.get_param_value("type");
			if (type == "gui")
			{
				res.set_content(send_success_response(), "application/json");
				std::string command = "procscan.exe " + type + " " + api_key;
				print_terminal_info();
				set_terminal_color(LIGHTGREEEN);
				std::cout << "PERFORMING VIRUSTOTAL SCAN ON RUNNING PROCESSES\n";
				set_terminal_color();
				system(command.c_str());
			}
		}
	});

	// Getting the TLSH hash for the file
	server.Post("/get_tlsh", [](const httplib::Request& req, httplib::Response& res) {
		bool is_file_present = req.has_param("file");
		if (is_file_present)
		{
			trendcpp tlsh;
			std::string hash = tlsh.hash_file_to_string(req.get_param_value("file"));
			print_terminal_info();
			set_terminal_color(CYAN);
			std::cout << "GETTING HASH FOR" << req.get_param_value("file") << "\n";
			set_terminal_color();
			res.set_content(tlsh_hash_to_json(hash), "application/json");
		}
	});

	// Check the similarity distance for TWO TLSH hashes
	server.Get("/get_tlsh_distance", [](const httplib::Request& req, httplib::Response& res) {
		bool is_hash_one_present = req.has_param("hash_one");
		bool is_hash_two_present = req.has_param("hash_two");
		print_terminal_info();
		std::cout << "REQUESTED TO GET SIMILARITY DISTANCE\n";
		if (is_hash_one_present && is_hash_two_present)
		{
			trendcpp tlsh;
			int similarity_distance = tlsh.similarity_distance(req.get_param_value("hash_one"), req.get_param_value("hash_two"));
			res.set_content(tlsh_hash_distance_to_json(similarity_distance), "application/json");
		}
	});

	// Check threat database
	server.Get("/check_threat_db", [](const httplib::Request& req, httplib::Response& res) {
		bool is_hash_present = req.has_param("tlsh");
		bool is_min_size_present = req.has_param("min_size");
		bool is_max_size_present = req.has_param("max_size");
		bool is_type_present = req.has_param("type");
		if (is_hash_present && is_min_size_present && is_max_size_present && is_type_present)
		{
			print_terminal_info();
			set_terminal_color(BLUE);
			std::cout << "SENDING HASH MATCHING INFO\n";
			set_terminal_color();
			std::string tlsh_hash = req.get_param_value("tlsh");
			long min_size = std::stoll(req.get_param_value("min_size"));
			long max_size = std::stoll(req.get_param_value("max_size"));
			std::string type = req.get_param_value("type");
			trendcpp tlsh;
			long id = tlsh.matching_hash_from_threat_db(tlsh_hash, type, min_size, max_size);
			res.set_content(return_json(id), "application/json");
		}
	});

	// Removing duplicates in threat database
	server.Get("/refactor_threat_db", [](const httplib::Request& req, httplib::Response& res) {
		threat_database db;
		db.refactor();
		res.set_content(send_success_response(), "application/json");
	});

	print_terminal_info();
	std::cout << "Server started on: " << "127.0.0.1:" << 5660 << "\n";
	server.listen("127.0.0.1", 5660);
}