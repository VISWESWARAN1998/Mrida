// SWAMI KARUPPASWAMI THUNNAI

#include "httplib.h"
#include <iostream>
#include <vector>
#include <experimental/filesystem>
#include <yaracpp/yaracpp.h>
#include "yara_scanner.h"
#include "threat_info.h"
#include "response.h"
#include "display.h"
#include "packer_detector.h"
#include "shannon_entropy.h"
#include "yara_error_checker.h"

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

	// About Mrida Server
	server.Get("/about", [](const httplib::Request& req, httplib::Response& res) {
		print_terminal_info();
		set_terminal_color(LIGHTGREEEN);
		std::cout << "Serving about.html\n";
		set_terminal_color();
		std::string out;
		httplib::detail::read_file("templates/about.html", out);
		res.set_content(out, "text/html");
	});

	print_terminal_info();
	std::cout << "Server started on: " << "127.0.0.1:" << 5660 << "\n";
	server.listen("127.0.0.1", 5660);
}