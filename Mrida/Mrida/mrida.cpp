// SWAMI KARUPPASWAMI THUNNAI

#include "httplib.h"
#include <iostream>
#include <vector>
#include <yaracpp/yaracpp.h>
#include "yara_scanner.h"
#include "threat_info.h"
#include "response.h"
#include "display.h"

yara_scanner scanner;

int main(int argc, char** argv)
{
	set_terminal_color();
	std::cout << "MRIDA AV CONSOLE\n";
	set_terminal_color(CYAN);
	std::cout << "________________________________________\n";
	set_terminal_color();
	httplib::Server server;
	// SCAN INDIVIDUAL FILE
	server.Post("/scan_file_for_yara", [](const httplib::Request& req, httplib::Response& res) {
		bool is_file_present = req.has_param("file");
		print_terminal_info();
		std::cout << "REQUEST MADE TO SCAN FILE: ";
		if (!is_file_present)
		{
			res.set_content(send_failure_response(), "application/json");
			set_terminal_color(RED);
			std::cout << "[LOCATION NOT FOUND]\n";
			set_terminal_color();
		}
		else
		{
			std::string file_location = req.get_param_value("file");
			std::cout << file_location << "\n";
			std::vector<threat_info> detections = scanner.scan_file(file_location);
			res.set_content(threat_info_vector_to_string(detections), "application/json");
		}
	});
	print_terminal_info();
	std::cout << "Server started on: " << "127.0.0.1:" << 5660 << "\n";
	server.listen("127.0.0.1", 5660);
}