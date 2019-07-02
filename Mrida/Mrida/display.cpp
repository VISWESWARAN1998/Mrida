// SWAMI KARUPPASWAMI THUNNAI

#include "display.h"

#ifdef _WIN32
	#include <Windows.h>
	#include <ShlObj_core.h>
	#include <Lmcons.h>
#endif // !_WIN32



void print_terminal_info()
{
#ifdef _WIN32
	char username[UNLEN + 1];
	DWORD len_of_username = UNLEN + 1;
	GetUserName(username, &len_of_username);
	std::cout << username << "@";
	char computer_name[UNLEN + 1];
	DWORD len_of_computer_name = UNLEN + 1;
	GetComputerName(computer_name, &len_of_computer_name);
	std::cout << computer_name << ":~";
	if (IsUserAnAdmin()) std::cout << "# ";
	else std::cout << "$ ";
#else
	std::cout << "[LINUX TERMINAL]: ";
#endif // _WIN32
}

void set_terminal_color(unsigned short int color)
{
#ifdef _WIN32
	HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(consoleHandle, color);
#endif // _WIN32
}

void error_print(std::string error_message)
{
	set_terminal_color(LIGHTRED);
	std::cout << error_message;
	set_terminal_color();
}

void success_print(std::string success_message)
{
	set_terminal_color(LIGHTGREEEN);
	std::cout << success_message;
	set_terminal_color();
}
