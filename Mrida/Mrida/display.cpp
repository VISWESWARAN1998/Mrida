// SWAMI KARUPPASWAMI THUNNAI

#include "display.h"

void print_terminal_info()
{
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
}
