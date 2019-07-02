// SWAMI KARUPPASWAMI THUNNAI

#pragma once
#include <iostream>
#include <string>

#define BLUE 1
#define GREEN 2
#define CYAN 3
#define RED 4
#define LIGHTGREEEN 10
#define LIGHTRED 12
#define YELLOW 14
#define WHITE 15



void print_terminal_info();

void set_terminal_color(unsigned short int color=15);

// Print error message to the console
void error_print(std::string error_message);

// Print success message to the console
void success_print(std::string success_message);



