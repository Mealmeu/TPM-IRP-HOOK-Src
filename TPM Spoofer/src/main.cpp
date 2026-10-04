// made by Mealmeu

#include <Windows.h>
#include <iostream>
#include <string>

#include "main.h"

using namespace std;

void cls()
{
	system("cls");
}

void success()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("[");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
	cout << ("+");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("] ");
}

void failed()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("[");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	cout << ("-");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("] ");
}

void loading()
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("[");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 13);
	cout << ("/");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cout << ("] ");
}

void logo()
{
	std::cout << R"(

	$$$$$$$$\                            $$\       $$$$$$\   $$$$$$\                  $$\  $$$$$$\            
	\__$$  __|                           $$ |     $$$ __$$\ $$$ __$$\                 $$ |$$ ___$$\           
	   $$ | $$$$$$\  $$$$$$\$$$$\        $$ |     $$$$\ $$ |$$$$\ $$ | $$$$$$\   $$$$$$$ |\_/   $$ | $$$$$$\  
	   $$ |$$  __$$\ $$  _$$  _$$\       $$ |     $$\$$\$$ |$$\$$\$$ | \____$$\ $$  __$$ |  $$$$$ / $$  __$$\ 
	   $$ |$$ /  $$ |$$ / $$ / $$ |      $$ |     $$ \$$$$ |$$ \$$$$ | $$$$$$$ |$$ /  $$ |  \___$$\ $$ |  \__|
	   $$ |$$ |  $$ |$$ | $$ | $$ |      $$ |     $$ |\$$$ |$$ |\$$$ |$$  __$$ |$$ |  $$ |$$\   $$ |$$ |      
	   $$ |$$$$$$$  |$$ | $$ | $$ |      $$$$$$$$\\$$$$$$  /\$$$$$$  /\$$$$$$$ |\$$$$$$$ |\$$$$$$  |$$ |      
	   \__|$$  ____/ \__| \__| \__|      \________|\______/  \______/  \_______| \_______| \______/ \__|      
	       $$ |                                                                                               
	       $$ |                                                                                               
	       \__|                                                                                               

)";
}

int main()
{
	int select;
	string title = ("Tpm Hook Loader");
	string downloadpath = "C:\\Windows\\System32\\IME";
	string options;
	string options2;

	string deletefilemapper = downloadpath + "\\Mapper.exe";
	string deletefiletpm = downloadpath + "\\tpm.sys";

	string delcmd = "del " + deletefilemapper;
	string delcmd2 = "del " + deletefiletpm;

	SetConsoleTitleA(title.c_str());

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 5);
	logo();

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);

	cout << "[1] - TPM Clean" << endl;
	cout << "[2] - TPM Spoof" << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
	cout << "[3] - exit" << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 3);
	cout << "\n\n[>] ";
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	cin >> select;

	cls();

	if (select == 1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 6);
		options = "Starting Clean TPM | Selected: 1";
		options2 = "Clean TPM Success";
	} else if (select == 2)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 6);
		options = "Starting Spoof TPM | Selected: 2";
		options2 = "Spoof TPM Success";
	} else if (select == 3)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		options = "exit";
	}
	else
	{
		Sleep(1000);
		exit(0);
	}

	cout << options;
	Sleep(1000);

	cls();

	switch (select)
	{
	case 1:
		TPMClean();
		break;
	case 2:
		TPMMapper(downloadpath);
		break;
	case 3:
		cls();
		exit(0);
		break;
	default:
		cout << options + "is not";
		Sleep(1000);
		return 1;
	}

	cls();

	system(delcmd.c_str());
	system(delcmd2.c_str());

	cls();

	cout << options2;
	Sleep(1000);
	exit(0);

	return 0;
}
