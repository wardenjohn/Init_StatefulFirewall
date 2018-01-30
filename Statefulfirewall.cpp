#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include "walldefiner.h"
#include "wallnetworker.h"
#include "extendfun.h"

#define BUFSIZE 1024

#define TIMEOUT_INTIME 1 // this is the limit time of in packages 
#define TIMEOUT_OUTTIME 1 // this is the limited time of out packages
#define MAX_INPUT_LINE 7

int inital_firewall(firewall *fw ,char *name_in ,char *name_out ,char *errbuf)
{
	std::ifstream settings;
	settings.open("setting.config",ios::in);

	if (!settings.is_open()) {
		printf("opening setting.config errors,exit the program\n");
		return -1;
	}

	int line = 0;
	char readbuff[BUFSIZE];
	while (getline(settings, readbuff)) {
		int length = strlen(readbuff);
		if (line == 0) {

		}
	}
}

int run_firewall(int ac)
{
	char errbuf[ERRBUF_SIZE];
	std::string name_in_t, name_out_t;
	std::cin >> name_in_t >> name_out_t;
	char name_in = name_in_t.c_str();
	char name_out = name_out_t.c_str();

	firewall *fw = (firewall *)malloc(sizeof(firewall));
	
	if (!inital_firewall(fw, name_in, name_out, errbuf)) {
		std::cout << "Errors while initialing the stateful firewall" << std::endl;
		exit(-1);
	}

}
//this is the entrance of the firewall function

int main(int ac , char *av[])//av is included the ./running command
{
	int choice;
	choice = print_title_cpp();
	if(choice == 0)
		return -1;
	else{
		if(choice == 1 ){
			//run the stateful firewall
			int flag;
			printf("please enter the enter device and out device\n" );
			flag=run_firewall(ac);
		}
		else if(choice == 2 ){
			//list the devices situation
			list_dev();
		}
		else if(choice == 3){
			//check about the network connection
			check_connection();
		}
		else if(choice == 4){
			//recover or stop the network connection
			re_st_net();
		}
		else if(choice == 5 ){
			printf("See you !\n");
			exit(0);
		}
		else{
			char err[]=" Something wrong while running the program , exit the program with exit code -1";
			printf("%s\n", err);
		}
	}
	return 0;
}

/* Processing stste:
*	you need to finish sevel function of the choosen menu;
*	how to check the network state
*	how to relize the stateful firewall?
*/