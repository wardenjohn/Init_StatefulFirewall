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

#define TIMEOUT_INTIME 1 // this is the limit time of in packages 
#define TIMEOUT_OUTTIME 1 // this is the limited time of out packages
#define MAX_INPUT_LINE 7


int main(int ac , char *av[])
{
	int choice;
	choice = print_title_cpp();
	if(choice == 0)
		return -1;
	else{
		if(choice == 1 ){
			
		}
		else if(choice == 2 ){
			list_dev();
		}
		else if(choice == 3 ){
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

/*
int main(int ac,char *av[])
{
	pcap_if_t *dev;
	char errbuf[100];
	pcap_findalldevs(&dev,errbuf);

	pcap_if_t *dev_it;

	for(dev_it = dev ; dev_it != NULL ; dev_it = dev_it->next)
	{
		std::cout<<"device name :"<<dev_it->name<<std::endl;
	}
	return 0;
}
*/