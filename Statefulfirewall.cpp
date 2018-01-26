#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <string.h>
#include <pcap/pcap.h>

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
