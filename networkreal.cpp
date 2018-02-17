#include <netinet/if_ether.h>
#include <iostream>
#include <stdio.h>
#include <cstring>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "walldefiner.h"
#include "wallnetworker.h"

/************* Helping function *************/
int service_map(char s[])
{
	if (is_match(s, "tcp")) return 0;
	else if (is_match(s, "udp")) return 1;
	else if (is_match(s, "icmp")) return 2;
	else if (is_match(s, "amy")) return 3;
	else return -1;
}//using the name to get the flag of the rules

