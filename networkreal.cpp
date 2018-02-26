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

/************** Function for the rule list *******/
void insert_rules(rules_ele *rule)
{
	if (rules_table.length == 0) {
		rules_table.length = 1;
		rules_table.head = rule;
		rules_table.tail = rule;
		rule->next = NULL;
	}
	else {
		rule->next = NULL;
		rules_table.length++;
		rules_table.tail->next = rule;
		rules_table.tail = rule;
	}
}//insert a rule node into the rule table


/************* Helping function *************/
int service_map(char s[])
{
	if (is_match(s, "tcp")) return 0;
	else if (is_match(s, "udp")) return 1;
	else if (is_match(s, "icmp")) return 2;
	else if (is_match(s, "amy")) return 3;
	else return -1;
}//using the name to get the flag of the rules

void str_to_ip(char *buf, uint8_t *ip) 
{
	int a, b, c, d;
	sscanf(buf, "%d,%d,%d,%d", &a, &b, &c, &d);
	ip[0] = a;
	ip[1] = b;
	ip[2] = c;
	ip[3] = d;
}

uint32_t unpack_4byte(const uint8_t *buf)
{
	uint32_t aux;
	memcpy(&aux,buf,sizeof(uint32_t));
	return ntonl(aux);//ntohl() function is to convert the unsign long web data into the format of this computer
}

uint16_t unpack_2byte(const uint8_t *buf)
{
	uint16_t aux;
	memcpy(&aux, buf, sizeof(uint16_t));
	return htons(aux);
}

bool address_address_equals_ip(const uint8_t *source, const uint8_t *check)
{
	for (int i = 0; i < IP_SIZE; i++)
		if (source[i] != check[i])
			return false;

	return true;
}
/*******************Debug function***********************/
void print_ethernet(ethernet_stor *ethernet_head, char *dir)
{
	char str[64];
	char arp[] = "ARP";
	char ip[] = "IP";
	char null[] = "null";
	char *type = NULL;
	uint16_t enthertype = unpack_2byte(ethernet_head->ethernet_type);
	//use unpack function to get the type into this function

	
}