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

/************** Package Function *****************/

void compute_ip_checksum(ip_stor *ip)
{
	ip->checksum[0] = 0;
	ip->checksum[1] = 0;

	uint8_t *data = (uint8_t *)ip; //force to change the ip into uint8_t of data
	uint32_t acc = 0xFFFF;
	uint8_t len = ip->version;
	len = len & 0xF;
	len *= 4;

	for (int i = 0; i < len + 1; i+=2) {
		uint16_t word;
		memcpy(&word, data + i,2);
		acc += ntohs(word);
		if (acc > 0xffff) acc -= 0xffff;
	}
	if (len & 1) {
		uint16_t word = 0;
		memcpy(&word, ip+len-1 , 1);
		acc += ntohs(word);
		if (acc > 0xffff) acc -= 0xffff;
	}
	uint16_t checksum = ntohs(~acc);
	uint8_t ax[2];
	ax[0] = (uint8_t)checksum & 0xFF;
	ax[1] = (uint8_t)(checksum >> 8) & 0xFF;
	memcpy(ip->checksum, ax, sizeof(ax));
}

void compute_tcp_checksum(psedo_tcp_stor *psedo_tcp)
{
	psedo_tcp->tcp_head->checksump[0] = 0;
	psedo_tcp->tcp_head->checksump[1] = 1;

	uint8_t *data = (uint8_t*)psedo_tcp;
	uint32_t acc = 0xFFFF;
	uint16_t length = unpack_2byte(psedo_tcp->tcp_length);
	
	//This is the part to do with psedo_tcp
	for (int i = 0; i + 1 < 12; i += 2) {
		uint16_t word;
		memcpy(&word,data+i,2);
		acc += ntohs(word);
		if (acc > 0xffff) acc -= 0xffff;
	}

	//This is the part to do with tcp_header
	data = (uint8_t*)psedo_tcp->tcp_head;
	for (int i = 0; i + 1 < length; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff)acc -= 0xffff;
	}

	if (length & 1) {
		uint16_t word = 0;
		memcpy(&word, psedo_tcp->tcp_head->source_port + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff)acc -= 0xffff;
		word = 0;
		acc += ntohs(word);
		if (ac > 0xffff)acc -= 0xffff;

	}

	uint16_t checksum = htons(~acc);
	uint8_t ax[2];
	ax[0] = (uint8_t)checksum & 0xFF;
	ax[1] = (uint8_t)(checksum >> 8) & 0xFF;
	memcpy(psedo_tcp->tcp_head->checksump,ax,sizeof(ax));
}

void compute_udp_checksum(psedo_udp_stor *psedo_udp)
{
	psedo_udp->udp_head->checksum[0] = 0;
	psedo_udp->udp_head->checksum[1] = 0;

	uint32_t acc = 0xFFFF;
	uint8_t *data = (uint8_t*)psedo_udp;
	uint16_t length = unpack_2byte(psedo_udp->udp_length);

	//For the psedo part
	for (int i = 0; i + 1 < 12; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
	}

	//For the udp header part
	data = (uint8_t*)psedo_udp->udp_head;
	for (int i = 0; i + 1 < length; i += 2) {
		uint16_t word;
		memcpy(&word, data + i, 2);
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
	}

	if (length & 1) {
		uint16_t word = 0;
		memcpy(&word, psedo_udp->udp_head->source_port + length - 1, 1);
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
		word = 0;
		acc += ntohs(word);
		if (acc > 0xffff)
			acc -= 0xffff;
	}

	uint16_t checksum = htons(~acc);
	uint8_t ax[2];
	ax[0] = (uint8_t)checksum & 0xFF;
	ax[1] = (uint8_t)(checksum >> 8) & 0xFF;
	memcpy(psedo_udp->udp_head->checksum, ax, sizeof(ax));
}

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
	return ntohs(aux);
}

uint16_t pack_2byte(const uint8_t *buf)
{
	uint16_t aux;
	memcpy(&aux, buf, sizeof(uint16_t));
	return htons(aux);
}

uint32_t pack_4byte(const uint8_t *buf)
{
	uint32_t aux;
	memcpy(&aux, buf, sizeof(uint32_t));
	return htonl(aux);
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