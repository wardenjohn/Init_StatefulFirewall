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
#define OK true
#define NO false

#define TIMEOUT_INTIME 1 // this is the limit time of in packages 
#define TIMEOUT_OUTTIME 1 // this is the limited time of out packages
#define MAX_SETTING_INPUT_LINE 7

int NEXT_TCP_PORT;
int NEXT_UDP_PORT;

int IS_ONLINE;

int ONLINE;

rules_list rules_table;//the rules table to store the rules
hash_node state_table[TABLE_LINE][TABLE_SIZE];
uint16_t port_map[MAP_SIZE][MAP_SIZE][PORT_RANGE];//class using the protocol/type 

/*function to find if the device is detected*/
bool is_devicefound(char *wait_to_check)
{
	pcap_if_t *alldev;
	char errbuf[BUFSIZE];
	int flag = pcap_findalldevs(&alldev,errbuf);
	if (flag == -1) {
		printf("Can not find out the web devices\n");
		exit(-1);
	}
	else {
		pcap_if_t *dev;
		int is_detected = 0;
		for (dev = alldev; dev != NULL; dev = dev->next) {
			if (strcmp(wait_to_check, dev->name) == 0) {//the ori code used matchname but i use strcmp here
				is_detected = 1;
				break;
			}
		}
		if (is_detected == 1) {
			return OK;
		}
		else {
			return NO;
		}
	}
}

/*function convert from setting to ip address*/
int convert_to_ip(char *buff,uint8_t *ip_dest)
{
	int a, b, c, d;
	sscanf(buff, "%d.%d.%d.%d", &a, &b, &c, &d);
	ip_dest[0] = a;
	ip_dest[1] = b;
	ip_dest[2] = c;
	ip_dest[3] = d;
	return 0;
}
///////////////////////////////////////////////

/*function convert from setting file to mac address*/
int conver_hexToint(char hex)
{
	hex = toupper(hex);
	return hex > '9' ? hex - 'A' + 10 : hex - '0';
}

int convert_to_mac(char* readbuff, uint8_t *mac_dest)
{
	// std::string tem;
	// for (int i = 0; i < readbuff.length(); i++) {
	// 	tem.append(convert_to_mac(readbuff[i]));
	// }
	// mac_dest = tem.c_str();//convert this string to char *
	// return 0;
	uint8_t aux;
	for(;*readbuff;readbuff+=3,mac_dest++){
		aux = (conver_hexToint(*readbuff) << 4 )+(conver_hexToint(*(readbuff+1)));
		*mac_dest = aux;
	}
}
////////////////////////////////////////////////////
int inital_firewall(firewall *fw ,char *name_in ,char *name_out ,char *errbuf)
{
	// std::ifstream settings;
	// settings.open("setting.config",std::ios::in);

	// if (!settings.is_open()) {
	// 	printf("opening setting.config errors,exit the program\n");
	// 	return -1;
	// }

	FILE *settings;
	settings = fopen("settings.config", "r");

	if (settings == NULL) {
		return 0;
	}
	int line = 0;
	char readbuff[1024];
	while (fgets(readbuff,1024,settings)) {

		int length = strlen(readbuff);
		if (line == 0) {
			convert_to_mac(readbuff, fw->virtual_mac_address);
		}
		else if (line == 1) {
			convert_to_mac(readbuff, fw->firewall_mac_address);
		}
		else if (line == 2) {
			convert_to_mac(readbuff, fw->switch_mac_address);
		}
		else if (line == 3){
			convert_to_mac(readbuff, fw->route_mac_address);
		}
		else if (line == 4) {
			//we need one more place here,convert to ip address
			fw->virtual_ip_buf = (char *)malloc(sizeof(length + 1));
			memcpy(fw->virtual_ip_buf,readbuff,length);
			fw->virtual_ip_buf[length] = 0;
			convert_to_ip(fw->virtual_ip_buf, fw->virtual_ip_bin);
		}
		else if (line == 5) {
			fw->firewall_ip_buf = (char *)malloc(sizeof(length + 1));
			memcpy(fw->firewall_ip_buf, readbuff, length);
			fw->firewall_ip_buf[length] = 0;
			convert_to_ip(fw->firewall_ip_buf, fw->firewall_ip_bin);
		}
		else if (line == 6) {
			fw->switch_ip_buf = (char *)malloc(sizeof(length + 1));
			memcpy(fw->firewall_ip_buf, readbuff, length);
			fw->switch_ip_buf[length] = 0;
			convert_to_ip(fw->switch_ip_buf, fw->switch_ip_bin);
		}
		else{
			break;
		}
		line++;
	}// this loop is convert the setting in file in to the program

	if (line != MAX_SETTING_INPUT_LINE) {
		fclose(settings);
		return -1;
	}

	int size = strlen(name_in);
	fw->devName_in = (char *)malloc(sizeof(size));
	memcpy(fw->devName_in, name_in,size);

	size = strlen(name_out);
	fw->devName_out = (char *)malloc(sizeof(size));
	memcpy(fw->devName_out, name_out, size);
	//this is used to copy the in dev and out dev into the firewall

	fw->data_timeout_in = TIMEOUT_INTIME;
	fw->data_timeout_out = TIMEOUT_OUTTIME;

	NEXT_TCP_PORT = HIGH_PORT;
	NEXT_UDP_PORT = HIGH_PORT;

	IS_ONLINE = 1;

	for (int i = 0; i < strlen(fw->devName_in); i++)
		if (fw->devName_in[i] == '.')//well , I am not clear why it is '.'
			ONLINE = 0;

	if (ONLINE) {
		if (!is_devicefound(fw->devName_in)) {
			printf("Device %s not found\n", fw->devName_in);
			exit(-1);
		}
		if (!is_devicefound(fw->devName_out)) {
			printf("Device %s not found", fw->devName_out);
			exit(-1);
		}

		//open_live return a pcap_t* to obtain a packet capture handle to look at packets on the network
		errbuf="";
		fw->pcap_in = pcap_open_live(fw->devName_in,BUFSIZE,0,fw->data_timeout_in,errbuf);
		if (fw->pcap_in == NULL) {
			printf("Error in pcap in ,device name : %s\n", fw->devName_in);
			return -1;
		}
		if (strlen(errbuf) != 0 && fw->pcap_in != NULL) {
			printf("Warning in pcap(in) : %s\n", errbuf);
		}
		if (pcap_datalink(fw->pcap_in) != 1) {
			printf("No ethernet data-link pcap in\n");
			return -1;
		}

		//using pcap_datalink to return the link-layer header type for the live capture
		errbuf = '\0';
		fw->pcap_out = pcap_open_live(fw->devName_out, BUFSIZE, 0, fw->data_timeout_out, errbuf);
		if (fw->pcap_out == NULL) {
			printf("Error in pcap out ,device name : %s\n", fw->devName_out);
			return -1;
		}
		if (strlen(errbuf) != 0 && fw->pcap_out != NULL) {
			printf("Warning in pcap(out) : %s\n",errbuf);
		}
		if (pcap_datalink(fw->pcap_out) != 1) {
			printf("No ethernet data-link pcap out\n");
			return -1;
		}
	}
	else {
		//pcap_open_offline will return a pcap_t* ,open a saved capture file for reading
		fw->pcap_in = pcap_open_offline(fw->devName_in, errbuf);
		if (fw->pcap_in == NULL) {
			printf("Error pcap in : %s \n", errbuf);
			return -1;
		}
		if (pcap_datalink(fw->pcap_in) != 1) {
			printf("No ethernet in pcap in \n");
			return -1;
		}

		fw->pcap_out = pcap_open_offline(fw->devName_out, errbuf);
		if (fw->pcap_out == NULL) {
			printf("Error pcap out in : %s \n", errbuf);
			return -1;
		}
		if (pcap_datalink(fw->pcap_out) != 1) {
			printf("No ethernet in pcap out \n");
			return -1;
		}
	}
	// settings.close();
	fclose(settings);
	return 0;
}

/////////////////////////////////////////////////////
//this is the function to set up the rules after setting up the firewall
//if success ,return 0
bool is_match(char *to_match,char *source)
{
	if (strlen(to_match) != strlen(source))
		return false;
	else {
		for (int i = 0; i < strlen(to_match); i++) {
			if (to_match[i] != source[i]) {
				return false;
			}
		}
	}
	return true;
}

uint16_t get_port(uint16_t port,int type,int dir)
{
	int count;
	if (type == TCP) {//protocol:TCP check all port
		for (count = 0; count < PORT_RANGE; count++) {
			if (port_map[type][dir][count] == 0) break;
			if (port_map[type][dir][count] == port) return port_map[type][(dir+1)%2][count];//Dont know why
		}
		if (count == PORT_RANGE) {
			std::cout << "Out of the Port Range" << std::endl;
			return 0;
		}
		port_map[type][dir][count] = port;
		port_map[type][(dir + 1) % 2][count] = NEXT_TCP_PORT;
		return NEXT_TCP_PORT++;
	}
	else if(type == UDP)
	{
		for (count = 0; count < PORT_RANGE; count++) {
			if (port_map[type][dir][count] == 0) break;
			if (port_map[type][dir][count] == port) return port_map[type][(dir + 1) % 2][count];
		}
		if (count == PORT_RANGE) {
			std::cout << "Out of the Port Range" << std::endl;
			return 0;
		}
		port_map[type][dir][count] = port;
		port_map[type][(dir + 1) % 2][count] = NEXT_UDP_PORT;
		return NEXT_UDP_PORT++;
	}
}

int inital_rules(firewall *fw)
{
	for (int i = 0; i < TABLE_LINE; i++) {
		for (int j = 0; j < TABLE_SIZE; j++) {
			state_table[i][j].length = 0;
			state_table[i][j].head = NULL;//initial each node
		}
	}
	for (int i = 0; i < PORT_RANGE; i++) {
		port_map[TCP][IN][i] = 0;
		port_map[TCP][OUT][i] = 0;
		port_map[UDP][IN][i] = 0;
		port_map[UDP][OUT][i] = 0;
	}//[rules][oper][range]

	rules_table.length = 0;
	rules_table.head = NULL;
	rules_table.tail = NULL;

	// std::fstream rules_file;
	// rules_file.open("default.rules");

	// if (!rules_file.is_open()) {
	// 	std::cout << "opening rules file failed!" << std::endl;
	// 	return -1;
	// }
	FILE *rules_file;
	rules_file = fopen("default.rules", "r");

	if (rules_file == NULL) {
		return 0;
	}

	char buff[1024];
	char rules[32], dir[32], service[32];
	char ip_src[32], ip_dest[32], port_source[32], port_destin[32];
	int count_rules = 0;

	uint8_t ip_bin[4];//store ip in binary
	while (fgets(buff,1024,rules_file)) {
		count_rules++;
		sscanf(buff, "%s %s %s %s %s %s %s", rules, dir, service, ip_src, port_source, ip_dest, port_destin);

		rules_ele *new_rule = (rules_ele *)malloc(sizeof(rules_ele));
		new_rule->destination_ip_any = 0;
		new_rule->destination_port_any = 0;
		new_rule->source_ip_any = 0;
		new_rule->source_port_any = 0;

		//Translation of the rules
		if (is_match(rules, "block"))
			new_rule->rules = BLOCK;
		else if (is_match(rules, "allow"))
			new_rule->rules = ALLOW;
		else {
			printf("no such rule from the description of the file at line %d\n", count_rules);
			free(new_rule);
		}

		//Direction
		if (is_match(dir, "in"))
			new_rule->direction = IN;
		else if (is_match(dir, "out"))
			new_rule->direction = OUT;
		else {
			printf("no such direction from the file at line %d\n", count_rules);
			free(new_rule);
		}

		//Service
		new_rule->service = service_map(service);
		if (new_rule->service == -1) {
			printf("protocol initial wrong ,at line %d\n", count_rules);
			free(new_rule);
		}

		//ip source 
		if (is_match(ip_src, "HOME")) {
			memcpy(ip_src, fw->virtual_ip_buf, strlen(fw->virtual_ip_buf) + 1);
		}
		if (is_match(ip_src, "any")) {
			new_rule->source_ip_any = 1;
		}
		else {
			str_to_ip(ip_src,ip_bin);//change the format from string into ip address
			new_rule->source_ip = unpack_4byte(ip_bin);
		}

		//Port Source
		if (is_match(port_source, "any")) {
			new_rule->source_port_any = 1;
		}
		else {
			new_rule->source_port = atoi(port_source);
		}

		//IP Destnation
		if (is_match(ip_dest, "HOME")) {
			memcpy(ip_dest,fw->virtual_ip_buf,strlen(fw->virtual_ip_buf+1));
		}
		if (is_match(ip_dest, "any")) {
			new_rule->destination_ip_any = 1;
		}
		else {
			new_rule->destination_ip = unpack_4byte(ip_bin);
		}

		//Port Destnation
		if (is_match(port_destin, "any")) {
			new_rule->destination_port_any = 1;
		}
		else {
			new_rule->destination_port = atoi(port_destin);
		}

		//inital_rules(new_rule);
		insert_rules(new_rule);
	}
	return 1;
}

//this function is for the protocal which is tcp
int NAT_TCP(firewall *fw,ethernet_stor *ethernet_header ,ip_stor *ip_header,tcp_stor *tcp_header,int dir)
{//dir --> direction
	if (dir == OUT) { //direction
		memcpy(ethernet_header->source_mac,fw->switch_mac_address,sizeof(fw->switch_mac_address));
		memcpy(ethernet_header->destnation_mac,fw->route_mac_address,sizeof(fw->route_mac_address));
		memcpy(ip_header->source_ip,fw->switch_ip_bin,sizeof(fw->switch_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_source_port = get_port(unpack_2byte(tcp_header->source_port),TCP,dir);
		new_source_port = pack_2byte((uint8_t *)&new_source_port);
		memcpy(tcp_header->source_port,(uint8_t *)&new_source_port,sizeof(uint16_t));

		psedo_tcp_stor *psedo_tcp_head = (psedo_tcp_stor *)malloc(sizeof(psedo_tcp_stor));

		memcpy(psedo_tcp_head->source_ip, ip_header->source_ip, sizeof(ip_header->source_ip));
		memcpy(psedo_tcp_head->destination_ip, ip_header->destnation_ip, sizeof(ip_header->destnation_ip));
		psedo_tcp_head->reseved = 0;//means still not reaseved
		psedo_tcp_head->protocol = ip_header->protocol;

		uint16_t len = unpack_2byte(ip_header->total_length) - ((ip_header->version & 0x0F) * 4);
		psedo_tcp_head->tcp_length[0] = ((uint8_t)(len >> 8)) & 0xFF;
		psedo_tcp_head->tcp_length[1] = (uint8_t)(len) & 0xFF; //I dont know why there should & 0xFF

		psedo_tcp_head->tcp_head = (tcp_stor *)malloc(len);
		memcpy(psedo_tcp_head->tcp_head, tcp_header, sizeof(len));
		compute_tcp_checksum(psedo_tcp_head);
		memcpy(tcp_header->checksum,psedo_tcp_head->tcp_head->checksum,sizeof(psedo_tcp_head->tcp_head->checksum));
		free(psedo_tcp_head->tcp_head);
		free(psedo_tcp_head);
	}
	else if (dir == IN) {
		memcpy(ethernet_header->source_mac, fw->firewall_mac_address, sizeof(fw->firewall_mac_address));
		memcpy(ethernet_header->destnation_mac, fw->virtual_mac_address, sizeof(fw->virtual_mac_address));
		memcpy(ip_header->destnation_ip,fw->virtual_ip_bin,sizeof(fw->virtual_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_destination_port = get_port(unpack_2byte(tcp_header->destination_port),TCP,dir);
		new_destination_port = pack_2byte((uint8_t*)&new_destination_port);
		memcpy(tcp_header->destination_port,(uint8_t*)&new_destination_port,sizeof(uint16_t));
	
		psedo_tcp_stor *psedo_tcp_head = (psedo_tcp_stor*)malloc(sizeof(psedo_tcp_stor));
		memcpy(psedo_tcp_head->source_ip, ip_header->source_ip, sizeof(ip_header->source_ip));
		memcpy(psedo_tcp_head->destination_ip, ip_header->destnation_ip, sizeof(ip_header->destnation_ip));

		psedo_tcp_head->protocol = ip_header->protocol;
		psedo_tcp_head->reseved = 0;

		uint16_t length = unpack_2byte(ip_header->total_length) - ((ip_header->version & 0x0F) * 4);
		psedo_tcp_head->tcp_length[0] = ((uint8_t)(length >> 8)) & 0xFF;
		psedo_tcp_head->tcp_length[1] = (uint8_t)(length) & 0xFF;

		psedo_tcp_head->tcp_head = (tcp_stor *)malloc(length);
		memcpy(psedo_tcp_head->tcp_head, tcp_header, length);
		compute_tcp_checksum(psedo_tcp_head);
		memcpy(tcp_header->checksum, psedo_tcp_head->tcp_head->checksum, sizeof(tcp_header->checksum));
		free(psedo_tcp_head->tcp_head);
		free(psedo_tcp_head);
	}
	return 1;
}

int NAT_UDP(firewall *fw, ethernet_stor *ethernet_header, ip_stor *ip_header, udp_stor *udp_header, int dir)
{
	if (dir == OUT) {
		memcpy(ethernet_header->source_mac, fw->switch_mac_address, sizeof(fw->switch_mac_address));
		memcpy(ethernet_header->destnation_mac, fw->route_mac_address, sizeof(fw->route_mac_address));
		memcpy(ip_header->source_ip, fw->switch_ip_bin, sizeof(fw->switch_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_sorce_port = get_port(unpack_2byte(udp_header->source_port), UDP, dir);
		new_sorce_port = pack_2byte((uint8_t*)&new_sorce_port);
		memcpy(udp_header->source_port,(uint8_t*)&new_sorce_port,sizeof(uint16_t));

		psedo_udp_stor *psedo_upd_header = (psedo_udp_stor*)malloc(sizeof(psedo_udp_stor));

		memcpy(psedo_upd_header->source_ip, ip_header->source_ip, sizeof(ip_header->source_ip));
		memcpy(psedo_upd_header->destination_ip, ip_header->destnation_ip, sizeof(ip_header->destnation_ip));
		psedo_upd_header->reserved = 0;
		psedo_upd_header->protocol = ip_header->protocol;
		uint16_t length = unpack_2byte(udp_header->length);
		psedo_upd_header->udp_length[0] = udp_header->length[0];
		psedo_upd_header->udp_length[1] = udp_header->length[1];

		psedo_upd_header->udp_head = (udp_stor*)malloc(length);
		memcpy(psedo_upd_header->udp_head, udp_header, length);
		
		compute_udp_checksum(psedo_upd_header);
		memcpy(udp_header->checksum,psedo_upd_header->udp_head->checksum,sizeof(udp_header->checksum));
		free(psedo_upd_header->udp_head);
		free(psedo_upd_header);
	}
	else if (dir == IN) {
		memcpy(ethernet_header->source_mac, fw->firewall_mac_address, sizeof(fw->firewall_mac_address));
		memcpy(ethernet_header->destnation_mac, fw->virtual_mac_address, sizeof(fw->virtual_mac_address));
		memcpy(ip_header->destnation_ip, fw->virtual_ip_bin, sizeof(fw->virtual_ip_bin));
		compute_ip_checksum(ip_header);

		uint16_t new_destination_port = get_port(unpack_2byte(udp_header->destination_port), UDP, dir);
		new_destination_port = pack_2byte((uint8_t*)&new_destination_port);
		memcpy(udp_header->destination_port, (uint8_t*)&new_destination_port, sizeof(uint16_t));

		psedo_udp_stor *psedo_udp_head = (psedo_udp_stor*)malloc(sizeof(psedo_udp_stor));
		memcpy(psedo_udp_head->source_ip, ip_header->source_ip, sizeof(ip_header->source_ip));
		memcpy(psedo_udp_head->destination_ip, ip_header->destnation_ip, sizeof(ip_header->destnation_ip));
		psedo_udp_head->reserved = 0;
		psedo_udp_head->protocol = ip_header->protocol;
		uint16_t length = unpack_2byte(udp_header->length);
		psedo_udp_head->udp_length[0] = udp_header->length[0];
		psedo_udp_head->udp_length[1] = udp_header->length[1];

		psedo_udp_head->udp_head = (udp_stor*)malloc(length);
		memcpy(psedo_udp_head->udp_head,udp_header,sizeof(length));
		compute_udp_checksum(psedo_udp_head);
		memcpy(udp_header->checksum,psedo_udp_head->udp_head->checksum,sizeof(udp_header->checksum));
		free(psedo_udp_head->udp_head);
		free(psedo_udp_head);
	}
	else {
		printf("Wrong Direction Syntax ! Error situation function : NAT_UDP\n");
		return -1;
	}

	return 1;
}

int NAT_ICMP(firewall *fw, ethernet_stor *ethernet_header, ip_stor *ip_header, int dir)
{
	if (dir == OUT) {
		memcpy(ethernet_header->source_mac,fw->switch_mac_address,sizeof(fw->switch_mac_address));
		memcpy(ethernet_header->destnation_mac, fw->route_mac_address, sizeof(fw->route_mac_address));
		memcpy(ip_header->source_ip,fw->switch_ip_bin,sizeof(fw->switch_ip_bin));
		compute_ip_checksum(ip_header);
	}
	else if (dir == IN) {
		memcpy(ethernet_header->source_mac,fw->firewall_mac_address,sizeof(fw->firewall_mac_address));
		memcpy(ethernet_header->destnation_mac,fw->virtual_mac_address,sizeof(fw->virtual_mac_address));
		memcpy(ip_header->destnation_ip, fw->virtual_ip_bin, sizeof(fw->virtual_ip_bin));
		compute_ip_checksum(ip_header);
	}
	else {
		printf("Wrong Direction Syntax ! Error Situation : function NAT_ICMP\n");
		return -1;
	}
	return 1;
}

void bulid_ARP_reply(firewall *fw,arp_stor *arp_header)
{
	arp_stor* arp_head_cpy = copy_arp_head(arp_header);
	uint16_t arp_operation = 2;
	uint8_t arp_op_reply[2];
	arp_op_reply[0] = 0;
	arp_op_reply[1] = (uint8_t)arp_operation & 0xFF;

	memcpy(arp_header->operation,arp_op_reply,sizeof(arp_op_reply));
	memcpy(arp_header->sender_hardware_addr,fw->firewall_mac_address,sizeof(fw->firewall_mac_address));
	memcpy(arp_header->sender_protocol_addr, arp_head_cpy->target_protocol_addr,sizeof(arp_head_cpy->target_protocol_addr));
	memcpy(arp_header->target_hardware_addr, arp_head_cpy->sender_hardware_addr,sizeof(arp_head_cpy->sender_hardware_addr));
	memcpy(arp_header->target_protocol_addr, arp_head_cpy->sender_protocol_addr,sizeof(arp_head_cpy->sender_protocol_addr));
	
	free(arp_head_cpy);
}
////////////////////////////////////////////////////
//main function listen in the data
int listen_in(firewall *fw)
{
	const uint8_t *packet = NULL;
	struct pcap_pkthdr *header = NULL; //pcap_pkthdr _readme.md ---1

	int ret = pcap_next_ex(fw->pcap_in, &header, &packet);//pcap_next_ex() README.md ---2

	if (ret == -2) return -1;
	if (packet == NULL) return -1;

	ethernet_stor *enthernet_header = (ethernet_stor *)packet;
	uint16_t enthertype = unpack_2byte(enthernet_header->ethernet_type);
	struct timeval current_time = header->ts;

#if DEBUGGING
	
#endif // DEBUGGING

	if (enthertype == ETHERTYPE_IP) {
		ip_stor *ip_header = (ip_stor *)malloc(sizeof(ip_stor));
		int protocol = ip_header->protocol;
		ip_group ip;
		ip_group inv_ip;
		ip_port_group ip_port;
		ip_port_group inv_ip_port;

#ifdef DEBUGGING

#endif // DEBUGGING , operate if under the debugging status

		if (address_equals_ip(fw->switch_ip_bin, ip_header->destnation_ip)) {
			if (protocol == 6) {//TCP
				tcp_status A;
				tcp_status A_inv;
				void* table_entry;

				int ihl = ip_header->version & 0x0F;
				tcp_stor *tcp_header = (tcp_stor *)malloc(sizeof(tcp_stor));

				ip_port.source_ip = ip.source_ip;
				ip_port.destination_ip = ip.destination_ip;
				ip_port.destination_port = unpack_2byte(tcp_header->destination_port);
				ip_port.source_port = unpack_2byte(tcp_header->source_port);

				inv_ip_port.source_ip = ip.source_ip;
				inv_ip_port.destination_ip = ip.destination_ip;
				inv_ip_port.source_port = ip_port.source_port;
				inv_ip_port.destination_port = ip_port.destination_port;

				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				NAT_TCP(fw, enthernet_header, ip_header, tcp_header, OUT);

				table_entry = state_table_find(state_table[TCP],(void*)&A_inv,TCP);//Inverted connection direction
				if (table_entry != NULL) {
					if (!TCP_check_state((tcp_status*)table_entry, (tcp_status*)&A_inv, tcp_header->flags, 1)) {
						return 0;
					}
					state_table_update(table_entry,(void*)&A_inv,TCP);
					packet_inject(fw->pcap_out,packet,header->caplen,"OUT/TCP");
					return 0;
				}

				table_entry = state_table_find(state_table[TCP],(void*)&A,TCP);
				if (table_entry != NULL) {
					if (!TCP_check_state((tcp_status*)table_entry, (tcp_status*)&A, tcp_header->flags, 0)) {
						return 0;
					}
					state_table_update(table_entry,(void *)&A,TCP);
					packet_inject(fw->pcap_out,header,header->caplen,"OUT/TCP");
				}

				if (!check_rule(OUT, TCP, ip.source_ip, ip.destination_ip, ip_port.source_port, ip_port.destination_port)) {
					//This package was block by the firewall , drop it
					return 0;
				}

				if (!TCP_check_state((tcp_status*)table_entry, (tcp_status*)&A, tcp_header->flags, 0)) {
					return 0;
				}
				state_table_insert(state_table[TCP],(void*)&A,TCP);//insert a new tcp stats
				packet_inject(fw->pcap_out,packet,header->caplen,"OUT/TCP");
			}
			else if (protocol == 17) {//UDP protocol
				udp_status A;
				udp_status A_inv;
				void *table_entry;
				int ihl = ip_header->version & 0x0F;
				udp_stor *udp_header = (udp_stor*)(&ip_header->version + ihl*4);

				ip_port.source_ip = ip.source_ip;
				ip_port.destination_ip = ip.destination_ip;
				ip_port.source_port = unpack_2byte(udp_header->source_port);
				ip_port.destination_port = unpack_2byte(udp_header->destination_port);

				inv_ip_port.source_ip = ip.destination_ip;
				inv_ip_port.destination_ip = ip.source_ip;
				inv_ip_port.source_port = ip_port.destination_port;
				inv_ip_port.destination_port = ip_port.source_port;

				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;

				NAT_UDP(fw, enthernet_header, ip_header, udp_header, OUT);

				table_entry = state_table_find(state_table[UDP], (void*)&A_inv, UDP);//Inverted connection direction.
				if (table_entry != NULL) {
					state_table_update(table_entry,(void*)&A_inv,UDP);
					packet_inject(fw->pcap_out,packet,header->caplen,"OUT/UDP");
					return 0;
				}

				table_entry = state_table_find(state_table[UDP], (void*)&A, UDP);
				if (table_entry != NULL) {
					state_table_update(table_entry, (void*)&A, UDP);
					packet_inject(fw->pcap_out, packet, header->caplen, "OUT/UDP");
					return 0;
				}

				if (!check_rule(OUT, UDP, ip.source_ip, ip.destination_ip, ip_port.source_port, ip_port.destination_port));//blocked by the firewall
				return 0;

				state_table_insert(state_table[UDP],(void*)&A,UDP);
				packet_inject(fw->pcap_out, packet, header->caplen, "OUT/UDP");
				return 0;
			}
			else if (protocol == 1) {//ICMP
				icmp_status A;
				icmp_status A_inv;
				void* table_entry;

				A.ip = ip;
				A_inv.ip = ip;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				NAT_ICMP(fw,enthernet_header,ip_header,OUT);

				table_entry = state_table_find(state_table[ICMP], (void*)&A_inv, ICMP);// Inverted connection direction.
				if (table_entry != NULL) {
					state_table_update(table_entry, (void*)&A_inv, ICMP);
					packet_inject(fw->pcap_out, packet, header->caplen, "OUT/ICMP");
					return 1;
				}

				table_entry = state_table_find(state_table[ICMP], (void*)&A, ICMP);
				if (table_entry != NULL) {
					state_table_update(table_entry, (void*)&A, ICMP);
					packet_inject(fw->pcap_out, packet, header->caplen, "OUT/ICMP");
					return 1;
				}

				if (!check_rule(OUT, ICMP, ip.source_ip, ip.destination_ip, ip_port.source_port, ip_port.destination_port))
					return 1;

				state_table_insert(state_table[ICMP], (void*)&A, ICMP);
				packet_inject(fw->pcap_out, packet, header->caplen, "OUT/ICMP");
				return 1;

			}
			else {
				printf("Other protocol , drop this packet!;Define function : listen_in \n");
				return 1;
			}
		}
	}

	if (enthertype == ETHERTYPE_ARP) {
		arp_stor *arp_header = (arp_stor*)malloc(sizeof(arp_stor));
		uint16_t arp_operation = unpack_2byte(arp_header->operation);
		if (arp_operation == 1) {
			if (address_equal_ip(fw->firewall_ip_bin, arp_header->target_protocol_addr)) {
				bulid_ARP_reply(fw, arp_header);
				packet_inject(fw->pcap_in, packet, header->caplen, "IN/ARP");
				return 1;
			}
		}
	}

	return 1;
}
////////////////////////////////////////////////////
//main function listen out or sending out the data
int listen_out(firewall *fw)
{
	const uint8_t* packet = NULL;
	struct pcap_pkthdr *header = NULL;

	int ret = pcap_next_ex(fw->pcap_out, &header, &packet);
	if (ret == -2) return -1;
	if (packet == NULL) return -1;

	ethernet_stor* ethernet_header = (ethernet_stor*)packet;
	uint16_t ethertype = unpack_2byte(ethernet_header->ethernet_type);
	struct timeval current_time = header->ts;

#ifdef DEBUGGING

#endif // DEBUGGING

	if (ethertype == ETHERTYPE_IP) {
		ip_stor* ip_header = (ip_stor*)ethernet_header->data;
		int protocol = ip_header->protocol;
		ip_group ip;
		ip_group inv_ip;
		ip_port_group ip_port;
		ip_port_group inv_ip_port;

			#ifdef DEBUGGING
		
			#endif

		if (address_equal_ip(fw->switch_ip_bin, ip_header->destnation_ip)){ //Switch gets a packet for it, let's send to VM if allowed. 
			if (protocol == 6) {
				tcp_status A;
				tcp_status A_inv;
				void *table_entry;

				int ihl = ip_header->version & 0x0F;
				tcp_stor *tcp_header = (tcp_stor*)(ip_header->version + ihl * 4);

				if (NAT_TCP(fw,ethernet_header,ip_header,tcp_header,IN)==0) {
					return 0;
				}

				ip.source_ip = unpack_4byte(ip_header->source_ip);
				ip.destination_ip = unpack_4byte(ip_header->destnation_ip);
				inv_ip.source_ip = ip.destination_ip;
				inv_ip.destination_ip = ip.source_ip;

				ip_port.source_ip = ip.source_ip;
				ip_port.destination_ip = ip.destination_ip;
				ip_port.source_port = unpack_2byte(tcp_header->source_port);
				ip_port.destination_port = unpack_2byte(tcp_header->destination_port);

				inv_ip_port.source_ip = ip.destination_ip;
				inv_ip_port.destination_ip = ip.source_ip;
				inv_ip_port.source_port = ip_port.destination_port;
				inv_ip_port.destination_port = ip_port.source_port;

				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				table_entry = state_table_find(state_table[TCP], (void*)&A_inv, TCP);
				if (table_entry != NULL) {
					if (!TCP_check_state((tcp_status*)table_entry,(tcp_status*)&A_inv,tcp_header->flags,1)) {
						return 0;
					}
					state_table_update(state_table[TCP], (void*)&A_inv, TCP);
					packet_inject(fw->pcap_out,packet,header->caplen,"IN/TCP");
				}

				table_entry = state_table_find(state_table[TCP], (void*)&A, TCP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					if (!TCP_check_state((tcp_status*)table_entry, (tcp_status*)&A, tcp_header->flags, 0))
						return 0;
					state_table_update(table_entry, (void*)&A, TCP);
					packet_inject(fw->pcap_in, packet, header->caplen, "IN/TCP");
					return 0;
				}

				if (!check_rule(IN, TCP, ip.source_ip, ip.destination_ip, ip_port.source_port, ip_port.destination_port)) // Blocked by firewall, drop the packet.
					return 0;

				if (!TCP_check_state((tcp_status*)table_entry, (tcp_status*)&A, tcp_header->flags, 0))
					return 0;
				state_table_insert(state_table[TCP], (void*)&A, TCP); // New TCP state
				packet_inject(fw->pcap_in, packet, header->caplen, "IN/TCP");
				return 0;
			}

			else if (protocol == 17) {
				udp_status A;
				udp_status A_inv;
				void *table_entry;

				int ihl = ip_header->version & 0x0F;
				udp_stor *udp_header = (udp_stor*)(ip_header->version + ihl * 4);

				if (NAT_UDP(fw, ethernet_header, ip_header, udp_header, IN) == 0) return 0;

				ip.source_ip = unpack_4byte(ip_header->source_ip);
				ip.destination_ip = unpack_4byte(ip_header->destnation_ip);
				inv_ip.source_ip = ip.destination_ip;
				inv_ip.destination_ip = ip.source_ip;

				ip_port.source_ip = ip.source_ip;
				ip_port.destination_ip = ip.destination_ip;
				ip_port.source_port = unpack_2byte(udp_header->source_port);
				ip_port.destination_port = unpack_2byte(udp_header->destination_port);

				inv_ip_port.source_ip = ip.destination_ip;
				inv_ip_port.destination_ip = ip.source_ip;
				inv_ip_port.source_port = ip_port.destination_port;
				inv_ip_port.destination_port = ip_port.source_port;

				A.ip_port = ip_port;
				A_inv.ip_port = inv_ip_port;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				table_entry = state_table_find(state_table[UDP], (void*)&A_inv, UDP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, UDP);
					packet_inject(fw->pcap_in, packet, header->caplen, "IN/UDP");
					return 0;
				}

				table_entry = state_table_find(state_table[UDP], (void*)&A, UDP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, UDP);
					packet_inject(fw->pcap_in, packet, header->caplen, "IN/UDP");
					return 0;
				}

				if (!check_rule(IN, UDP, ip.source_ip, ip.destination_ip, ip_port.source_port, ip_port.destination_port)) // Blocked by firewall, drop the packet.
					return 0;

				state_table_insert(state_table[UDP], (void*)&A, UDP); // UDP state
				packet_inject(fw->pcap_in, packet, header->caplen, "IN/UDP");
				return 0;
			}
			else if (protocol == 1) {
				icmp_status A;
				icmp_status A_inv;
				void* table_entry;

				NAT_ICMP(fw, ethernet_header, ip_header, IN);

				ip.source_ip = unpack_4byte(ip_header->source_ip);
				ip.destination_ip = unpack_4byte(ip_header->destnation_ip);
				inv_ip.source_ip = ip.destination_ip;
				inv_ip.destination_ip = ip.source_ip;
				A.ip = ip;
				A_inv.ip = inv_ip;
				A.event_time = current_time;
				A_inv.event_time = current_time;

				table_entry = state_table_find(state_table[ICMP], (void*)&A_inv, ICMP); // Inverted connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A_inv, ICMP);
					packet_inject(fw->pcap_in, packet, header->caplen, "IN/ICMP");
					return 0;
				}

				table_entry = state_table_find(state_table[ICMP], (void*)&A, ICMP); // Current connection direction.
				if (table_entry != NULL) { // Previous flow exists
					state_table_update(table_entry, (void*)&A, ICMP);
					packet_inject(fw->pcap_in, packet, header->caplen, "IN/ICMP");
					return 0;
				}

				if (!check_rule(IN, ICMP, ip.source_ip, ip.destination_ip, 0, 0)) // Blocked by firewall, drop the packet.
					return 0;

				state_table_insert(state_table[ICMP], (void*)&A, ICMP); // ICMP state

				packet_inject(fw->pcap_in, packet, header->caplen, "IN/ICMP");
				return 0;
			}
			else {
				printf("Other Protocol,drop this packet; situation : listen_out ");
			}
		}
	}

	if (ethertype == ETHERTYPE_ARP) {
		arp_stor* arp_header = (arp_stor*)ethernet_header->data;
		uint16_t arp_operation = unpack_2byte(arp_header->operation);

		if (arp_operation == 1) { // This is arp request
			if (address_equal_ip(fw->firewall_ip_bin, arp_header->target_protocol_addr)) { // ARP request for firewall IP
				bulid_ARP_reply(fw, arp_header);
				packet_inject(fw->pcap_out, packet, header->caplen, "OUT/ARP");
				return 1;
			}
		}
	}
}

////////////////////////////////////////////////////
int run_firewall(int ac)
{
	char errbuf[ERRBUF_SIZE];
	// std::string name_in_t, name_out_t;
	// std::cin >> name_in_t >> name_out_t;
	// char name_in = name_in_t.c_str();
	// char name_out = name_out_t.c_str();
	char *name_in,*name_out;
	scanf("%s",name_in);
	scanf("%s",name_out);

	firewall *fw = (firewall *)malloc(sizeof(firewall));
	
	if (!inital_firewall(fw, name_in, name_out, errbuf)) {
		//if failed when initaling firewall
		std::cout << "Errors while initialing the stateful firewall" << std::endl;
		return -1;
	}

	if (!inital_rules(fw)) {
		//if failed when initaling the rules
		printf("Errors when setting up rules\n");
		return -1;
	}

	while (true) {
		listen_in(fw);
		listen_out(fw);
	}

	return 0;
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
