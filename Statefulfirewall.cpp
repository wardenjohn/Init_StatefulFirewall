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
int convert_to_ip(char *buff,char *ip_dest)
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
	return hex > '9' ? hex - 'A' + 10 : hex - '0';
}

int convert_to_mac(std::string readbuff, char *mac_dest)
{
	std::string tem;
	for (int i = 0; i < readbuff.length(); i++) {
		tem.append(convert_to_mac(readbuff[i]));
	}
	mac_dest = tem.c_str();//convert this string to char *
	return 0;
}
////////////////////////////////////////////////////
int inital_firewall(firewall *fw ,char *name_in ,char *name_out ,char *errbuf)
{
	std::ifstream settings;
	settings.open("setting.config",ios::in);

	if (!settings.is_open()) {
		printf("opening setting.config errors,exit the program\n");
		return -1;
	}

	int line = 0;
	std::string readbuff[BUFSIZE];
	while (getline(settings, readbuff)) {
		int length = readbuff->length();
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
		settings.close();
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
		char err[BUFSIZE] = '\0';
		fw->pcap_in = pcap_open_live(fw->devName_in,BUFSIZE,0,fw->data_timeout_in,err);
		if (fw->pcap_in == NULL) {
			printf("Error in pcap in ,device name : %s\n", fw->devName_in);
			return -1;
		}
		if (strlen(err) != 0 && fw->pcap_in != NULL) {
			printf("Warning in pcap(in) : %s\n", err);
		}
		if (pcap_datalink(fw->pcap_in) != 1) {
			printf("No ethernet data-link pcap in\n");
			return -1;
		}

		//using pcap_datalink to return the link-layer header type for the live capture
		err = '\0';
		fw->pcap_out = pcap_open_live(fw->devName_out, BUFSIZE, 0, fw->data_timeout_out, err);
		if (fw->pcap_out == NULL) {
			printf("Error in pcap out ,device name : %s\n", fw->devName_out);
			return -1;
		}
		if (strlen(err) != 0 && fw->pcap_out != NULL) {
			printf("Warning in pcap(out) : %s\n",err);
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
	settings.close();
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

	std::fstream rules_file;
	rules_file.open("default.rules");

	if (!rules_file.is_open()) {
		std::cout << "opening rules file failed!" << std::endl;
		return -1;
	}

	char buff[1024];
	char rules[32], driver[32], service[32];
	char ip_src[32], ip_dest[32], port_source[32], port_destin[32];
	int count_rules = 0;

	uint8_t ip_bin[4];//store ip in binary
	while (getline(rules_file, buff)) {
		count_rules++;
		sscanf(buff, "%s %s %s %s %s %s %s", rules, driver, service, ip_src, port_source, ip_dest, port_destin);

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
			new_rule->source_port_any = 1
		}
		else {
			new_rule->source_port = atoi(port_source);
		}

		//IP Destnation
		if (is_match(ip_dest, "HOME")) {
			memcpy(ip_dest,fw->virtual_ip_buf,strlen(sizeof(fw->virtual_ip_buf)+1));
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

		inital_rules(new_rule);
	}
	return 1;
}

////////////////////////////////////////////////////
//main function listen in the data
int listen_in(firewall *fw)
{

}
////////////////////////////////////////////////////
//main function listen out or sending out the data
int listen_out(firewall *fw)
{

}

////////////////////////////////////////////////////
int run_firewall(int ac)
{
	char errbuf[ERRBUF_SIZE];
	std::string name_in_t, name_out_t;
	std::cin >> name_in_t >> name_out_t;
	char name_in = name_in_t.c_str();
	char name_out = name_out_t.c_str();

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