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
arp_stor* copy_arp_head(arp_stor* arp_header)// Mind some bug if happend
{
	arp_stor* arp_head_cpy = new(arp_stor);
	memcpy(arp_head_cpy, arp_header, sizeof(arp_stor));
	return arp_head_cpy;
}

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

void packet_inject(pcap_t *p, const void *packet, size_t len, char* dir)
{
	if (ONLINE) {
		if (pcap_inject(p, packet, len) == -1) {
			printf("Error inject %s / %s \n", pacp_geterr(p), dir);
			exit(1);
		}
	}
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

int check_rule(int dir, int service, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
	int ret;
	if (dir == IN) ret = 0;
	if (dir == OUT)ret = 1;

	rules_ele *pointer;
	pointer = rules_table.head;
	while (pointer != NULL) {
		if (service == TCP || service == UDP) {
			if (pointer->direction == dir) {
				if (pointer->rules == ALLOW) {
					if ((pointer->service == service || pointer->service == ANY) && (pointer->source_ip==src_ip||pointer->source_ip_any)
						 && (pointer->destination_ip==dst_ip || pointer->destination_ip_any) && (pointer->source_port == src_port || pointer->source_port_any)
					     && (pointer->destination_port==dst_port || pointer->destination_port_any))
					{
						ret = 1;
					}
				}
				else if (pointer->rules == BLOCK) {
					if ((pointer->service == service || pointer->service == ANY) && (pointer->source_ip == src_ip || pointer->source_ip_any)
						&& (pointer->destination_ip == dst_ip || pointer->destination_ip_any) && (pointer->source_port == src_port || pointer->source_port_any)
						&& (pointer->destination_port == dst_port || pointer->destination_port_any)) {
						ret = 0;
					}
				}
			}
		}
		else if(service == ICMP) {
			if (pointer->direction == dir) {
				if (pointer->rules == ALLOW) {
					if ((pointer->service == service || pointer->service == ANY) && (pointer->source_ip==src_ip||pointer->source_ip_any)
						&&(pointer->destination_ip==dst_ip||pointer->destination_ip_any)) {
						ret = 1;
					}
				}
				else if (pointer->rules == BLOCK) {
					if ((pointer->service == service || pointer->service == ANY) && (pointer->source_ip == src_ip || pointer->source_ip_any)
						&& (pointer->destination_ip == dst_ip || pointer->destination_ip_any)) {
						ret = 0;
					}
				}
			}
		}
		pointer = pointer->next;
	}
	return ret;
}
/************* Hash Functions ******************/

int hash_ip_port(ip_port_group ip_port)
{
	int result = 17;//why
	result = 31 * result + ip_port.source_ip;
	result = 31 * result + ip_port.destination_ip;
	if (result < 0) result = result*-1;
	return result%TABLE_SIZE;
}

int state_hash(void* state_A, int server_number)
{
	if (server_number == 0) { //TCP
		tcp_status *tcp_A = (tcp_status*)state_A;
		return hash_ip_port(tcp_A->ip_port);
	}
	else if(server_number == 1){//UDP
		udp_status *udp_A = (udp_status*)state_A;
		return hash_ip_port(udp_A->ip_port);
	}
	else if (server_number == 2) {//ICMP
		icmp_status *icmp_A = (icmp_status*)state_A;
		return hash_ip_port(icmp_A->ip);
	}
	else {
		std::cout << "Wrong service number !" << std::endl;
		return -1;
	}
}

/************** Function for the State table *****/

int out_dated_entry(void* stats_A, void* stats_B, int serv_number)
{
	struct timeval diff;
	if (serv_number == 0) {
		tcp_status *tcp_A = (tcp_status*)stats_A;
		tcp_status *tcp_B = (tcp_status*)stats_B;
		timersub(&tcp_A->event_time, &tcp_B->event_time, &diff);
		uint64_t milliseconds = (diff.tv_sec*(uint64_t)1000) + (diff.tv_usec / 1000);
		if (milliseconds > 6000 && tcp_B->last_state == 4) return 1; //1 minutes and close
	}
	else if (serv_number == 1) {
		udp_status *udp_A = (udp_status*)stats_A;
		udp_status *udp_B = (udp_status*)stats_B;
		timersub(&udp_A->event_time, &udp_B->event_time, &diff);
		uint64_t milliseconds = (diff.tv_sec*(uint64_t)1000) + (diff.tv_usec / 1000);
		if (milliseconds > 6000) return 1;
	}
	else if (serv_number == 2) {
		icmp_status *icmp_A = (icmp_status*)stats_A;
		icmp_status *icmp_B = (icmp_status*)stats_B;
		timersub(&icmp_A->event_time, &icmp_B->event_time, &diff);
		uint64_t milliseconds = (diff.tv_sec*(uint64_t)1000) + (diff.tv_usec / 1000);
		if (milliseconds > 6000) return 1;
	}
	return 0;
}

void* state_table_find(hash_node *hash_table, void* status_A, int server_number)
{
	int hash=state_hash(status_A,server_number);
	int length = hash_table[hash].length;
	if (length == 0)return NULL;
	hash_ele *hash_pointer = hash_table[hash].head;
	hash_ele *hash_prev = NULL;
	
	while (hash_pointer != NULL) {
		if (out_dated_entry(status_A, hash_pointer->stats, server_number)) {
			if (hash_prev == NULL) { //no previes pointer
				hash_table[hash].head = hash_pointer->next;
			}
			else {
				hash_prev->next = hash_pointer->next;
			}
			hash_table[hash].length--;
			free(hash_pointer->stats);
			free(hash_pointer);
			if (hash_prev == NULL)
				hash_pointer = hash_table[hash].head;
			else
				hash_pointer = hash_prev;
			if (hash_pointer == NULL)
				return NULL;
		}
		else {
			if (match_status(status_A, hash_pointer->stats, server_number))
				return hash_pointer->stats;
		}
		hash_pointer = (hash_ele*)hash_pointer->next;
	}
	return NULL;
}

int match_status(void* status_A, void* status_B, int type) 
{
	if (type == 0) { //tcp
		tcp_status *tcp_A = (tcp_status*)status_A;
		tcp_status *tcp_B = (tcp_status*)status_B;
		return ip_port_group_issame(tcp_A->ip_port, tcp_B->ip_port);
	}
	else if (type == 1) {//udp
		udp_status *udp_A = (udp_status*)status_A;
		udp_status *udp_B = (udp_status*)status_B;
		return ip_port_group_issame(udp_A->ip_port, udp_B->ip_port);
	}
	else if (type == 2) {//icmp
		icmp_status *icmp_A = (icmp_status*)status_A;
		icmp_status *icmp_B = (icmp_status*)status_B;
		return ip_port_group_issame(icmp_A->ip, icmp_B->ip);
	}
	else {//syntax error
		printf("Wrong compare !");
		return 0;
	}
}

int TCP_check_state(tcp_status *connection, tcp_status* A, uint8_t flags, int inv)
{
	int FIN = flags&1;
	int SYN = flags&(1 << 1);
	int RST = flags&(1 << 2);
	int PSH = flags&(1 << 3);
	int ACK = flags&(1 << 4);
	int URG = flags&(1 << 5);

	if (connection == NULL) { //if this is a new connection
		if (RST || FIN || ACK || PSH || !SYN)
			return 0;

		A->last_state = 0;//initialize the new state
		A->fin_A = 0;
		A->fin_B = 0;
	}
	else if (inv == 0) {//if inv == 0 , it means that  
		//This is a A -> B connection
		if (connection->last_state == 0) {//send SYN
			if (SYN&&ACK)
				return 0;
			else if (SYN)
				A->last_state = 0; //resend SYN
			else if (ACK && !FIN)
				return 0;
			else if (FIN)
				return 0;
			else if (RST)
				A->last_state = 4;//close the connection
		}
		else if (connection->last_state == 1) {//received SYNACK
			if (SYN&&ACK)
				return 0;
			else if (SYN)
				return 0;
			else if (ACK && !FIN)
				A->last_state = 2;//send final 3-way handshake ACK
			else if (FIN)
				return 0;
			else if (RST)
				A->last_state = 4;//close the connection
		}
		else if (connection->last_state == 2) {//send ACK
			if (SYN && ACK) {
				return 0;
			}
			else if (SYN) {
				return 0;
			}
			else if (ACK && !FIN) {
				A->last_state = 2;	// Send data ACK.
			}
			else if (FIN) {
				A->last_state = 3; // Start FIN
				A->fin_A = 1;
				A->fin_B = 0;
			}
			else if (RST) {
				A->last_state = 4; // Close Connection
			}
		}
		else if (connection->last_state == 3) {//FIN seen
			if (A->fin_A) { // Issued by A
				if (SYN && ACK) {
					return 0;
				}
				else if (SYN) {
					return 0;
				}
				else if (ACK && !FIN) {
					A->last_state = 2;	// Send ACK for B data.
				}
				else if (FIN) {
					A->last_state = 3; // Resend FIN
				}
				else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
			else {
				if (SYN && ACK) {
					return 0;
				}
				else if (SYN) {
					return 0;
				}
				else if (ACK && !FIN) {
					A->last_state = 2;	// Send Data
				}
				else if (FIN) {
					A->last_state = 4; // Send FIN and close
				}
				else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
		}
		else if (connection->last_state == 4) {
			if (SYN && ACK) {
				return 0;
			}
			else if (SYN) {
				A->last_state = 0;   // Start new connection
				A->fin_A = 0;
				A->fin_B = 0;
			}
			else if (ACK && !FIN) {
				return 0;
			}
			else if (FIN) {
				return 0;
			}
			else if (RST) {
				return 0;
			}
		}
		else {
			printf("Wrong connection state of connection ! Error situtaion : function:TCP_check_state\n");
		}
	}
	else {//else it means that
		// B -> A packet
		if (connection->last_state == 0) { 				// Received SYN 
			if (SYN && ACK) {
				A->last_state = 1; // Send SYNACK
			}
			else if (SYN) {
				return 0;
			}
			else if (ACK && !FIN) {
				return 0;
			}
			else if (FIN) {
				return 0;
			}
			else if (RST) {
				A->last_state = 4;	// Close connection
			}
		}
		else if (connection->last_state == 1) { // Sent SYNACK
			if (SYN && ACK) {
				A->last_state = 1; // Resend SYNACK
			}
			else if (SYN) {
				return 0;
			}
			else if (ACK && !FIN) {
				return 0;
			}
			else if (FIN) {
				return 0;
			}
			else if (RST) {
				A->last_state = 4; // Close Connection
			}
		}
		else if (connection->last_state == 2) { // Received ACK
			if (SYN && ACK) {
				return 0;
			}
			else if (SYN) {
				return 0;
			}
			else if (ACK && !FIN) {
				A->last_state = 2;	// Send data ACK.
			}
			else if (FIN) {
				A->last_state = 3; // Start FIN
				A->fin_A = 0;
				A->fin_B = 1;
			}
			else if (RST) {
				A->last_state = 4; // Close Connection
			}
		}
		else if (connection->last_state == 3) { // FIN seen.
			if (A->fin_B) { // Issued by B
				if (SYN && ACK) {
					return 0;
				}
				else if (SYN) {
					return 0;
				}
				else if (ACK && !FIN) {
					A->last_state = 2;	// Send ACK for A data.
				}
				else if (FIN) {
					A->last_state = 3; // Resend FIN
				}
				else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
			else {
				if (SYN && ACK) {
					return 0;
				}
				else if (SYN) {
					return 0;
				}
				else if (ACK && !FIN) {
					A->last_state = 2;	// Send Data
				}
				else if (FIN) {
					A->last_state = 4; // Send FIN and close
				}
				else if (RST) {
					A->last_state = 4; // Close Connection
				}
			}
		}
		else if (connection->last_state == 4) { // Closed connection.
			if (SYN && ACK) {
				return 0;
			}
			else if (SYN) {
				return 0;       // B can't restart connection.
			}
			else if (ACK && !FIN) {
				return 0;
			}
			else if (FIN) {
				return 0;
			}
			else if (RST) {
				return 0;
			}
		}
	}

#ifdef DEBUGGING

#endif // DEBUGGING

}

void state_table_insert(hash_node *hash_table, void* stats_A, int serv_number)
{
	int hash = state_hash(stats_A, serv_number);
	hash_ele* new_node = (hash_ele*)malloc(sizeof(hash_ele));
	if (new_node == NULL) {
		printf("Can not get the memery of the hash node , Error function : state_table_insert");
		return;
	}

	if (serv_number == 0) {//TCP
		tcp_status *tcp_A = (tcp_status*)stats_A;
		tcp_status *new_tcp = (tcp_status*)malloc(sizeof(tcp_status));
		
		new_tcp->ip_port = tcp_A->ip_port;
		new_tcp->last_state = tcp_A->last_state;
		new_tcp->event_time = tcp_A->event_time;
		new_tcp->fin_A = tcp_A->fin_A;
		new_tcp->fin_B = tcp_A->fin_B;
		new_node->stats = new_tcp;
	}
	else if (serv_number == 1) {//UDP
		udp_status *udp_A = (udp_status*)stats_A;
		udp_status *new_udp = (udp_status*)malloc(sizeof(udp_status));

		new_udp->ip_port = udp_A->ip_port;
		new_udp->event_time = udp_A->event_time;
		new_node->stats = new_udp;
	}
	else if (service_number == 2) {//ICMP
		icmp_status *icmp_A = (icmp_status*)stats_A;
		icmp_status *new_icmp = (icmp_status*)malloc(sizeof(icmp_status));
		
		new_icmp->ip = icmp_A->ip;
		new_icmp->event_time = icmp_A->event_time;
		new_node->stats = new_icmp;
	}

	new_node->next = hash_table[hash].head;
	hash_table[hash].head = new_node;
	hash_table[hash].length++;
	return;
}


void state_table_update(void* table_entry, void* stats_A, int serv_number)
{
	if (serv_number == 0) {//tcp
		tcp_status* tcp_A = (tcp_status *)stats_A;
		tcp_status* pointer = (tcp_status *)table_entry;
		
		pointer->fin_A = tcp_A->fin_A;
		pointer->fin_B = tcp_A->fin_B;
		pointer->ip_port = tcp_A->ip_port;
		pointer->last_state = tcp_A->last_state;
		pointer->event_time = tcp_A->event_time;
	}
	else if (serv_number==1) {//udp
		udp_status* udp_A = (udp_status *)stats_A;
		udp_status* pointer = (udp_status *)table_entry;
		pointer->event_time = udp_A->event_time;
	}
	else if (serv_number == 2) {//icmp
		icmp_status* icmp_A = (icmp_A *)stats_A;
		icmp_status* pointer = (icmp_A *)table_entry;
		pointer->event_time = icmp_A->event_time;
	}
}
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

bool address_equals_ip(const uint8_t *source, const uint8_t *check)
{
	for (int i = 0; i < IP_SIZE; i++)
		if (source[i] != check[i])
			return false;

	return true;
}

int ip_port_group_issame(ip_port_group A, ip_port_group B)
{
	if (A.destination_port == B.destination_port&&A.destination_ip == B.destination_ip&&A.source_ip == B.source_ip&&A.source_port == B.source_port)
		return 1;
	return 0;
}

int address_equal_ip(const uint8_t *a, const uint8_t *b)
{
	for (int i = 0; i < IP_SIZE; i++)
		if (a[i] != b[i])
			return 0;

	return 1;
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
