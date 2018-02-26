/*This is the definder of the header file,in which will provide the define of the structor*/
/*************************************Header File******************************************/
#define ERRBUF_SIZE 100

typedef struct ethernet_stor
{
	uint8_t destnation_mac[6]; //the mac address of the destination
	uint8_t source_mac[6];
	uint8_t ethernet_type[2];
	uint8_t data;
}ethernet_stor;

typedef struct ip_stor
{
	uint8_t version;
	uint8_t description;
	uint8_t total_length[2];
	uint8_t identification[2];
	uint8_t flag_frag_offset[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t checksum[2];
	uint8_t source_ip[4];
	uint8_t destnation_ip[4];
	uint8_t options_data;
}ip_stor;

typedef struct tcp_stor
{
	uint8_t source_port[2];
	uint8_t destination_port[2];
	uint8_t seq_number[4];
	uint8_t ack_number[4];
	uint8_t offset_reserve_flag;
	uint8_t flags;
	uint8_t window_size[2];
	uint8_t checksump[2];
	uint8_t urg_pointer[2];
	uint8_t options_data;
}tcp_stor;

//rules list and rules elements in order to creat a rules table to store the rules
typedef struct rules_element
{
	int rules;
	int direction;
	int service;
	uint32_t source_ip,destination_ip;
	uint16_t source_port, destination_port;
	uint8_t source_ip_any, destination_ip_any;
	uint8_t source_port_any, destination_port_any;
	void *next;
}rules_ele;

typedef struct rules_list
{
	int length;
	rules_ele *head;
	rules_ele *tail;
}rules_list;

/****************IP block rules ******************/
typedef struct ip_group
{
	uint32_t source_ip;
	uint32_t destination_ip;
}ip_group;

typedef struct ip_port_group
{
	uint32_t source_ip;
	uint32_t destination_ip;
	uint32_t source_port;
	uint32_t destination_port;
}ip_port_group;

typedef struct ip_status
{
	ip_group ip;
	int service;
}ip_status;

typedef struct tcp_status
{
	ip_port_group ip_port;
	int last_state;
	int fin_A, fin_B; //The object sent FIN(A->B)
	struct timeval event_time;
	//To record the time of this event happend

}tcp_status;

///////////////////////////////////////////////////
//hash node definder
typedef struct hash_element
{
	void *stats;
	void *next;
	//this void * means that it is a pointer pointing at any kind of functions
}hash_ele;

typedef struct hash_node
{
	int length;
	hash_ele *head;
}hash_node;

