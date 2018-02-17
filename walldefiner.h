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

