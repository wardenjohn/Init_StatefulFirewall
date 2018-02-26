/***********This is the function and structor of network definder file***********/
#define MAC_NUM 6
#define BIN_NUM 4
#define HIGH_PORT 50000
#define TABLE_SIZE 8192
#define TABLE_LINE 3
#define MAP_SIZE 2
#define PORT_RANGE 8192
//define of the rules and kind
#define TCP 0
#define UDP 1
#define ICMP 2
#define ANY 3
#define IN 0
#define OUT 1
#define ALLOW 2
#define BLOCK 3
#define MAC_SIZE 6
#define IP_SIZE 4

extern int ONLINE;

extern int TCP_PORT;
extern int UDP_PORT;

rules_list rules_table;//the rules table to store the rules
hash_node state_table[TABLE_LINE][TABLE_SIZE];
uint16_t port_map[MAP_SIZE][MAP_SIZE][PORT_RANGE];

typedef struct FireWall {
	uint8_t virtual_mac_address[MAC_NUM];
	uint8_t firewall_mac_address[MAC_NUM];
	uint8_t switch_mac_address[MAC_NUM];
	uint8_t route_mac_address[MAC_NUM];

	char *virtual_ip_buf;
	char *firewall_ip_buf;
	char *switch_ip_buf;

	uint8_t virtual_ip_bin[BIN_NUM];
	uint8_t firewall_ip_bin[BIN_NUM];
	uint8_t switch_ip_bin[BIN_NUM];

	char *devName_in;//entrance of the name of the device
	char *devName_out;//out of the device name

	pcap_t *pcap_in;
	pcap_t *pcap_out;

	int data_timeout_in;
	int data_timeout_out;
}firewall;

/******** Functions for the rules list ******/
int service_map(char s[]);

uint32_t unpack_4byte(const uint8_t *buf);//unpack the wen package

uint16_t unpack_2byte(const uint8_t *buf);

void insert_rules(rules_ele *rule);
/************ Helping Function *************/
bool is_match(char *to_match, char *source);

void str_to_ip(char *buf, uint8_t *ip);

void print_ethernet(ethernet_stor *enthernet_head, char *dir);

bool address_equals_ip(const uint8_t *source, const uint8_t *check);