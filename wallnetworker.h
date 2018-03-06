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

extern rules_list rules_table;//the rules table to store the rules
extern hash_node state_table[TABLE_LINE][TABLE_SIZE];
extern uint16_t port_map[MAP_SIZE][MAP_SIZE][PORT_RANGE];

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

/************ Package function ***********/
arp_stor* copy_arp_head(arp_stor* arp_header);

void compute_ip_checksum(ip_stor *ip);//����ipУ���

void compute_tcp_checksum(psedo_tcp_stor *tcp);

void compute_udp_checksum(psedo_udp_stor* pseudo_udp);

void packet_inject(pcap_t *p, const void *packet, size_t len, char* dir);
/******** Functions for the rules list ******/
int service_map(char s[]);

void insert_rules(rules_ele *rule);

int address_equal_ip(const uint8_t *a, const uint8_t *b);

int check_rule(int dir, int service, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port);
/*********** State table Functions **********/

void* state_table_find(hash_node *hash_table, void* status_A, int server_number);

void state_table_update(void* table_entry, void* stats_A, int serv_number);

void state_table_insert(hash_node* hash_table, void* stats_A, int serv_number);

int out_dated_entry(void* stats_A, void* stats_B, int serv_number);

int match_status(void* status_A,void* status_B,int type);

int TCP_check_state(tcp_status *connection ,tcp_status* A,uint8_t flags,int inv);
/*********** Hash Functions **************/

int hash_ip_port(ip_port_group ip_port);

int hash_ip(ip_group ip);

int state_hash(void* state_A,int server_number);

/************ Helping Function *************/
bool is_match(char *to_match, char *source);

void str_to_ip(char *buf, uint8_t *ip);

void print_ethernet(ethernet_stor *enthernet_head, char *dir);

bool address_equals_ip(const uint8_t *source, const uint8_t *check);

int convert_to_mac(char *readbuff, char *mac_dest);

int convert_to_ip(char *buff,char *ip_dest);

uint32_t unpack_4byte(const uint8_t *buf);//unpack the web package

uint16_t unpack_2byte(const uint8_t *buf);//���

uint16_t pack_2byte(const uint8_t *buf);//���

uint32_t pack_4byte(const uint8_t *buf);

int ip_port_group_issame(ip_port_group A, ip_port_group B);

int ip_group_issame(ip_group A,ip_group B);
