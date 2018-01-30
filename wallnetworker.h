/***********This is the function and structor of network definder file***********/
#define MAC_NUM 6
#define BIN_NUM 4

extern int ONLINE;

extern int TCP_PORT;
extern int UDP_PORT;


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
}firewall;