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
//this is a structor of the ethernet