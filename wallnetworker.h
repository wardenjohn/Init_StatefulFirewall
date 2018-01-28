/***********This is the funtion body definder file***********/
//#include "walldefinder.h"
// void list_dev()
// {
// 	pcap_if_t *alldevs;
// 	char errbuf[ERRBUF_SIZE];	

// 	int pcap_flag ;

// 	pcap_flag = pcap_findalldevs(&alldevs , errbuf);

// 	if(pcap_flag == -1){
// 		char err[]="finding devs get wrong and error message as follow";
// 		printf("%s\n", err);
// 		printf("%s\n", errbuf);
// 	}
// 	else{
// 		pcap_if_t *dev;
// 		int count=0;
// 		for(dev = alldevs ;dev != NULL;dev = dev->next){
// 			printf("device name : %s\n", dev->name);
// 			count++;
// 		}
// 		printf("total devices in count is : %d\n",count);
// 	}
// }