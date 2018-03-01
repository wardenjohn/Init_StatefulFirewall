# Init_StatefulFirewall
#Introduction of Stateful Firewall

#Forhead knowledge
TCP: TCP is make up of some prarameter in #--4
UDP: UDP header is make up of 4 area (source port / destination port / the length of the data / checksum)
ICMP:


#---1
pcap_pkthdr--is a structor having 3 elements ( struct timeval ts ,bpf_u_int32 caplen , bpf_u_int32 len) 
ts have tow part ,the first part of ts is the second from 1900 , and the other part is the container part from now
caplen is the length of the data it catched
len is the ture length of the packet

#---2
 pcap_next_ex(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data)
 function:get a packet from interface or a offline record
 p:a tar of a packet which had catched 
 pkt_header : the head of the package
 pkt_data : the contain of the package
 return : 1:seccess 0:time out -1:failed -2:get the last package of the offline record
It will tempory get use of about 500KB space of memory.

#--3
ntohs()
this function's header #include <netinet/in.h>
uint16_t ntohs(uint16_t netshort)
this function is to covert the 16 byte from web into master engine
uint16_t netshort is a 16 byte number express by the web order 
See also ntohl / htonl / htons

#--4
Introduction of structor
EP1: 
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

You can serch on the internet about the TCP.This structor is a TCP Header type. 
Here are some information I picked from Baidu.com in Chinese:

TCP的首部格式图右图所示：
---Source Port是源端口，16位。
TCP首部
TCP首部
---Destination Port是目的端口，16位。
---Sequence Number是发送数据包中的第一个字节的序列号，32位。
---Acknowledgment Number是确认序列号，32位。
---Data Offset是数据偏移，4位，该字段的值是TCP首部（包括选项）长度除以4。[1] 
---标志位： 6位，URG表示Urgent Pointer字段有意义：
ACK表示Acknowledgment Number字段有意义
PSH表示Push功能，RST表示复位TCP连接
SYN表示SYN报文（在建立TCP连接的时候使用）
FIN表示没有数据需要发送了（在关闭TCP连接的时候使用）
Window表示接收缓冲区的空闲空间，16位，用来告诉TCP连接对端自己能够接收的最大数据长度。
---Checksum是校验和，16位。
---Urgent Pointers是紧急指针，16位，只有URG标志位被设置时该字段才有意义，表示紧急数据相对序列号（Sequence Number字段的值）的偏移。

