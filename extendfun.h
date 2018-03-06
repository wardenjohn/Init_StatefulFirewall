/*******This is the extends function of the selection of the firewall *****************/
#include <vector>
#include <fstream>

int print_title_cpp()
{
	std::cout<<"*****Welcome using stateful firewall!*****"<<std::endl;
	std::cout<<"Please enter the operation number you want:"<<std::endl;
	std::cout<<"1.start to run the stateful firewall"<<std::endl;
	std::cout<<"2.check all the web devices"<<std::endl;
	std::cout<<"3.chech the state of the network connection"<<std::endl;
	std::cout<<"4.recover or stop the network connection"<<std::endl;
	std::cout<<"5.exit the program"<<std::endl;

	int choice;
	std::cin>>choice;
	if(choice == 1 || choice == 2 || choice == 3 || choice == 4 || choice == 5)
		return choice;
	else{
		std::cout<<"Sorry , you enter a wrong input"<<std::endl;
		return 0;
	}
}

/*****************List the network devices**************************/
void list_dev()
{
	pcap_if_t *alldevs;
	char errbuf[ERRBUF_SIZE];	

	int pcap_flag ;

	pcap_flag = pcap_findalldevs(&alldevs , errbuf);

	if(pcap_flag == -1){
		char err[]="finding devs get wrong and error message as follow";
		printf("%s\n", err);
		printf("%s\n", errbuf);
	}
	else{
		pcap_if_t *dev;
		int count=0;
		for(dev = alldevs ;dev != NULL;dev = dev->next){
			printf("device name : %s\n", dev->name);
			count++;
		}
		printf("total devices in count is : %d\n",count);
	}
}

/****************Check network connection ***********************/
void check_connection()
{
	std::cout << "This is a function to check if the network is unblocked"<<std::endl;
	
	std::fstream webfile;
	webfile.open("connection.txt", std::ios::in);

	if (!webfile.is_open()) {
		std::cout << "can not find the connection file " << std::endl;
		std::cout << "To make a new connection file , you can rebuild a file using the name 'connection.txt' and input the ip address of the website to check" << std::endl;
		return;
	}

	std::string ip;
	int commLEN = 1024;
	while (getline(webfile, ip)) {
		char comm[commLEN];
		sprintf(comm,"ping %s",ip.c_str());
		system(comm);

		char goon;
		std::cout << "goon next ip address?(y/n)" << std::endl;
		std::cin >> goon;
		if (goon == 'y' || goon == 'Y') {

		}
		else {
			break;
		}
	}
}

/****************Stop or recover the network*********************/

void recover_network()
{
	std::fstream dev_back;
	dev_back.open("dev_backup.txt");
	
	std::vector<std::string> dev_name;
	std::string namebuf;
	while (getline(dev_back , namebuf)) {
		dev_name.push_back(namebuf);
	}

	//start to turn on the device
	int comm_len = 20;
	char comm[comm_len];
	for (int i = 0; i < dev_name.size(); i++) {
		sprintf(comm, "sudo ifconfig %s up", dev_name[i].c_str());
		system(comm);
	}
}

void stop_network()
{
	pcap_if_t *alldevs;
	std::vector<std::string> dev_name;
	char errbuf[ERRBUF_SIZE];

	std::ofstream dev_backup;
	dev_backup.open("dev_backup.txt");

	int pcap_flag = pcap_findalldevs(&alldevs,errbuf);
	
	if (pcap_flag == -1) {
		printf("finding devs get wrong and error message as follow\n");
		printf("%s\n", errbuf);
	}
	else {
		pcap_if_t *dev;
		for (dev = alldevs; dev != NULL; dev = dev->next) {
			dev_backup << dev->name << "\n";
			dev_name.push_back(dev->name);
		}
	}

	int com_len = 20;
	char comm[com_len];
	for (int i = 0; i < dev_name.size(); i++) {
		sprintf(comm, "sudo ifconfig %s down", dev_name[i].c_str());
		system(comm);
	}
}

void re_st_net()
{
	int choose;
	std::cout<<"WARING : DO NOT TRY TO DELETE THE DEVICE RECORDING FILE ! OR NETWORK RECOVERY IS INAVLIABLE !"<<std::endl;
	std::cout<<"enter 1 to recover the network"<<std::endl;
	std::cout<<"enter 2 to stop the network"<<std::endl;
	std::cout<<"enter 3 to exit the program"<<std::endl;

	std::cin>>choose;

	if(choose == 1){
		recover_network();
	}
	else if(choose == 2){
		stop_network();
	}
	else if(choose == 3){
		std::cout<<"Bye!"<<std::endl;
		exit(0);
	}else{
		printf("Input a wrong command ! Exit the program\n");
		exit(-1);
	}
}

