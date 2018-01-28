/*******This is the menu of the selection of the firewall *****************/

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


// void print_title_c()
// {

// }
