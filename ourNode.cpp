
//#include <csignal>
//#include <iostream>

#include "config.hpp"
#include "network.hpp"
#include "blockchain.hpp"
#include "synchronized.hpp"

//ournode::network *g_net = nullptr;
//
//void ctrlc_handler(int sig)
//{
//	std::cout << "Shutting down" << std::endl;
//	g_net->stop();
//}

int main()
{
	utttil::synchronized<ournode::config, boost::fibers::mutex, boost::fibers::condition_variable> conf;
	conf->load("ournode.conf");
	
	utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> bc;
	// bc.load("./"); // select different folders for testnet3/mainnet

	ournode::network net(conf, bc);
	std::thread network_thread([&]() { net.run(); });

	// ctrlc handling
	//g_net = &net;
	//struct sigaction sigIntHandler;
	//sigIntHandler.sa_handler = ctrlc_handler;
	//sigemptyset(&sigIntHandler.sa_mask);
	//sigIntHandler.sa_flags = 0;
	//sigaction(SIGINT, &sigIntHandler, NULL);

	// shutdown
	network_thread.join();
	conf->save();
	std::cout << "Stopped gracefully" << std::endl;
	return 0;
}