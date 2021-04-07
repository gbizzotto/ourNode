
//#include <csignal>
//#include <iostream>

#include "synchronized.hpp"

#include "config.hpp"
#include "network.hpp"
#include "blockchain.hpp"
#include "block_verifier.hpp"

//ournode::network *g_net = nullptr;
//
//void ctrlc_handler(int sig)
//{
//	std::cout << "Shutting down" << std::endl;
//	g_net->stop();
//}

void check_integrity(utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc)
{
	Hash256 previous_hash;
	previous_hash.zero();
	int i;
	bc->get_raw_block_headers([&](std::string_view sv) -> bool
		{
			ournode::block b;
			Hash256 hash;
			std::tie(b,hash) = ournode::consume_header(sv, false);
			if (b.prev_block_hash != previous_hash)
			{
				std::cout << "Block " << i << " out of order " << hash << std::endl;
				std::cout << "Block's previous hash " << b.prev_block_hash << std::endl;
				std::cout << "File's previous hash " << previous_hash << std::endl;
				return false;
			}
			previous_hash = hash;
			i++;
			return true;
		});
	std::cout << "blockchain integrity checked" << std::endl;
}

int main()
{
	utttil::synchronized<ournode::config, boost::fibers::mutex, boost::fibers::condition_variable> conf;
	conf->load("ournode.conf");
	
	utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> bc;
	bc->load("./testnet"); // select different folders for testnet3/mainnet
	check_integrity(bc);

	ournode::block_verifier verifier(bc);
	verifier.start();

	ournode::network net(conf, bc, verifier);
	net.start();

	// ctrlc handling
	//g_net = &net;
	//struct sigaction sigIntHandler;
	//sigIntHandler.sa_handler = ctrlc_handler;
	//sigemptyset(&sigIntHandler.sa_mask);
	//sigIntHandler.sa_flags = 0;
	//sigaction(SIGINT, &sigIntHandler, NULL);

	// shutdown
	net.join();
	verifier.join();
	conf->save();
	std::cout << "Stopped gracefully" << std::endl;
	return 0;
}