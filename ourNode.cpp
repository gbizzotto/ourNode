
//#include <csignal>
//#include <iostream>

#include "synchronized.hpp"

//#include "trace.hpp"
#include "config.hpp"
#include "network.hpp"
#include "blockchain.hpp"
#include "block_verifier.hpp"

ournode::network        *g_net      = nullptr;
ournode::block_verifier *g_verifier = nullptr;

void ctrlc_handler(int sig)
{
	utttil::must_have() << "Shutting down" << std::endl;
	g_net->stop_signal();
	g_verifier->stop_signal();
}

void check_integrity(utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc)
{
	utttil::info() << "Checking integrity of blocks in persistent memory." << std::endl;
	utttil::info() << "This will take a while." << std::endl;

	Hash256 previous_hash;
	previous_hash.zero();
	int i;
	bc->get_block_handles_preload_data([&](ournode::block_handle & bh) -> bool
		{
			Hash256 expected_hash = bh.hash;
			ournode::block b;
			if ( ! ournode::block_verifier::verify_candidade(bh, b))
				return false;
			if (expected_hash != bh.hash)
			{
				utttil::error() << "Block " << i << "'s calculated hash doens't match the index" << bh.hash << std::endl;
				utttil::error() << "Block's hash " << bh.hash << std::endl;
				utttil::error() << "index's hash " << expected_hash << std::endl;
				return false;
			}
			if (b.prev_block_hash != previous_hash)
			{
				utttil::error() << "Block " << i << " out of order " << bh.hash << std::endl;
				utttil::error() << "Block's previous hash " << b.prev_block_hash << std::endl;
				utttil::error() << "File's previous hash " << previous_hash << std::endl;
				return false;
			}
			previous_hash = bh.hash;
			if ((i&0xFFF) == 0)
				utttil::info() << "Block " << i << " checked" << std::endl;
			i++;
			return true;
		});
	utttil::info() << "blockchain integrity checked" << std::endl;
}

int main()
{
	utttil::default_logger(std::cout);

	utttil::fiber_local_logger("main_thread");
	utttil::must_have() << "Startup" << std::endl;

	TRACE

	try {
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
		g_net = &net;
		g_verifier = &verifier;
		struct sigaction sigIntHandler;
		sigIntHandler.sa_handler = ctrlc_handler;
		sigemptyset(&sigIntHandler.sa_mask);
		sigIntHandler.sa_flags = 0;
		sigaction(SIGINT, &sigIntHandler, NULL);

		// shutdown
		verifier.join();
		net.join();
		conf->save();
		utttil::must_have() << "Stopped gracefully" << std::endl;
	} catch(...) {
		PRINT_TRACE
	}
	return 0;
}