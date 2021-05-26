
//#include <csignal>
//#include <iostream>

#include "synchronized.hpp"

#include "config.hpp"
#include "network.hpp"
#include "blockchain.hpp"
#include "block_serialization.hpp"
#include "block_verifier.hpp"

ournode::network                                                                         *g_net      = nullptr;
ournode::block_verifier<ournode::file_block_persistence, ournode::memory_tx_persistence> *g_verifier = nullptr;

void ctrlc_handler(int sig)
{
	utttil::must_have() << "Shutting down" << std::endl;
	g_net->stop_signal();
	g_verifier->stop_signal();
}

template<typename BlockPersistence, typename TxPersistence>
void check_integrity(utttil::synchronized<ournode::blockchain<BlockPersistence, TxPersistence>, boost::fibers::mutex, boost::fibers::condition_variable> & bc)
{
	utttil::info() << "Checking integrity of blocks in persistent memory." << std::endl;
	utttil::info() << "This will take a while." << std::endl;

	std::cout << "hash 0: " << bc->root_chain.persistence.get_hash(0) << std::endl;
	std::cout << "last known hash: " << bc->get_last_known_block_hash() << std::endl;

	Hash256 previous_hash;
	previous_hash.zero();
	int i;
	auto bcp = bc.lock();
	size_t total_blocks_size = 0;
	size_t total_utxos_size = 0;
	bcp->get_blocks_raw_data([&](typename BlockPersistence::persistent_index_block & pib, std::string & block_data) -> bool
		{
			total_blocks_size += block_data.size();

			ournode::block b;
			Hash256 calculated_hash;
			if ( ! ournode::block_verifier<BlockPersistence, TxPersistence>::verify(block_data, b, calculated_hash))
				return false;
			if (pib.hash != calculated_hash)
			{
				utttil::error() << "Block " << i << "'s calculated hash doens't match the index:" << std::endl;
				utttil::error() << "Block's hash " << calculated_hash << std::endl;
				utttil::error() << "index's hash " << pib.hash << std::endl;
				return false;
			}
			if (b.prev_block_hash != previous_hash)
			{
				utttil::error() << "Block " << i << " out of order " << calculated_hash << std::endl;
				utttil::error() << "Block's previous hash " << b.prev_block_hash << std::endl;
				utttil::error() << "File's previous hash " << previous_hash << std::endl;
				return false;
			}
			previous_hash = calculated_hash;
			if ((i&0xFFF) == 0) {
				utttil::info() << "Block " << i << " checked" << std::endl;
				utttil::info() << "block size: " << total_blocks_size << ", output_sie: " << total_utxos_size << std::endl;
			}

			for (const auto & tx : b.txs)
				for (const auto & out : tx.outputs)
					total_utxos_size += out.bytes_size();
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
		
		utttil::synchronized<ournode::blockchain<ournode::file_block_persistence, ournode::memory_tx_persistence>
		                    ,boost::fibers::mutex
		                    ,boost::fibers::condition_variable> bc("./testnet");
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