
#include "config.hpp"
#include "network.hpp"
#include "blockchain.hpp"
#include "synchronized.hpp"

int main()
{
	utttil::synchronized<ournode::config> conf;
	conf->load("ournode.conf");

	utttil::synchronized<ournode::blockchain> bc;
	// bc.load("./"); // select different folder for testnet3/mainnet

	ournode::network net(conf, bc);
	std::thread network_thread([&]() { net.run(); });

	network_thread.join();

	conf->save();
}