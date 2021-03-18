
#include "config.hpp"
#include "network.hpp"
#include "synchronized.hpp"

int main()
{
	utttil::synchronized<ournode::config> conf;
	conf->load("ournode.conf");

	ournode::network net(conf);
	std::thread network_thread([&]() { net.run(); });

	network_thread.join();

	conf->save();
}