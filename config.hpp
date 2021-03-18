
#pragma once

#include <set>
#include <string>
#include <fstream>
#include <sstream>
#include <string>

namespace ournode {

struct config
{
	struct peer
	{
		std::string ip;
		int port;
		std::string version;
	};

	std::set<peer> known_peers;
	std::set<peer> rejected_peers;
	int parallel_connection_ratio = 10;
	int min_peer_count = 10;
	std::string filename;

	config()
	{
		add_known_peer_address("127.0.0.1", 18333);
		add_known_peer_address("54.36.62.47", 9333);
	}

	void load(std::string filename_)
	{
		filename = std::move(filename_);

		std::ifstream infile(filename);
		if (infile)
			known_peers.clear();
		std::string line;
		while (std::getline(infile, line))
		{
			std::istringstream iss(line);
			std::string type;
			iss >> type;
			if (type == "known_peer")
			{
				std::string ip;
				int port;
				iss >> ip >> port;
				known_peers.insert({ip, port, ""});
			}
			else if (type == "rejected_peer")
			{
				std::string ip;
				int port;
				iss >> ip;
				rejected_peers.insert({ip, 0, ""});
			}
			else if (type == "parallel_connection_ratio")
			{
				iss >> parallel_connection_ratio;
			}
			else if (type == "min_peer_count")
			{
				iss >> min_peer_count;
			}
		}
	}

	void save()
	{
		if (filename.empty())
			return;
		std::ofstream outfile(filename);
		outfile << "min_peer_count "            << min_peer_count            << std::endl;
		outfile << "parallel_connection_ratio " << parallel_connection_ratio << std::endl;
		for (const peer & p : known_peers)
			outfile << "known_peer " << p.ip << " " << p.port << std::endl;
		for (const peer & p : rejected_peers)
			outfile << "rejected_peer " << p.ip << std::endl;
	}

	void add_known_peer_address(const std::string & ip, int port)
	{
		auto ip_match = [ip](const peer & p){ return p.ip==ip; };
		auto is_known      = std::find_if(     known_peers.begin(),      known_peers.end(), ip_match) !=      known_peers.end();
		auto is_rejected   = std::find_if(  rejected_peers.begin(),   rejected_peers.end(), ip_match) !=   rejected_peers.end();
		if (!is_known && !is_rejected)
			known_peers.insert({ip, port, ""});
	}

	void reject_peer(std::string ip)
	{
		auto ip_match = [ip](const peer & p){ return p.ip==ip; };
		auto peer_it = std::find_if(known_peers.begin(), known_peers.end(), ip_match);
		if (peer_it != known_peers.end())
		{
			rejected_peers.insert(*peer_it);
			known_peers.erase(peer_it);
		}
	}
};

bool operator<(const config::peer & left, const config::peer & right)
{
	return left.ip < right.ip || left.port < right.port;
}


} // namespace