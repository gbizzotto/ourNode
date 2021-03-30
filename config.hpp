
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
		std::string ip = "";
		int port = 0;
		std::string version = "";
		operator bool()
		{
			return ip.empty() || port==0;
		}
	};

	std::set<peer> trusted_peers;
	std::set<peer> known_peers;
	std::set<peer> rejected_peers;
	int parallel_connection_ratio = 10;
	int min_peer_count = 10;
	std::string filename;

	config()
	{
		insert_peer("127.0.0.1", 18333);
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
			if (type == "trusted_peer")
			{
				std::string ip;
				int port;
				iss >> ip >> port;
				trusted_peers.insert({ip, port, ""});
			}
			else if (type == "known_peer")
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
				iss >> ip >> port;
				rejected_peers.insert({ip, port, ""});
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
		for (const peer & p : trusted_peers)
			outfile << "trusted_peer " << p.ip << " " << p.port << std::endl;
		for (const peer & p : known_peers)
			outfile << "known_peer " << p.ip << " " << p.port << std::endl;
		for (const peer & p : rejected_peers)
			outfile << "rejected_peer " << p.ip << " " << p.port << std::endl;
	}

	void insert_peer(const std::string & ip, int port)
	{
		auto ip_match = [ip](const peer & p){ return p.ip==ip; };
		auto is_trusted    = std::find_if(   trusted_peers.begin(),    trusted_peers.end(), ip_match) !=    trusted_peers.end();
		auto is_rejected   = std::find_if(  rejected_peers.begin(),   rejected_peers.end(), ip_match) !=   rejected_peers.end();
		if (!is_trusted && !is_rejected)
			known_peers.insert({ip, port, ""});
	}

	void erase_peer(const peer & p)
	{
		trusted_peers .erase(p);
		known_peers   .erase(p);
		rejected_peers.erase(p);
	}
	void trust_peer(const peer & p)
	{
		known_peers.erase(p);
		trusted_peers.insert(p);
	}
	void reject_peer(const peer & p)
	{
		known_peers.erase(p);
		rejected_peers.insert(p);
	}
};

bool operator<(const config::peer & left, const config::peer & right)
{
	return left.ip < right.ip || left.port < right.port;
}
bool operator==(const config::peer & left, const config::peer & right)
{
	return left.ip == right.ip && left.port == right.port;
}


} // namespace