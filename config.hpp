
#pragma once

#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <string>
#include <iostream>

namespace ournode {

struct peer_config
{
	enum Quality
	{
		Good = 0,
		Unknown = 1,
		Unresponsive = 2,
		Rejected = 3,
	};

	std::string ip = "";
	int port = 0;

	operator bool() const  { return ip.empty() || port==0; }
};

bool operator<(const peer_config & left, const peer_config & right)
{
	return left.ip < right.ip || (left.ip == right.ip && left.port < right.port);
}
bool operator==(const peer_config & left, const peer_config & right)
{
	return left.ip == right.ip && left.port == right.port;
}

template<typename O>
O & operator<<(O & out, const peer_config & p)
{
	return out << p.ip << " " << p.port;
}

template<typename O>
O & operator<<(O & out, const peer_config::Quality & q)
{
	return out << [](const peer_config::Quality & q)
		{
			switch (q)
			{
				case peer_config::Quality::Good        : return "good";
				case peer_config::Quality::Unknown     : return "unknown";
				case peer_config::Quality::Unresponsive: return "unresponsive";
				case peer_config::Quality::Rejected    : return "rejected";
			}
		}(q);
}

struct config
{
	std::map<peer_config,peer_config::Quality> peers;
	size_t parallel_connections_max = 100;
	size_t parallel_connections_ratio = 10;
	size_t min_peer_count = 10;
	std::string filename;

	void load(std::string filename_)
	{
		filename = std::move(filename_);

		std::ifstream infile(filename);
		if (infile)
		{
			std::string line;
			while (std::getline(infile, line))
			{
				std::istringstream iss(line);
				std::string type;
				iss >> type;
				if (type == "peer")
				{
					std::string quality;
					std::string ip;
					int port;
					iss >> quality >> ip >> port;

					peer_config::Quality q = [&quality]()
						{
							if (quality == "good")
								return peer_config::Quality::Good;
							else if (quality == "unresponsive")
								return peer_config::Quality::Unresponsive;
							else if (quality == "rejected")
								return peer_config::Quality::Rejected;
							else
								return peer_config::Quality::Unknown;
							
						}();
					peers[{ip, port}] = q;
				}
				else if (type == "parallel_connections_max")
				{
					iss >> parallel_connections_max;
				}
				else if (type == "parallel_connections_ratio")
				{
					iss >> parallel_connections_ratio;
				}
				else if (type == "min_peer_count")
				{
					iss >> min_peer_count;
				}
			}
		}
		if (peers.empty())
			peers[{"127.0.0.1",18333}] = peer_config::Quality::Unknown;
	}

	void save()
	{
		if (filename.empty())
			return;
		std::ofstream outfile(filename);
		outfile << "min_peer_count "             << min_peer_count             << std::endl;
		outfile << "parallel_connections_max "   << parallel_connections_max   << std::endl;
		outfile << "parallel_connections_ratio " << parallel_connections_ratio << std::endl;
		for (const auto & p : peers)
			outfile << "peer " << p.second << " " << p.first << std::endl;
	}

	void insert_peer(const std::string & ip, int port)
	{
		peer_config pc{ip,port};
		auto it = peers.find(pc);
		if (it == peers.end())
			peers.insert(std::make_pair(pc, peer_config::Quality::Unknown));
	}
	void erase_peer(const peer_config & p)
	{
		peers.erase(p);
	}

	void set_peer_quality(const peer_config & p, const peer_config::Quality & q)
	{
		peers[p] = q;
	}

	peer_config::Quality get_quality(const peer_config & p)
	{
		return peers.insert(std::make_pair(p,peer_config::Unknown)).first->second;
	}
};

} // namespace