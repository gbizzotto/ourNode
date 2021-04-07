
#pragma once

#include <deque>
#include <thread>
#include <chrono>
#include "log.hpp"
#include "synchronized.hpp"
#include "blockchain.hpp"
#include "block_parsing.hpp"

namespace ournode
{

struct block_verifier
{
	utttil::synchronized<std::deque<block_handle>> candidates;
	utttil::synchronized<std::deque<block_handle>> rejects;

	utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc;
	utttil::LogWithPrefix log;

	bool go_on = true;
	std::thread t;

	block_verifier(utttil::synchronized<ournode::blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc_)
		: bc(bc_)
		, log("verifier")
	{}
	~block_verifier()
	{
		stop();
	}
	void join()
	{
		t.join();
	}
	void stop()
	{
		go_on = false;
		join();
	}
	void start()
	{
		t = std::thread([&](){ this->run(); });
	}
	void run()
	{
		log << utttil::LogLevel::INFO << "run" << std::endl;
		for (;go_on;std::this_thread::sleep_for(std::chrono::milliseconds(1)))
			while(go_on)
			{
				block_handle handle;
				{
					auto candidates_proxy = candidates.wait_for_notification([](std::deque<block_handle> & candidates){ return ! candidates.empty(); });
					handle = std::move(candidates_proxy->front());
					candidates_proxy->pop_front();
				}
				if ( ! verify_candidade(handle))
					rejects->emplace_back(std::move(handle));
			}
	}

	void add_candidate(std::string_view block_data, const Hash256 & hash)
	{
		block_handle result;
		result.hash = hash;
		result.block_data = block_data;
		result.file_number = 0;
		result.offset      = 0;
		candidates->push_back(std::move(result));
		candidates.notify_one();
	}

	bool verify_candidade(block_handle & handle)
	{
		std::string_view data(handle.block_data.data(), handle.block_data.size());

		try { // parsing might throw
			// std::string block_hash = dbl_sha256({data.data(), 80});
			// std::reverse(block_hash.begin(), block_hash.end());
			// pxln(block_hash.data(), 32);

			block bl;
			Hash256 hash;
			std::tie(bl, hash) = consume_header(data, false);

			auto ntx = consume_var_int(data);
			std::vector<Hash256> txids;
			txids.reserve(ntx);
			for (int i=0 ; i<ntx ; i++)
			{
				const char * tx_begin = data.data();
				bl.txs.push_back(consume_tx(data));
				const char * tx_end = data.data();
				std::string_view tx_sv((char*)tx_begin, std::distance(tx_begin, tx_end));
				//pxln(tx_sv);
				txids.emplace_back();
				fill_dbl_sha256(txids.back(), tx_sv);
				//std::cout << std::hex << txids.back() << std::dec << std::endl;
			}

			Hash256 merkle_root;
			fill_merkle_root(merkle_root, std::move(txids));
			if (bl.merkle_root != merkle_root) {
				log << utttil::LogLevel::INFO
				    << "Invalid merkle root: " << std::endl
				    << "Block      merkle root: " << std::hex << bl.merkle_root << std::dec << std::endl
				    << "Calculated merkle root: " << std::hex <<    merkle_root << std::dec << std::endl;
				return false;
			}

			//std::cout << "ntx: " << ntx << std::endl;
			//if (ntx > 1)
			//	for (int i=0 ; i<ntx ; i++)
			//		std::cout << "tx " << i << std::endl
			//				<< bl.txs[i] << std::endl;

			bc->add(std::string_view(handle.block_data.data(), handle.block_data.size()), hash, bl.prev_block_hash);
			return true;

		} catch (std::exception & e) {
			log << utttil::LogLevel::INFO << "exc: " << e.what() << std::endl;
			return false;
		}
		log << utttil::LogLevel::INFO << "no idea" << std::endl;
		return false;
	}
};

} // namespace
