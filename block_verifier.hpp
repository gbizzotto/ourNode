
#pragma once

#include <deque>
#include <thread>
#include <chrono>

#define _GNU_SOURCE
#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>
typedef boost::error_info<struct tag_stacktrace, boost::stacktrace::stacktrace> traced;

#include "log.hpp"
#include "synchronized.hpp"
#include "blockchain.hpp"
#include "block_parsing.hpp"


namespace ournode
{

Hash256 calculate_target(std::uint32_t bits)
{
	Hash256 result;
	result.zero();

	int exp = bits >> 24;
	int shift = 8 * (exp-3);
	std::uint32_t mantissa = bits & 0x00FFFFFF;
	mantissa <<= shift % 8;
	int offset = shift >> 3;

	result.h[offset  ] =  mantissa        & 0xFF;
	result.h[offset+1] = (mantissa >>  8) & 0xFF;
	result.h[offset+2] = (mantissa >> 16) & 0xFF;

	return result;
}

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
	{
		log.add(std::cout);
	}
	~block_verifier()
	{
		if (go_on)
		{
			stop_signal();
			join();
		}
	}
	void join()
	{
		if (t.joinable())
			t.join();
	}
	void stop_signal()
	{
		go_on = false;
		candidates.notify_all();
	}
	void start()
	{
		t = std::thread([&]()
			{
				TRACE
				try {
					run();
				} catch (const std::exception & e) {
					log << utttil::LogLevel::INFO << "peer::run() threw: " << e.what() << std::endl;
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					if (st) {
						std::cerr << *st << '\n';
					}
					PRINT_TRACE
				} catch(...) {
					PRINT_TRACE
				}
			});
	}
	void run()
	{
		TRACE
		try {
			log << utttil::LogLevel::INFO << "run" << std::endl;
			for (;go_on;std::this_thread::sleep_for(std::chrono::milliseconds(1)))
				while(go_on)
				{
					block_handle handle;
					{
						auto candidates_proxy = candidates.wait_for_notification([&](std::deque<block_handle> & candidates){ return ! candidates.empty() || ! go_on; });
						if ( ! go_on)
							return;
						handle = std::move(candidates_proxy->front());
						candidates_proxy->pop_front();
					}
					if ( ! verify_candidade(handle))
						rejects->emplace_back(std::move(handle));
				}
		} catch(...) {
			PRINT_TRACE
		}
	}

	size_t candidates_count() const { return candidates->size(); }
	size_t   rejected_count() const { return    rejects->size(); }
	auto get_rejected_blocks_proxy() { return rejects.lock(); }

	bool verify_merkle_root(const block & bl, std::vector<Hash256> && txids)
	{
		TRACE

		Hash256 merkle_root;
		fill_merkle_root(merkle_root, std::move(txids));
		if (bl.merkle_root != merkle_root)
		{
			//log << utttil::LogLevel::INFO
			//    << "Invalid merkle root: " << std::endl
			//    << "Block      merkle root: " << std::hex << bl.merkle_root << std::dec << std::endl
			//    << "Calculated merkle root: " << std::hex <<    merkle_root << std::dec << std::endl;
			return false;
		}
		return true;
	}

	void add_candidate(std::string_view block_data, const Hash256 & hash)
	{
		TRACE

		block_handle result;
		result.hash = hash;
		result.file_number = 0;
		result.offset      = 0;
		result.block_data  = std::move(block_data);
		candidates->push_back(std::move(result));
		candidates.notify_one();
	}

	bool verify_candidade(block_handle & handle)
	{
		TRACE

		std::string_view data(handle.block_data.data(), handle.block_data.size());

		try { // parsing might throw
			block bl;
			std::tie(bl, handle.hash) = consume_header(data, false);

			// check hash vs target
			if (calculate_target(bl.bits) < handle.hash)
			{
				//log << utttil::LogLevel::INFO
				//    << "Difficulty doens't match: "
				//    << calculate_target(bl.bits) << " < " << handle.hash
				//    << std::endl;
				return false;
			}

			// check merkle root
			auto ntx = consume_var_int(data);
			std::vector<Hash256> txids;
			txids.reserve(ntx);
			for (int i=0 ; i<ntx ; i++)
			{
				const char * tx_begin = data.data();
				bl.txs.push_back(consume_tx(data));
				const char * tx_end = data.data();
				std::string_view tx_sv((char*)tx_begin, std::distance(tx_begin, tx_end));
				txids.emplace_back();
				fill_dbl_sha256(txids.back(), tx_sv);
			}
			if ( ! verify_merkle_root(bl, std::move(txids)))
				return false;

			bc->add(std::string_view(handle.block_data.data(), handle.block_data.size()), handle.hash, bl.prev_block_hash);
			return true;

		} catch (std::exception & e) {
			log << utttil::LogLevel::ERROR << "exc: " << e.what() << std::endl;
			PRINT_TRACE
			return false;
		} catch (...) {
			PRINT_TRACE
			return false;
		}
		log << utttil::LogLevel::ERROR << "no idea" << std::endl;
		return false;
	}
};

} // namespace
