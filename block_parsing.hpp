
#pragma once

#include <cstdlib>
#include <string_view>
#include <boost/asio.hpp>

#include "sha256sum.hpp"
#include "blockchain.hpp"

namespace ournode
{

std::uint32_t calculate_checksum(unsigned char * data, size_t len)
{
	Hash256 hash;
	fill_dbl_sha256(hash, std::string_view((char*)data, len));
	return hash.hash_hash;
}

bool recv_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::mutable_buffer buffer, std::chrono::seconds timeout, const bool & go_on)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());

	boost::asio::async_read(socket, buffer, 
		[promise=std::move(promise)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	for (auto deadline=std::chrono::system_clock::now()+timeout ; go_on && std::chrono::system_clock::now()<deadline ; )
		if (future.wait_for(std::chrono::milliseconds(100)) == boost::fibers::future_status::ready)
			return future.get();
	socket.cancel();
	return false;
}
bool send_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::const_buffer buffer, std::chrono::seconds timeout, const bool & go_on)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());
	
	//pxln({buf.get(), buffer.size()});
	socket.async_send(buffer, [promise=std::move(promise)](const boost::system::error_code & ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	for (auto deadline=std::chrono::system_clock::now()+timeout ; go_on && std::chrono::system_clock::now()<deadline ; )
		if (future.wait_for(std::chrono::milliseconds(100)) == boost::fibers::future_status::ready)
			return future.get();
	return false;
}


struct net_addr
{
	std::uint32_t time;
	std::uint64_t services = 0;
	char addr[16] = {0};
	std::uint16_t port = 0;

	std::string to_string() const
	{
		bool ten_zeroes = std::find_if(&addr[0], &addr[10], [](unsigned char c) { return c!=0; }) >= &addr[10];
		if (ten_zeroes) {
			std::string_view sv((char*)&addr[12], 4);
			return boost::asio::ip::address_v4(consume_big_endian<unsigned int>(sv)).to_string();
		} else {
			std::array<unsigned char, 16> a;
			std::copy(addr, addr+16, a.data());
			return boost::asio::ip::address_v6(a).to_string();
		}
	}
};

net_addr consume_net_addr(std::string_view & sv, bool has_time)
{
	net_addr a;
	if (has_time)
		a.time = consume_little_endian<decltype(a.time)>(sv);
	a.services = consume_little_endian<decltype(a.services)>(sv);
	consume_bytes(sv, a.addr, 16);
	a.port     = consume_big_endian<decltype(a.port    )>(sv);
	return a; // counting of copy elision
}

std::tuple<block,Hash256> consume_header(std::string_view & data, bool consume_ntx)
{
	if (data.size() < 81)
		throw std::invalid_argument("data.size() < 81");

	Hash256 hash;
	fill_dbl_sha256(hash, std::string_view(data.data(), 80));

	block header;	
	header.version = consume_little_endian<std::int32_t>(data);
	consume_bytes(data, (char*)header.prev_block_hash.h, 32);
	consume_bytes(data, (char*)header.merkle_root.h, 32);
	header.timestamp  = consume_little_endian<std::uint32_t>(data);
	header.difficulty = consume_little_endian<std::uint32_t>(data);
	header.nonce =  consume_little_endian<std::uint32_t>(data);
	if (consume_ntx)
		consume_var_int(data);
	return {header, hash};
}


txin consume_vin(std::string_view & data)
{
	txin in;
	memcpy(in.txid.h, data.data(), 32);
	data.remove_prefix(32);
	in.idx = consume_little_endian<std::uint32_t>(data);
	in.script_size = consume_var_int(data);
	in.scriptsig.reset(new unsigned char[in.script_size], std::default_delete<unsigned char[]>());
	memcpy(in.scriptsig.get(), data.data(), in.script_size);
	data.remove_prefix(in.script_size);
	in.sequence = consume_little_endian<uint32_t>(data);
	return in;
}
txout consume_vout(std::string_view & data)
{
	txout out;
	out.amount = consume_little_endian<std::int64_t>(data);
	out.script_size = consume_var_int(data);
	out.scriptpubkey.reset(new unsigned char[out.script_size], std::default_delete<unsigned char[]>());
	memcpy(out.scriptpubkey.get(), data.data(), out.script_size);
	data.remove_prefix(out.script_size);
	return out;
}
void consume_witness(std::string_view & data)
{
	auto witness_count = consume_var_int(data);
	for (decltype(witness_count) i=0 ; i<witness_count ; i++)
	{
		auto witness_size = consume_var_int(data);
		data.remove_prefix(witness_size);
	}
}

transaction consume_tx(std::string_view & data)
{
	transaction tx;

	auto version = consume_little_endian<std::int32_t>(data);

	tx.has_witness = false;
	if (data.data()[0] == 0) {
		//std::cout << "has witness" << std::endl;
		tx.has_witness = true;
		data.remove_prefix(2);
	}
	auto nin = consume_var_int(data);
	for (decltype(nin) i=0 ; i<nin ; i++)
		tx.inputs.emplace_back(consume_vin(data));
	auto nout = consume_var_int(data);
	for (decltype(nout) i=0 ; i<nout ; i++)
		tx.outputs.emplace_back(consume_vout(data));
	if (tx.has_witness)
		consume_witness(data);
	tx.locktime = consume_little_endian<std::uint32_t>(data);

	return tx;
}

} // namespace
