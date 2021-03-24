
#pragma once

#include <cstring>
#include <boost/asio.hpp>
#include <boost/fiber/all.hpp>
#include "round_robin.hpp"
#include "yield.hpp"

#define _GNU_SOURCE
#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>
typedef boost::error_info<struct tag_stacktrace, boost::stacktrace::stacktrace> traced;

#include "synchronized.hpp"
#include "sha256sum.hpp"
#include "blockchain.hpp"

namespace ournode {

#define MSG_BLOCK 2

template<typename T>
T consume_little_endian(std::string_view & data)
{
	if (data.size() < sizeof(T))
		throw std::invalid_argument("not enough data");
	T result = 0;
	for (int i=0 ; i < sizeof(T) ; i++)
		result += (((T)data[i]) & 0xFF) << (i*8);
	data.remove_prefix(sizeof(T));
	return result;
}
template<typename T>
T consume_big_endian(std::string_view & data)
{
	if (data.size() < sizeof(T))
		throw std::invalid_argument("not enough data");
	T result = 0;
	for (int i=0 ; i < sizeof(T) ; i++) {
		result <<= 8;
		result += (((T)data[i]) & 0xFF);
	}
	data.remove_prefix(sizeof(T));
	return result;
}
template<typename T>
void serialize_little_endian(unsigned char * data, T value)
{
	for (int i=0 ; i<sizeof(T) ; i++, value >>= 8)
		*data++ = (value & 0xFF);
}
template<typename T>
void serialize_big_endian(unsigned char * data, T value)
{
	for (int i=sizeof(T)-1 ; i>0 ; i--)
		*data++ = ((value >> (8*i)) & 0xFF);
}
std::uint64_t consume_var_int(std::string_view & data)
{
	if (data.size() < 1)
		throw std::invalid_argument("data.size() < 1");
	unsigned char first = data[0];
	data.remove_prefix(1);
	if (first == 0xFF) {
		auto result = consume_little_endian<std::uint64_t>(data);
		return result;
	} else if (first == 0xFE) {
		auto result = consume_little_endian<std::uint32_t>(data);
		return result;
	} else if (first == 0xFD) {
		auto result = consume_little_endian<std::uint16_t>(data);
		return result;
	} else {
		return first;
	}
}
void consume_bytes(std::string_view & src, char *dst, size_t len)
{
	if (src.size() < len)
		throw std::invalid_argument("data.size() < 1");
	std::copy(src.data(), src.data()+len, dst);
	src.remove_prefix(len);
}

std::uint32_t calculate_checksum(unsigned char * data, size_t len)
{
	Hash256 hash;
	fill_dbl_sha256(hash, std::string_view((char*)data, len));
	return hash.hash_hash;
	//std::string_view sv((char*)hash.h, 4);
	//return consume_little_endian<std::uint32_t>(sv);
}

bool recv_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::mutable_buffer buffer, std::chrono::seconds timeout)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());
	
	boost::asio::async_read(socket, buffer, 
		[promise=std::move(promise)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	if (future.wait_for(timeout) != boost::fibers::future_status::ready) {
		socket.cancel();
		return false;
	}
	return future.get();
}
bool send_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::const_buffer buffer, std::chrono::seconds timeout)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());
	
	//pxln({buf.get(), buffer.size()});
	socket.async_send(buffer, [promise=std::move(promise)](const boost::system::error_code & ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	if (future.wait_for(timeout) != boost::fibers::future_status::ready) {
		socket.cancel();
		return false;
	}
	return future.get();
}

std::string consume_var_str(std::string_view & sv)
{
	size_t size = consume_var_int(sv);
	std::string result(size, 0);
	consume_bytes(sv, result.data(), size);
	return result;
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
	a.port     = consume_little_endian<decltype(a.port    )>(sv);
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
		std::cout << "has witness" << std::endl;
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


inline static const unsigned int g_testnet_magic_number = 0x0709110b;
inline static const          int g_version              = 0x00011180;
inline static const char user_agent[] = "ourNode:0.0";
net_addr our_net_address;
net_addr blank_net_address;

struct message
{
	char header[24];
	std::string body; // might use a custom allocator to avoid zero-init on resize() https://stackoverflow.com/questions/21028299/is-this-behavior-of-vectorresizesize-type-n-under-c11-and-boost-container/21028912#21028912

	std::uint32_t magic_number;
	std::string command;
	std::uint32_t len;
	std::uint32_t checksum;

	message() = default;
	message(const std::string cmd)
		: command(cmd)
	{
		serialize_little_endian((unsigned char*)header, g_testnet_magic_number);
		std::strncpy((char*)&header[4], std::string(12,0).c_str(), 12);
		std::strncpy((char*)&header[4], cmd.c_str(), 12);
	}

	template<typename T>
	void append_little_endian(T t)
	{
		for (int i=0 ; i<sizeof(T) ; i++, t >>= 8)
			body.push_back((char)(t & 0xFF));
	}
	template<typename C>
	void append_bytes(const C b[], size_t N)
	{
		body.append((char*)b, (char*)b+N);
	}
	void append_var_str(const char b[], size_t N)
	{
		append_var_int(N);
		append_bytes(b, N);
	}
	void append_var_int(size_t s)
	{
		if (s < 0xFD)
			body.push_back((char)s);
		else if (s <= 0xFFFF)
		{
			body.push_back((char)0xFD);
			append_little_endian(std::uint16_t(s));
		}
		else if (s <= 0xFFFFFFFF)
		{
			body.push_back((char)0xFE);
			append_little_endian(std::uint32_t(s));
		}
		else
			append_little_endian(s);
	}
	void append_net_addr(const net_addr & addr, bool has_time)
	{
		if (has_time)
			append_little_endian(std::uint32_t(addr.time));
		append_little_endian(addr.services);
		append_bytes(addr.addr, sizeof(our_net_address.addr));
		append_little_endian(addr.port);
	}

	bool recv(boost::asio::ip::tcp::socket & socket, std::chrono::seconds timeout)
	{
		if ( ! recv_bytes(socket, boost::asio::buffer(header, 24), timeout))
			return false;
		
		std::string_view sv(header, 24);

		magic_number = consume_little_endian<decltype(magic_number)>(sv);
		for (char *ptr=&header[4] ; ptr<&header[16] && *ptr!=0 ; ++ptr)
			command.push_back(*ptr);
		sv.remove_prefix(12);
		len = consume_little_endian<decltype(len)>(sv);
		checksum = consume_little_endian<decltype(checksum)>(sv);

		if (magic_number != g_testnet_magic_number) {
			std::cout << "Bad magic number." << std::endl;
			return false;
		}
		if (len > 10*1024*1024) {
			std::cout << "dropping msg, too big" << std::endl;
			return false;
		}
		if (len != 0)
		{
			body.resize(len);
			if ( ! recv_bytes(socket, boost::asio::buffer(body.data(), len), std::chrono::seconds(10)))
				return false;
		}

		if (checksum != calculate_checksum((unsigned char*)body.data(), len))
			std::cout << "Bad checksum for command " << command << " "
			          << std::hex << checksum
			          << " instead of " << calculate_checksum((unsigned char*)body.data(), len)
			          << std::dec << std::endl;

		return true;
	}

	bool send(boost::asio::ip::tcp::socket & socket)
	{
		len = body.size();
		checksum = calculate_checksum((unsigned char*)body.data(), len);
		serialize_little_endian((unsigned char*)&header[16], len);
		serialize_little_endian((unsigned char*)&header[20], checksum);

		return send_bytes(socket, boost::asio::buffer((char*)header, sizeof(header)), std::chrono::seconds(5))
			&& send_bytes(socket, boost::asio::buffer(body.data(), len) , std::chrono::seconds(5));
	}
};

std::ostream & operator<<(std::ostream & out, const message & m)
{
	if (out.flags() & std::ios::hex)
	{
		pxln(std::string_view(m.header, 24));
		px(std::string_view(m.body.data(), m.body.size()));
	}
	return out;
}

struct peer : std::enable_shared_from_this<peer>
{
	boost::asio::ip::tcp::socket socket;

	bool handshaken;
	bool error;
	uint64_t nonce;
	config::peer peer_config;
	utttil::synchronized<ournode::config> & conf;

	boost::fibers::fiber handshake_fiber;
	std::map<std::string, boost::fibers::promise<message>> expected_messages;

	// peer's info
	std::int32_t  peer_version;
	std::uint64_t peer_services;
	net_addr      peer_net_address;
	uint64_t      peer_nonce;
	int64_t       peer_timestamp;
	std::string   peer_user_agent;
	int32_t       peer_block_height;

	peer(boost::asio::io_context & io_context, config::peer peer_config_, utttil::synchronized<ournode::config> & conf_)
		: socket(io_context)
		, handshaken(false)
		, error(false)
		, nonce((((uint64_t)rand()) << 32) + rand())
		, peer_config(std::move(peer_config_))
		, conf(conf_)
	{}
	~peer()
	{
		if (handshake_fiber.joinable())
			handshake_fiber.join();
	}

	const config::peer & get_config() const { return peer_config; }

	void start()
	{
		boost::fibers::fiber([this](){
				try {
					run();
				} catch (const std::exception & e) {
					std::cout << "run() trew: " << e.what() << std::endl;
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					if (st) {
						std::cerr << *st << '\n';
					}
					error = true;
				}
			}).detach();
	}

	void run()
	{
		if ( !connect())
			return;

		// handshake
		handshake_fiber = boost::fibers::fiber(boost::fibers::launch::dispatch,
			[this](){
				send_version_msg();
				handshaken = expect_many({"version","verack"}, std::chrono::seconds(5));
				error &= ! handshaken;
				if (handshaken) {
					std::cout << "Connected to " << peer_config.ip << " " << peer_config.port << std::endl;
					message("getaddr").send(socket);
				} else {
					std::cout << "Coudln't connect to " << peer_config.ip << " " << peer_config.port << std::endl;
				}
			});

		// message loop
		while( ! error) {
			message m = recv_msg();
			if (error) break;
			handle_msg(std::move(m));
		}
	}

	bool connect()
	{
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(peer_config.ip), peer_config.port);
		
		boost::fibers::promise<bool> promise;
		boost::fibers::future<bool> future(promise.get_future());
		
		//std::cout << "Trying " << peer_config.ip << " " << peer_config.port << std::endl;
		socket.async_connect(endpoint, [promise=std::move(promise)](boost::system::error_code ec) mutable {
				promise.set_value(!ec);
			});
		if (future.wait_for(std::chrono::seconds(5)) != boost::fibers::future_status::ready) {
			socket.cancel();
			error = true;
			return false;
		}
		error = ! future.get();
		return ! error;
	}
	bool got_handshake() const
	{
		return handshaken;
	}

	void send_version_msg()
	{
		int32_t start_height = 0;

		std::int64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		our_net_address.time = unix_time;

		message m("version");
		m.append_little_endian(g_version);
		m.append_little_endian(our_net_address.services);
		m.append_little_endian(unix_time);
		m.append_net_addr(blank_net_address, false);
		m.append_net_addr(  our_net_address, false);
		m.append_little_endian(nonce);
		m.append_var_str(user_agent, sizeof(user_agent));
		m.append_little_endian(start_height);

		m.send(socket);

		//std::cout << "sent " << m.len << " bytes of -version- to " << peer_config.ip << " " << peer_config.port << std::endl;
		//std::cout << std::hex << m << std::dec << std::endl;
		//pxln({(char*)m.header, 24});
		//pxln((char*)buf, len);
	}
	void send_getheaders_msg(const Hash256 & last_known_hash)
	{
		Hash256 zero_hash;
		zero_hash.zero();

		message m("getheaders");

		m.append_little_endian(g_version);
		m.append_var_int(1);
		m.append_bytes(last_known_hash.h, 32);
		m.append_bytes(zero_hash.h, 32);

		m.send(socket);
	}
	void send_block_getdata_msg(const Hash256 & last_known_hash)
	{
		message m("getdata");

		m.append_var_int(1);
		m.append_little_endian(std::uint32_t(MSG_BLOCK));
		m.append_bytes(last_known_hash.h, 32);

		m.send(socket);
	}

	bool expect_many(const std::vector<std::string> msg_types, std::chrono::seconds timeout)
	{
		for (const std::string & msg_type : msg_types)
		{
			//std::cout << "expecting " << msg_type << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			expected_messages.emplace(msg_type, boost::fibers::promise<message>());
		}
		bool got_all = true;
		auto deadline = std::chrono::system_clock::now() + timeout;
		for (const std::string & msg_type : msg_types)
		{
			//std::cout << "Now waiting for " << msg_type << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			bool got_this_one = expected_messages[msg_type].get_future().wait_until(deadline) == boost::fibers::future_status::ready;
			//std::cout << "Got " << msg_type << " ? " << got_this_one << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			got_all &= got_this_one;
			expected_messages.erase(msg_type);
		}
		//std::cout << "expect fulfilled " << peer_config.ip << "  " << peer_config.port << std::endl;
		return got_all;
	}

	std::tuple<bool,message> expect(std::string msg_type, std::chrono::seconds timeout = std::chrono::seconds(5))
	{
		expected_messages.emplace(msg_type, boost::fibers::promise<message>());
		auto deadline = std::chrono::system_clock::now() + timeout;
		auto future = expected_messages[msg_type].get_future();
		if (future.wait_until(deadline) != boost::fibers::future_status::ready) {
			expected_messages.erase(msg_type);
			return {false,{}};
		}
		message m = std::move(future.get());
		expected_messages.erase(msg_type);
		return {true,std::move(m)};
	}

	const message recv_msg()
	{
		message result;
		error = ! result.recv(this->socket, std::chrono::seconds(600));
		//std::cout << "recvd " << result.len << " bytes of " << result.command << " from " << peer_config.ip << "  " << peer_config.port << std::endl;
		return result;
	}

	void handle_msg(message && m)
	{		
		//std::cout << "Msg: " << m.command << std::endl;

		if (m.command == "version")
			process_version_msg(m);
		else if (m.command == "addr")
			process_addr_msg(m);
		else if (m.command == "reject")
			process_reject_msg(m);
		else if (m.command == "verack")
		{} // not much to do here
		else if (m.command == "block")
		{
		}
		else
		{
			std::cout << "Msg not handled: " << m.command << std::endl;
		}

		//else if (std::strcmp(&header[4], "headers") == 0)
		//	process_headers_msg(std::string_view(body.get(), len));
		//else if (std::strcmp(&header[4], "inv") == 0)
		//	process_inv_msg(std::string_view(buf, len));
		//else if (std::strcmp(&header[4], "block") == 0)
		//	process_block_msg(std::string_view(buf, len));

		auto it = expected_messages.find(m.command);
		if (it != expected_messages.end())
			it->second.set_value(std::move(m));
	}

	void process_reject_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.body.size());

		size_t rejected_len = consume_var_int(sv);
		std::string rejected_message(rejected_len+1, 0);
		strncpy(rejected_message.data(), sv.data(), rejected_len);
		sv.remove_prefix(rejected_len);

		char code = consume_little_endian<char>(sv);

		size_t reason_len = consume_var_int(sv);
		std::string reason_message(reason_len+1, 0);
		strncpy(reason_message.data(), sv.data(), reason_len);
		sv.remove_prefix(reason_len);

		std::cout << "Rejected " << rejected_message << ", because " << reason_message << std::endl;
	}

	void process_version_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.body.size());

		peer_version     = consume_little_endian<decltype(peer_version )>(sv);
		peer_services    = consume_little_endian<decltype(peer_services)>(sv);
		peer_timestamp   = consume_little_endian<decltype(peer_timestamp)>(sv);
		our_net_address  = consume_net_addr(sv, false);
		peer_net_address = consume_net_addr(sv, false);
		peer_nonce       = consume_little_endian<decltype(peer_nonce)>(sv);
		peer_user_agent  = consume_var_str(sv);

		message("verack").send(socket);
	}

	void process_addr_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.len);

		auto naddr = consume_var_int(sv);
		std::set<std::tuple<std::string,int>> known_peers_addresses;

		for (int i=0 ; i<naddr ; i++)
		{
			net_addr net_address = consume_net_addr(sv, peer_version >= 31402);

			std::string ip = net_address.to_string();
			//std::cout << "Got peer? " << ip << "  " << port << std::endl;
			known_peers_addresses.insert({ip, net_address.port});
		}

		{
			auto conf_proxy = conf.lock();
			for (const auto & t : known_peers_addresses)
				conf_proxy->add_known_peer_address(std::get<0>(t), std::get<1>(t));
		}
	}

	std::tuple<bool,message> get_headers(const Hash256 & last_known_hash)
	{
		send_getheaders_msg(last_known_hash);
		return expect("headers");
	}
	std::tuple<bool,message> get_block(const Hash256 & block_hash)
	{
		send_block_getdata_msg(block_hash);
		return expect("block");
	}
};

struct network
{
	utttil::synchronized<ournode::config> & conf;
	utttil::synchronized<ournode::blockchain> & bc;

	std::shared_ptr<boost::asio::io_context> io_context;
	boost::fibers::fiber keep_well_connected_fiber;
	boost::fibers::fiber keep_up_to_date_fiber;

	std::vector<std::shared_ptr<peer>> handshaken_peers;
	bool error;

	network(utttil::synchronized<ournode::config> & conf_, utttil::synchronized<ournode::blockchain> & bc_)
		: conf(conf_)
		, bc(bc_)
	{}

	void run()
	{
		io_context = std::make_shared<boost::asio::io_context>();
		boost::fibers::use_scheduling_algorithm<boost::fibers::asio::round_robin>(io_context);

		keep_well_connected_fiber = boost::fibers::fiber([this](){ keep_well_connected(); });
		keep_up_to_date_fiber     = boost::fibers::fiber([this](){ keep_up_to_date(); });
		boost::this_fiber::sleep_for(std::chrono::seconds(1));
		
		io_context->run();
				
		keep_well_connected_fiber.join();
		keep_up_to_date_fiber.join();
	}

	void keep_well_connected()
	{
		size_t parallel_connection_ratio = conf.lock()->parallel_connection_ratio;
		size_t min_peer_count            = conf.lock()->min_peer_count;

		std::set<config::peer> untried_peers  = conf.lock()->known_peers;
		std::set<config::peer> rejected_peers = conf.lock()->rejected_peers;

		std::vector<std::shared_ptr<peer>> trying_peers;
		trying_peers.reserve(min_peer_count * parallel_connection_ratio);

		for (;;)
		{
			if (handshaken_peers.empty() && untried_peers.empty() && trying_peers.empty())
			{
				error = true;
				std::cout << "No more known peers, can't connect." << std::endl;
				return;
			}

			if (handshaken_peers.size() < min_peer_count)
			{
				size_t needed_tries = (min_peer_count - handshaken_peers.size()) * parallel_connection_ratio;
				while (trying_peers.size() < needed_tries && ! untried_peers.empty())
				{
					auto p = std::make_shared<peer>(*io_context, *untried_peers.begin(), conf);
					untried_peers.erase(untried_peers.begin());
					trying_peers.push_back(p);
					p->start();
				}
			}			
			boost::this_fiber::sleep_for(std::chrono::seconds(1));
			std::erase_if(trying_peers, [&](const auto & p)
				{
					if (p->error) {
						//std::cout << "Rejecting " << p->get_config().ip << " " << p->get_config().port << std::endl;
						rejected_peers.insert(p->get_config());
						untried_peers.erase(p->get_config());
						return true;
					} else if (p->got_handshake()) {
						handshaken_peers.push_back(p);
						untried_peers.erase(p->get_config());
						return true;
					}
					return false;
				});
			//std::cout << "Handshaken with " << handshaken_peers.size() << std::endl;
		}
	}

	std::shared_ptr<peer> select_peer()
	{
		// Random for now. How about a round robin here?
		return *std::next(handshaken_peers.begin(), rand() % handshaken_peers.size());
	}

	void keep_up_to_date()
	{
		while (handshaken_peers.empty())
			boost::this_fiber::sleep_for(std::chrono::milliseconds(1));

		// initial sync
		for (int i=0 ; i<conf->min_peer_count ; i++)
		{
			auto peer = select_peer();
			if ( ! peer || peer->error) {
				std::cout << "Bad peer chosen" << std::endl;
				continue;
			}
			if (bc->best_height() == blockchain::no_height)
			{
				bool rcvd;
				message genesis_block_msg;
				std::tie(rcvd,genesis_block_msg) = peer->get_block(blockchain::testnet_genesis_block_hash);
				if ( ! rcvd)
					continue;
				try
				{
					if (process_block_msg(genesis_block_msg, blockchain::testnet_genesis_block_hash))
						break;
				}
				catch (const std::exception & e)
				{
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					break;
				}
			}
		}
		if (bc->best_height() == blockchain::no_height)
		{
			std::cout << "Failed to get the genesis block" << std::endl;
			return;
		}

		std::cout << "Synching from block height " << bc->best_height() << std::endl;
		for (int i=0 ; i<conf->min_peer_count ;)
		{
			auto peer = select_peer();
			auto & last_known_hash = bc->get_last_known_block_hash();
			bool rcvd;
			message headers_msg;
			std::tie(rcvd,headers_msg) = peer->get_headers(last_known_hash);
			if ( ! rcvd) {
				++i;
				continue;
			}
			try
			{
				std::vector<std::tuple<block,Hash256>> headers = process_headers_msg(headers_msg);
				for (std::tuple<block,Hash256> & p : headers)
				{
					for (;;)
					{
						if (bc->has(std::get<1>(p)))
							break;
						bool rcvd;
						message block_msg;
						std::tie(rcvd,block_msg) = peer->get_block(std::get<1>(p));
						if (rcvd && process_block_msg(block_msg, std::get<1>(p)))
							break;
					}
				}
				auto & new_last_known_hash = bc->get_last_known_block_hash();
				if (new_last_known_hash == last_known_hash)
					++i;
			}
			catch (std::exception & e)
			{}
		}

		// all up-to-date
	}

	std::vector<std::tuple<block,Hash256>> process_headers_msg(const message & msg)
	{
		std::vector<std::tuple<block,Hash256>> result;

		std::string_view data(msg.body.data(), msg.body.size());

		std::uint64_t nheaders;
		nheaders = consume_var_int(data);
		size_t unknown_headers = 0;

		for(decltype(nheaders) i = 0 ; i< nheaders ; i++)
		{
			const char * header_begin = data.data();
			block bl;
			Hash256 hash;
			std::tie(bl, hash) = consume_header(data, true);
			const char * header_end = data.data();
			result.push_back({std::move(bl), hash});
		}
		return result;
	}
	bool process_block_msg(const message & msg, const Hash256 & supposed_block_hash)
	{
		//std::cout << "msg: " << std::hex << msg << std::dec << std::endl;
		std::string_view data(msg.body.data(), msg.body.size());

		if (data.size() < 81)
		{
			std::cout << "BLOCK DROPPED: block was truncated." << std::endl;
			return false;
		}

		// std::string block_hash = dbl_sha256({data.data(), 80});
		// std::reverse(block_hash.begin(), block_hash.end());
		// pxln(block_hash.data(), 32);

		// unsigned char * announced_previous_block_hash = (unsigned char*)data.data()+4;
		// if ( ! bc.is_block_hash_close_to_tip(announced_previous_block_hash))
		// {
		// 	std::cout << "BLOCK DROPPED: previous block not in cache." << std::endl;
		// 	return;
		// }

		block bl;
		Hash256 hash;
		std::tie(bl, hash) = consume_header(data, false);

		if (hash != supposed_block_hash) {
			std::cout << "Was expecting " << supposed_block_hash
			          << ", got " << hash << std::endl;
			return false;
		}

		std::cout << "Block hash: " << std::hex << hash << std::dec << std::endl;

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
			std::cout << std::hex << txids.back() << std::dec << std::endl;
		}

		Hash256 merkle_root;
		fill_merkle_root(merkle_root, std::move(txids));
		std::cout << "Block merkle root     : " << std::hex << bl.merkle_root << std::dec << std::endl;
		std::cout << "Calculated merkle root: " << std::hex << merkle_root << std::dec << std::endl;
		if (bl.merkle_root != merkle_root) {
			std::cout << "======================================================================================================================" << std::endl << std::endl << std::endl;
			exit(-1);
		}
		//std::cout << "ntx: " << ntx << std::endl;
		//if (ntx > 1)
		//	for (int i=0 ; i<ntx ; i++)
		//		std::cout << "tx " << i << std::endl
		//				<< bl.txs[i] << std::endl;

		return bc->add(std::move(bl), hash);
	}
};

} // namespace
 