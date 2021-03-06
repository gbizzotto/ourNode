
#pragma once

#include <list>
#include <set>
#include <unordered_set>
#include <cstring>
#include <tuple>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/fiber/all.hpp>
#include "round_robin.hpp"
#include "yield.hpp"

#define _GNU_SOURCE
#include <boost/stacktrace.hpp>
#include <boost/exception/all.hpp>
typedef boost::error_info<struct tag_stacktrace, boost::stacktrace::stacktrace> traced;

#include "synchronized.hpp"
#include "observable.hpp"
#include "log.hpp"

#include "config.hpp"
#include "sha256sum.hpp"
#include "blockchain.hpp"
#include "misc.hpp"
#include "block_verifier.hpp"
#include "block_parsing.hpp"

namespace ournode {

// inv type
#define MSG_BLOCK 2
// node services
#define NODE_NETWORK 1

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
		, len(0)
	{
		serialize_little_endian((unsigned char*)header, g_testnet_magic_number);
		std::strncpy((char*)&header[4], std::string(12,0).c_str(), 12);
		std::strncpy((char*)&header[4], cmd.c_str(), 12);
	}

	size_t byte_count() const { return 24 + len; }

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

	bool recv(boost::asio::ip::tcp::socket & socket, std::chrono::seconds timeout, const bool & go_on)
	{
		if ( ! recv_bytes(socket, boost::asio::buffer(header, 24), timeout, go_on))
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
			if ( ! recv_bytes(socket, boost::asio::buffer(body.data(), len), timeout*2, go_on))
				return false;
		}

		if (checksum != calculate_checksum((unsigned char*)body.data(), len))
			std::cout << "Bad checksum for command " << command << " "
			          << std::hex << checksum
			          << " instead of " << calculate_checksum((unsigned char*)body.data(), len)
			          << std::dec << std::endl;

		return true;
	}

	bool send(boost::asio::ip::tcp::socket & socket, const bool & go_on)
	{
		len = body.size();
		checksum = calculate_checksum((unsigned char*)body.data(), len);
		serialize_little_endian((unsigned char*)&header[16], len);
		serialize_little_endian((unsigned char*)&header[20], checksum);

		return send_bytes(socket, boost::asio::buffer((char*)header, sizeof(header)), std::chrono::seconds(10), go_on)
			&& send_bytes(socket, boost::asio::buffer(body.data(), len)             , std::chrono::seconds(10), go_on);
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

template<typename network>
struct peer : std::enable_shared_from_this<peer<network>>
{
	enum Status
	{
		Closed = 0,
		Opening = 1,
		Handshaken = 2,
	};

	network & net;
	boost::asio::ip::tcp::socket socket;

	uint64_t nonce;
	peer_config my_peer_config;

	utttil::observable<Status> status;
	utttil::observable<peer_config::Quality> quality;

	// network stats
	size_t bytes_rcvd = 0;
	size_t bytes_sent = 0;

	std::map<std::string, boost::fibers::promise<message>> expected_messages;

	// peer's info
	std::int32_t  peer_version;
	std::uint64_t peer_services;
	net_addr      peer_net_address;
	uint64_t      peer_nonce;
	int64_t       peer_timestamp;
	std::string   peer_user_agent;
	int32_t       peer_block_height;

	peer(network & net_, const peer_config & peer_config_, const peer_config::Quality q=peer_config::Quality::Unknown)
		: net(net_)
		, socket(*net_.io_context)
		, nonce((((uint64_t)rand()) << 32) + rand())
		, my_peer_config(peer_config_)
		, status(Closed)
		, quality(q)
	{}

	const peer_config & get_config() const { return my_peer_config; }
	operator peer_config() const { return my_peer_config; }
	bool has(std::uint64_t services) const { return (services & peer_services) == services; }

	void start()
	{
		status = Opening;
		boost::fibers::fiber([self=this->shared_from_this()](){
				utttil::fiber_local_logger("peer");
				TRACE
				try {
					self->run();
				} catch (const std::exception & e) {
					utttil::error() << "peer::run() threw: " << e.what() << std::endl;
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					if (st) {
						std::cerr << *st << '\n';
					}
					self->socket.close();
					self->status = Closed;
					PRINT_TRACE
				} catch(...) {
					PRINT_TRACE
				}
			}).detach();
	}

	void run()
	{
		TRACE
		//utttil::info() << "Trying " << my_peer_config << std::endl;
		if ( !connect()) {
			return;
		}

		//utttil::info() << "Socket opened with " << my_peer_config << std::endl;

		// handshake
		boost::fibers::fiber(boost::fibers::launch::dispatch,
			[self=this->shared_from_this()](){
				TRACE
				try {		
					self->send_version_msg();
					bool rcvd = self->expect_many({"version","verack"}, std::chrono::seconds(20));
					if ( ! rcvd) {
						//utttil::info() << "Coudln't connect to " << self->my_peer_config << std::endl;
						return;
					}
					//utttil::info() << "Hands shaken with " << self->my_peer_config << std::endl;
					self->send(message("getaddr"));
					/*message addr;
					std::tie(rcvd,addr) = self->expect("addr", std::chrono::seconds(10));
					if ( ! rcvd) {
						//utttil::info() << "Didn't receive 'addr' msg from " << self->my_peer_config << std::endl;
						return;
					}*/
					//utttil::info() << "Fully connected to " << self->my_peer_config << std::endl;
					self->quality = peer_config::Quality::Good;
					self->status = Handshaken;
				} catch (const std::exception & e) {
					utttil::info() << "peer handshake threw: " << e.what() << std::endl;
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					if (st) {
						std::cerr << *st << '\n';
					}
					self->socket.close();
					self->status = Closed;
					PRINT_TRACE
				} catch(...) {
					PRINT_TRACE
				}
			}).detach();

		// message loop
		while(status != Closed) {
			message m = recv_msg();
			if (status == Closed)
				break;
			handle_msg(std::move(m));
		}
	}

	bool connect()
	{
		TRACE
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(my_peer_config.ip), my_peer_config.port);
		
		boost::fibers::promise<bool> promise;
		boost::fibers::future<bool> future(promise.get_future());
		
		socket.async_connect(endpoint, [self=this->shared_from_this(),promise=std::move(promise)](boost::system::error_code ec) mutable {
				if (ec) {
					//std::cout << "async_connect to " << self->my_peer_config << ", ec: " << ec.message() << std::endl;
					if (ec == boost::asio::error::connection_refused) {
						self->quality = peer_config::Quality::Rejected;
						//std::cout << "REJECTING " << self->my_peer_config;
					}
					self->status = Closed;
				}
				promise.set_value(!ec);
			});
		if (future.wait_for(std::chrono::seconds(10)) != boost::fibers::future_status::ready)
		{
			//std::cout << "Timeout connecting to " << my_peer_config << std::endl;
			socket.close();
			quality = peer_config::Quality::Unresponsive;
			status = Closed;
			return false;
		}
		if (status == Closed)
			return false;
		return true;
	}
	bool send(message & m)
	{
		TRACE
		if (m.send(socket, net.go_on)) {
			bytes_sent     += m.byte_count();
			net.bytes_sent += m.byte_count();
			return true;
		} else {
			quality = peer_config::Quality::Unknown;
			socket.close();
			status  = Closed;
		}
		return false;
	}
	bool send(message && m)
	{
		return send(std::ref(m));
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

		send(m);

		//std::cout << "sent " << m.len << " bytes of -version- to " << my_peer_config << std::endl;
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

		send(m);
	}
	void send_block_getdata_msg(const Hash256 & last_known_hash)
	{
		message m("getdata");

		m.append_var_int(1);
		m.append_little_endian(std::uint32_t(MSG_BLOCK));
		m.append_bytes(last_known_hash.h, 32);

		send(m);
	}
	void send_block_getdata_msg(const std::list<Hash256> & hashes)
	{
		message m("getdata");

		m.append_var_int(hashes.size());
		for (const Hash256 & h : hashes)
		{
			m.append_little_endian(std::uint32_t(MSG_BLOCK));
			m.append_bytes(h.h, 32);
		}

		send(m);
	}
	void send_getblocks_msg(const Hash256 & last_known_hash)
	{
		Hash256 zero_hash;
		zero_hash.zero();

		message m("getblocks");

		m.append_little_endian(g_version);
		m.append_var_int(1);
		m.append_bytes(last_known_hash.h, 32);
		m.append_bytes(zero_hash.h, 32);

		send(m);
	}

	bool expect_many(const std::vector<std::string> msg_types, std::chrono::seconds timeout)
	{
		TRACE
		for (const std::string & msg_type : msg_types)
		{
			//std::cout << "expecting " << msg_type << " " << my_peer_config << std::endl;
			expected_messages.emplace(msg_type, boost::fibers::promise<message>());
		}
		bool got_all = true;
		auto deadline = std::chrono::system_clock::now() + timeout;
		for (const std::string & msg_type : msg_types)
		{
			//std::cout << "Now waiting for " << msg_type << " " << my_peer_config << std::endl;
			bool got_this_one = expected_messages[msg_type].get_future().wait_until(deadline) == boost::fibers::future_status::ready;
			//std::cout << "Got " << msg_type << " ? " << got_this_one << " " << my_peer_config << std::endl;
			got_all &= got_this_one;
			expected_messages.erase(msg_type);
		}
		//std::cout << "expect fulfilled " << my_peer_config << std::endl;
		return got_all;
	}

	std::tuple<bool,message> expect(std::string msg_type, std::chrono::seconds timeout = std::chrono::seconds(10))
	{		
		TRACE
		expected_messages.emplace(msg_type, boost::fibers::promise<message>());
		auto future = expected_messages[msg_type].get_future();
		for (auto deadline = std::chrono::system_clock::now()+timeout ; net.go_on && std::chrono::system_clock::now() < deadline ; )
			if (future.wait_until(deadline) == boost::fibers::future_status::ready)
			{
				message m = std::move(future.get());
				expected_messages.erase(msg_type);
				return {true,std::move(m)};
			}
		expected_messages.erase(msg_type);
		return {false,{}};
	}

	const message recv_msg()
	{
		TRACE
		message result;

		std::chrono::seconds timeout(600);
		for (auto deadline=std::chrono::system_clock::now()+timeout ; net.go_on && std::chrono::system_clock::now() < deadline ; )
			if (result.recv(this->socket, timeout, net.go_on))
			{
				bytes_rcvd     += result.byte_count();
				net.bytes_rcvd += result.byte_count();
				return result;
			}
		quality = peer_config::Quality::Unknown;
		socket.close();
		status  = Closed;
		return {};
	}

	void handle_msg(message && m)
	{	
		TRACE	
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
		{}
		else if (m.command == "inv") {
			net.process_inv_msg(m);
		}
		else
		{
			//std::cout << "Msg not handled: " << m.command << std::endl;
		}

		//else if (std::strcmp(&header[4], "headers") == 0)
		//	process_headers_msg(std::string_view(body.get(), len));
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

		std::cout << "Msg was rejected " << rejected_message << ", because " << reason_message << std::endl;
	}

	void process_version_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.body.size());

		peer_version     = consume_little_endian<decltype(peer_version )>(sv);
		peer_services    = consume_little_endian<decltype(peer_services)>(sv);
		peer_timestamp   = consume_little_endian<decltype(peer_timestamp)>(sv);
		our_net_address  = consume_net_addr(sv, false);
		if (peer_version >= 106)
		{
			peer_net_address = consume_net_addr(sv, false);
			peer_nonce       = consume_little_endian<decltype(peer_nonce)>(sv);
			peer_user_agent  = consume_var_str(sv);
			peer_block_height= consume_little_endian<decltype(peer_block_height)>(sv);
			if (peer_block_height > net.peer_block_height)
				net.peer_block_height = peer_block_height;
		}

		send(message("verack"));
	}

	void process_addr_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.len);

		auto naddr = consume_var_int(sv);
		std::set<std::tuple<std::string,int>> known_peers_addresses;
		for (int i=0 ; i<naddr ; i++)
		{
			net_addr net_address = consume_net_addr(sv, peer_version >= 31402);
			if ( ! net_address.port)
				continue;
			std::string ip = net_address.to_string();
			known_peers_addresses.insert({ip, net_address.port});
		}

		size_t old_peer_count = 0;
		size_t new_peer_count = 0;
		{
			auto conf_proxy = net.conf.lock();
			old_peer_count = conf_proxy->peers.size();
			for (const auto & t : known_peers_addresses)
				conf_proxy->insert_peer(std::get<0>(t), std::get<1>(t));
			new_peer_count = conf_proxy->peers.size();
		}
		if (old_peer_count != new_peer_count)
			net.my_peer_manager.check_need_more_tries();
	}

	std::tuple<bool,message> get_headers(const Hash256 & last_known_hash)
	{
		send_getheaders_msg(last_known_hash);
		return expect("headers");
	}
	std::tuple<bool,message> get_block(const Hash256 & block_hash, std::chrono::seconds timeout=std::chrono::seconds(60))
	{
		send_block_getdata_msg(block_hash);
		return expect("block", timeout);
	}
	std::tuple<bool,message> get_next_blocks_inv(const Hash256 & last_block_hash, std::chrono::seconds timeout=std::chrono::seconds(60))
	{
		send_getblocks_msg(last_block_hash);
		return expect("inv", timeout);
	}
};

template<typename network>
struct peer_manager
{
	using peer_sptr = std::shared_ptr<peer<network>>;

	network & net;

	std::shared_ptr<boost::asio::io_context> io_context;

	std::set<peer_config> closed_good_peers;
	std::set<peer_config> closed_unknown_peers;
	std::map<peer_config, peer_sptr> opening_peers;
	std::map<peer_config, peer_sptr> handshaken_peers;
	std::map<peer_config, peer_sptr> peers_in_use;
	std::atomic_int waiting_count = 0;

	peer_manager(network & net_)
		: net(net_)
		, io_context(net_.io_context)
	{}
	void quality_change_callback(const std::shared_ptr<peer<network>> & p, const peer_config::Quality & before, const peer_config::Quality & after)
	{
		TRACE
		net.conf->set_peer_quality(p->get_config(), after);
	}
	void status_change_callback(const std::shared_ptr<peer<network>> & p, const typename peer<network>::Status & before, const typename peer<network>::Status & after)
	{
		TRACE
		opening_peers.erase(p->get_config());
		{
			handshaken_peers.erase(p->get_config());
		}
		switch(after)
		{
			case peer<network>::Status::Opening:
				closed_good_peers.erase(p->get_config());
				closed_unknown_peers.erase(p->get_config());
				opening_peers.insert({p->get_config(), p});
				break;
			case peer<network>::Status::Handshaken:
				opening_peers.erase(p->get_config());
				handshaken_peers.insert({p->get_config(), p});
				break;
			case peer<network>::Status::Closed:
				opening_peers.erase(p->get_config());
				handshaken_peers.erase(p->get_config());
				peers_in_use.erase(p->get_config());
				auto q = net.conf->get_quality(p->get_config());
				if (q == peer_config::Quality::Good)
					closed_good_peers.insert(p->get_config());
				else if (q == peer_config::Quality::Unknown)
					closed_unknown_peers.insert(p->get_config());
				break;
		}
		check_need_more_tries();
	}

	void load_from_conf()
	{
		//std::cout << "load_from_conf() closed_peers.size(): " << closed_good_peers.size() + closed_unknown_peers.size() << std::endl;
		for (const auto & p : net.conf->peers)
		{
			if (p.second == peer_config::Quality::Rejected || p.second == peer_config::Quality::Unresponsive)
				continue;
			if (   in(p.first, closed_good_peers)
			    || in(p.first, closed_unknown_peers)
			    || in(p.first, opening_peers)
			    || in(p.first, handshaken_peers)
			    || in(p.first, peers_in_use) )
			{
				continue;
			}
			if (p.second == peer_config::Quality::Good)
				closed_good_peers.insert(p.first);
			else if (p.second == peer_config::Quality::Unknown)
				closed_unknown_peers.insert(p.first);
		}
	}

	void check_need_more_tries()
	{
		TRACE
		size_t parallel_connections_max;
		size_t parallel_connections_ratio;
		{
			auto proxy = net.conf.lock();
			parallel_connections_max   = proxy->parallel_connections_max;
			parallel_connections_ratio = proxy->parallel_connections_ratio;
		}
		for ( size_t parallel_connections_needed = std::min(parallel_connections_max, parallel_connections_ratio*(waiting_count))
		    ; parallel_connections_needed > opening_peers.size()
			; parallel_connections_needed-- )
		{
			if (closed_good_peers.empty() && closed_unknown_peers.empty()) 
				load_from_conf();
			if (closed_good_peers.empty() && closed_unknown_peers.empty())
				return;
			std::shared_ptr<peer<network>> new_peer;
			if ( ! closed_good_peers.empty()) {
				auto it = random(closed_good_peers);
				new_peer = std::make_shared<peer<network>>(net, *it, peer_config::Quality::Good);
				closed_good_peers.erase(it);
			} else {
				auto it = random(closed_unknown_peers);
				new_peer = std::make_shared<peer<network>>(net, *it, peer_config::Quality::Unknown);
				closed_unknown_peers.erase(it);
			}
			new_peer->quality.observe([new_peer,self=this](const peer_config::Quality & before, const peer_config::Quality & after)
				{
					self->quality_change_callback(new_peer, before, after);
				});
			new_peer->status.observe([new_peer,self=this](const typename peer<network>::Status & before, const typename peer<network>::Status & after)
				{
					self->status_change_callback(new_peer, before, after);
				});
			new_peer->start();
			opening_peers.insert({new_peer->get_config(), new_peer});
		}
	}

	std::shared_ptr<peer<network>> get_peer()
	{
		TRACE
		std::pair<peer_config, std::shared_ptr<peer<network>>> p;
		waiting_count++;
		check_need_more_tries();
		ON_SCOPE_EXIT([&](){ waiting_count--; });
		for ( ; net.go_on ; boost::this_fiber::sleep_for(std::chrono::milliseconds(100)))
			if ( ! handshaken_peers.empty())
			{
				p = *handshaken_peers.begin();
				handshaken_peers.erase(handshaken_peers.begin());
				peers_in_use.insert(p);
				return p.second;
			}
		return nullptr;
	}

	void return_peer(std::shared_ptr<peer<network>> p)
	{
		TRACE
		peers_in_use.erase(p->get_config());
		switch(p->status)
		{
			case peer<network>::Status::Opening:
				closed_good_peers.erase(p->get_config());
				closed_unknown_peers.erase(p->get_config());
				opening_peers.insert({p->get_config(), p});
				break;
			case peer<network>::Status::Handshaken:
				opening_peers.erase(p->get_config());
				handshaken_peers.insert({p->get_config(), p});
				break;
			case peer<network>::Status::Closed:
				opening_peers.erase(p->get_config());
				handshaken_peers.erase(p->get_config());
				peers_in_use.erase(p->get_config());
				auto q = net.conf->get_quality(p->get_config());
				if (q == peer_config::Quality::Good)
					closed_good_peers.insert(p->get_config());
				else if (q == peer_config::Quality::Unknown)
					closed_unknown_peers.insert(p->get_config());
				break;
		}
	}
};

struct network
{
	using blockchain = ournode::blockchain<file_block_persistence, memory_tx_persistence>;

	std::shared_ptr<boost::asio::io_context> io_context;
	utttil::synchronized<ournode::config                 , boost::fibers::mutex, boost::fibers::condition_variable> & conf;
	utttil::synchronized<blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc;

	peer_manager<network> my_peer_manager;
	std::vector<std::shared_ptr<peer<network>>> peers;

	int32_t peer_block_height = 0;
	std::list<Hash256> missing_blocks;

	block_verifier<file_block_persistence, memory_tx_persistence> & verifier;

	bool go_on;
	std::thread t;

	// network stats
	size_t bytes_rcvd = 0;
	size_t bytes_sent = 0;

	boost::fibers::fiber keep_well_connected_fiber;
	boost::fibers::fiber keep_up_to_date_fiber;
	boost::fibers::fiber keep_printing_stats_fiber;
	boost::fibers::fiber keep_saving_conf_fiber;

	
	network(utttil::synchronized<ournode::config, boost::fibers::mutex, boost::fibers::condition_variable> & conf_, utttil::synchronized<blockchain, boost::fibers::mutex, boost::fibers::condition_variable> & bc_, block_verifier<file_block_persistence, memory_tx_persistence> & verifier_)
		: io_context(std::make_shared<boost::asio::io_context>())
		, conf(conf_)
		, bc(bc_)
		, my_peer_manager(*this)
		, verifier(verifier_)
	{}
	~network()
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
		io_context->stop();
	}
	void start()
	{
		t = std::thread([&]()
			{
				utttil::fiber_local_logger("network");
				try {
					this->run();
				} catch (const std::exception & e) {
					utttil::error() << "network::run() threw: " << e.what() << std::endl;
					const boost::stacktrace::stacktrace* st = boost::get_error_info<traced>(e);
					if (st)
						utttil::error() << *st << '\n';
					PRINT_TRACE
				} catch(...) {
					TRACE
				}
			});
	}
	template<typename F>
	boost::fibers::fiber create_fiber(std::string s, F f)
	{
		return boost::fibers::fiber([&s,f2=std::move(f)]()
			{
				utttil::fiber_local_logger(s);
				TRACE
				ON_SCOPE_EXIT([&](){ utttil::info() << s << " ends" << std::endl; });
				try {
					f2();
				} catch(...) {
					PRINT_TRACE
				}
			});
	}
	void run()
	{
		TRACE

		go_on = true;
		boost::fibers::use_scheduling_algorithm<boost::fibers::asio::round_robin>(io_context);

		//my_peer_manager.start();
		keep_well_connected_fiber = create_fiber("keep_well_connected", [this](){ keep_well_connected(); });
		keep_up_to_date_fiber     = create_fiber("keep_up_to_date"    , [this](){ keep_up_to_date    (); });
		keep_printing_stats_fiber = create_fiber("keep_printing_stats", [this](){ keep_printing_stats(); });
		keep_saving_conf_fiber    = create_fiber("keep_saving_conf"   , [this](){ keep_saving_conf   (); });

		boost::this_fiber::sleep_for(std::chrono::seconds(1));
		io_context->run();
		go_on = false;

		keep_saving_conf_fiber.join();
		keep_printing_stats_fiber.join();
		keep_up_to_date_fiber.join();
		keep_well_connected_fiber.join();
	}

	void keep_well_connected()
	{
		TRACE

		auto min_peer_count = conf->min_peer_count;
		for ( ; go_on ; boost::this_fiber::sleep_for(std::chrono::seconds(1)))
		{
			while (peers.size() < min_peer_count && go_on)
			{
				auto p_sptr = my_peer_manager.get_peer();
				if ( ! p_sptr)
					return;
				peers.push_back(p_sptr);
			}
			std::erase_if(peers, [&](const auto & p)
				{
					if ( ! p)
						return true;
					if (p->quality == peer_config::Quality::Rejected) {
						//std::cout << "Rejecting " << p->get_config().ip << " " << p->get_config().port << std::endl;
						conf->set_peer_quality(p->get_config(), p->quality);
						return true;
					} else if (p->quality == peer_config::Quality::Unresponsive) {
						//std::cout << "Timed out " << p->get_config().ip << " " << p->get_config().port << std::endl;
						conf->set_peer_quality(p->get_config(), p->quality);
						return true;
					} else if (p->status == peer<network>::Status::Closed) {
						//std::cout << "Closed " << p->get_config().ip << " " << p->get_config().port << std::endl;
						return true;
					}
					return false;
				});
		}
	}

	void keep_printing_stats()
	{
		TRACE
		
		std::chrono::seconds timeout(1);
		while(go_on)
		{
			for (auto deadline=std::chrono::system_clock::now()+timeout ; go_on && std::chrono::system_clock::now() < deadline ; boost::this_fiber::sleep_for(std::chrono::milliseconds(10)))
			{}
			print_stats();
		}
	}
	void keep_saving_conf()
	{
		TRACE
		
		std::chrono::seconds timeout(10);
		while(go_on)
		{
			for (auto deadline=std::chrono::system_clock::now()+timeout ; go_on && std::chrono::system_clock::now() < deadline ; boost::this_fiber::sleep_for(std::chrono::milliseconds(10)))
			{}
			conf->save();
		}
	}

	void print_stats()
	{
		TRACE

		static size_t bytes_sent_then = 0;
		static size_t bytes_rcvd_then = 0;
		static auto then = std::chrono::system_clock::now();

		utttil::info() << std::endl;
		utttil::info() << "Handshaken with " << peers.size()+my_peer_manager.handshaken_peers.size()+my_peer_manager.peers_in_use.size() << std::endl;
		{
			auto bc_proxy = bc.lock();
			bc_proxy->print();
			utttil::info() << bc_proxy->size() << " blocks, " << missing_blocks.size() << " to go." << std::endl;
		}
		utttil::info() << verifier.candidates_count() << " queued for verification." << std::endl;
		utttil::info() << verifier.rejected_count() << " rejected from verification." << std::endl;
		auto now = std::chrono::system_clock::now();
		auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now-then).count();
		if (milliseconds != 0) {
			utttil::info() << "Sending bytes: " << (this->bytes_sent-bytes_sent_then) / milliseconds << " kB/s. : " << 8*(this->bytes_sent-bytes_sent_then) / milliseconds << " kb/s." << std::endl;
			utttil::info() << "Recving bytes: " << (this->bytes_rcvd-bytes_rcvd_then) / milliseconds << " kB/s. : " << 8*(this->bytes_rcvd-bytes_rcvd_then) / milliseconds << " kb/s." << std::endl;
		}
		then = now;
		bytes_sent_then = this->bytes_sent;
		bytes_rcvd_then = this->bytes_rcvd;
	}

	void keep_up_to_date()
	{
		TRACE
		
		// initial sync
		if (bc->best_height() == blockchain::no_height)
			missing_blocks.push_back(blockchain::testnet_genesis_block_hash);
		do {
			synchronize_blockchain();
		} while (bc->best_height() < peer_block_height && go_on);

		for ( ; go_on ; boost::this_fiber::sleep_for(std::chrono::seconds(10)))
		{
			auto bc_proxy = bc.lock();
			if (bc_proxy->best_height() < peer_block_height || bc_proxy->orphan_chains.size() > 0)
				synchronize_blockchain();
		}
	}

	void get_back_rejected_blocks()
	{
		auto hashes = std::move(*verifier.get_rejected_blocks_proxy());
		for (auto & hash : hashes)
			missing_blocks.push_front(hash);
	}

	void synchronize_blockchain()
	{
		TRACE

		utttil::info() << "Start synching blockchain." << std::endl;

		auto get_last_known_block_hash = [&]() -> const Hash256
			{
				auto bc_proxy = bc.lock();
				if ( ! missing_blocks.empty())
					return missing_blocks.back();
				else if (bc_proxy->best_height() != blockchain::no_height)
					return bc_proxy->get_last_known_block_hash();
				else
					return blockchain::testnet_genesis_block_hash;
			};

		bool downloading_block_list = true;

		auto get_block_hashes_fiber = boost::fibers::fiber(boost::fibers::launch::dispatch, [&]()
			{
				utttil::fiber_local_logger("get_block_hashes_fiber");
				TRACE
				try 
				{		
					utttil::info() << "get_block_hashes_fiber fiber starts" << std::endl;
					ON_SCOPE_EXIT([&](){ utttil::info() << "get_block_hashes_fiber fiber ends" << std::endl; });
					for (int i=0 ; i<10 && go_on ; i++)
					{
						auto p = my_peer_manager.get_peer();
						if ( ! p)
							return;
						utttil::info() << "Got peer get_block_hashes_fiber" << std::endl;

						while (go_on)
						{
							get_back_rejected_blocks();

							Hash256 request_hash = get_last_known_block_hash();
							//utttil::info() << "Requesting blocks after " << request_hash << std::endl;
							p->send_getblocks_msg(request_hash);

							for ( auto timeout=std::chrono::system_clock::now()+std::chrono::seconds(10)
								; std::chrono::system_clock::now() < timeout && go_on
								; boost::this_fiber::sleep_for(std::chrono::milliseconds(10)) )
							{
								if (get_last_known_block_hash() != request_hash) {
									i = 0;
									break;
								}
							}
							if (get_last_known_block_hash() == request_hash)
								break; // get another peer
						}
						my_peer_manager.return_peer(p);
					}
					utttil::must_have() << "I'm done getting new block hashes." << std::endl;
					downloading_block_list = false;
				} catch(...) {
					PRINT_TRACE
				}
			});

		const int max_DL_fibers_count = 10;
		std::vector<boost::fibers::fiber> get_blocks_fibers;
		get_blocks_fibers.reserve(max_DL_fibers_count);
		while (get_blocks_fibers.size() < max_DL_fibers_count && go_on)
			get_blocks_fibers.emplace_back([&]()
			{
				utttil::fiber_local_logger("get_blocks_fibers");
				TRACE
				try {
					//utttil::info() << "get_blocks_fiber fiber starts" << std::endl;
					//ON_SCOPE_EXIT([&](){ utttil::info() << "get_blocks_fiber fiber ends" << std::endl; });
					std::chrono::seconds timeout(20);
					std::list<Hash256> asked_blocks;
					auto p = my_peer_manager.get_peer();
					if ( ! p)
						return;

					while((downloading_block_list || ! this->missing_blocks.empty()) && go_on)
					{
						if (this->missing_blocks.empty()) {
							boost::this_fiber::sleep_for(std::chrono::seconds(1));
							continue;
						}

						int blocks_to_get = std::min(1 + (int)this->missing_blocks.size() / max_DL_fibers_count, 100);
						std::list<Hash256> tmp_list;
						tmp_list.splice(tmp_list.begin(), this->missing_blocks, this->missing_blocks.begin(), std::next(this->missing_blocks.begin(), blocks_to_get));
						p->send_block_getdata_msg(tmp_list);
						asked_blocks.splice(asked_blocks.end(), tmp_list);
						
						while( ! asked_blocks.empty() && go_on)
						{
							bool rcvd = true;
							message msg;
							std::tie(rcvd, msg) = p->expect("block", timeout);
							if ( ! rcvd)
							{
								this->missing_blocks.splice(this->missing_blocks.begin(), asked_blocks);
								my_peer_manager.return_peer(p);
								p = my_peer_manager.get_peer();
								if ( ! p)
									return;
							}
							else
							{
								Hash256 h = process_block_msg(msg);
								std::erase_if(asked_blocks, [&](const Hash256 & elm) { return h == elm; });
							}
						}
					}
				} catch(...) {
					PRINT_TRACE
				}
			});
		get_block_hashes_fiber.join();
		for (auto & f : get_blocks_fibers)
			if (f.joinable())
				f.join();
	}

	void process_inv_msg(const message & msg)
	{
		TRACE
		
		std::string_view data(msg.body.data(), msg.body.size());

		size_t ninv = consume_var_int(data);
		auto bc_proxy = bc.lock();
		for (size_t i=0 ; i<ninv ; i++)
		{
			std::uint32_t type = consume_little_endian<decltype(type)>(data);
			Hash256 h;
			consume_bytes(data, (char*)h.h, 32);
			switch(type)
			{
				case MSG_BLOCK:
					if ( ! bc_proxy->has(h))
						missing_blocks.push_back(h);
					break;
			}
		}
	}

	std::vector<std::tuple<block,Hash256>> process_headers_msg(const message & msg)
	{
		TRACE
		
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
	Hash256 process_block_msg(const message & msg)
	{
		TRACE
		
		block bl;
		Hash256 hash;

		try { 
			std::string_view data(msg.body.data(), msg.body.size());
			std::tie(bl, hash) = consume_header(data, false);
			verifier.add_candidate(std::string_view(msg.body.data(), msg.body.size()), hash);
			return hash;
		} catch (std::exception & e) {
			hash.zero();
			return hash;
		}
	}
};

} // namespace
 