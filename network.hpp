
#pragma once

#include <cstring>
#include <boost/asio.hpp>
#include <boost/fiber/all.hpp>
#include "round_robin.hpp"
#include "yield.hpp"

#include "synchronized.hpp"
#include "sha256sum.hpp"

namespace ournode {


inline void px(const std::string_view sv)
{
	for (auto s: sv)
		printf("%02x", (unsigned char)s);
	printf("\n");
}

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
	std::string_view sv((char*)hash.h, 4);
	return consume_little_endian<std::uint32_t>(sv);
}

bool recv_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::mutable_buffer buffer, std::chrono::seconds timeout)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());
	
	boost::asio::async_read(socket, buffer, 
		[promise=std::move(promise)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	if (future.wait_for(timeout) != boost::fibers::future_status::ready)
		return false;
	return future.get();
}
bool send_bytes(boost::asio::ip::tcp::socket & socket, boost::asio::const_buffer buffer, std::chrono::seconds timeout)
{
	boost::fibers::promise<bool> promise;
	boost::fibers::future<bool> future(promise.get_future());
	
	//px({buf.get(), buffer.size()});
	//std::cout << std::endl;

	socket.async_send(buffer, [promise=std::move(promise)](const boost::system::error_code & ec, std::size_t bytes_transferred) mutable {
			promise.set_value(!ec);
		});
	if (future.wait_for(timeout) != boost::fibers::future_status::ready)
		return false;
	return future.get();
}

inline static const unsigned int testnet_magic_number = 0x0709110b;
inline static const unsigned int version              = 0x00011180;
inline static const char user_agent[] = "ourNode:0.0";

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
		serialize_little_endian((unsigned char*)header, testnet_magic_number);
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
	void append_str(const char b[], size_t N)
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

		if (magic_number != testnet_magic_number) {
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
			std::cout << "Bad checksum" << std::endl;

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
		std::cout << "peer dies." << std::endl;
	}

	const config::peer & get_config() const { return peer_config; }

	void start()
	{
		boost::fibers::fiber([this](){ run(); std::cout << "fiber ends." << std::endl; }).detach();
	}

	void run()
	{
		if ( !connect())
			return;

		// handshake
		handshake_fiber = boost::fibers::fiber(boost::fibers::launch::dispatch,
			[this](){
				send_version_msg();
				handshaken = expect({"version","verack"}, std::chrono::seconds(5));
				error &= ! handshaken;
				if (handshaken) {
					std::cout << "Connected to " << peer_config.ip << " " << peer_config.port << std::endl;
					message("getaddr").send(socket);
				} else {
					std::cout << "Coudln't connect to " << peer_config.ip << " " << peer_config.port << std::endl;
				}
			});

		while( ! error) {
			const message m = recv_msg();
			if (error) break;
			handle_msg(m);
		}
	}

	bool connect()
	{
		boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address(peer_config.ip), peer_config.port);
		
		boost::fibers::promise<bool> promise;
		boost::fibers::future<bool> future(promise.get_future());
		
		std::cout << "Trying " << peer_config.ip << " " << peer_config.port << std::endl;
		socket.async_connect(endpoint, [promise=std::move(promise)](boost::system::error_code ec) mutable {
				promise.set_value(!ec);
			});
		if (future.wait_for(std::chrono::seconds(5)) != boost::fibers::future_status::ready) {
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
		size_t services = 0;
		std::int64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		unsigned char ipv6[26] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		int32_t start_height = 0;

		message m("version");
		m.append_little_endian(version);
		m.append_little_endian(services);
		m.append_little_endian(unix_time);
		m.append_bytes(ipv6, sizeof(ipv6));
		m.append_bytes(ipv6, sizeof(ipv6));
		m.append_little_endian(nonce);
		m.append_str(user_agent, sizeof(user_agent));
		m.append_little_endian(start_height);

		m.send(socket);

		std::cout << "sent " << m.len << " bytes of -version- to " << peer_config.ip << " " << peer_config.port << std::endl;
		px({(char*)m.header, 24});
		//px((char*)buf, len);
		//std::cout << std::endl;
	}

	bool expect(const std::vector<std::string> msg_types, std::chrono::seconds timeout)
	{
		for (const std::string & msg_type : msg_types)
		{
			std::cout << "expecting " << msg_type << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			expected_messages.emplace(msg_type,boost::fibers::promise<message>());
		}
		bool got_all = true;
		auto deadline = std::chrono::system_clock::now() + timeout;
		for (const std::string & msg_type : msg_types)
		{
			std::cout << "Now waiting for " << msg_type << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			bool got_this_one = expected_messages[msg_type].get_future().wait_until(deadline) == boost::fibers::future_status::ready;
			std::cout << "Got " << msg_type << " ? " << got_this_one << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			got_all &= got_this_one;
			expected_messages.erase(msg_type);
		}
		std::cout << "expect fulfilled " << peer_config.ip << "  " << peer_config.port << std::endl;
		return got_all;
	}

	const message recv_msg()
	{
		message result;
		error = ! result.recv(this->socket, std::chrono::seconds(600));
		std::cout << "recvd " << result.len << " bytes of " << result.command << " from " << peer_config.ip << "  " << peer_config.port << std::endl;
		return result;
	}

	void handle_msg(const message & m)
	{
		auto it = expected_messages.find(m.command);
		if (it != expected_messages.end())
			it->second.set_value(m);
		
		if (m.command == "version")
			message("verack").send(socket);
		else if (m.command == "addr")
			process_addr_msg(m);
		else if (m.command == "reject")
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

		//else if (std::strcmp(&header[4], "headers") == 0)
		//	process_headers_msg(std::string_view(body.get(), len));
		//else if (std::strcmp(&header[4], "inv") == 0)
		//	process_inv_msg(std::string_view(buf, len));
		//else if (std::strcmp(&header[4], "block") == 0)
		//	process_block_msg(std::string_view(buf, len));
	}

	void process_addr_msg(const message & m)
	{
		std::string_view sv(m.body.data(), m.len);

		auto naddr = consume_var_int(sv);
		std::set<std::tuple<std::string,int>> known_peers_addresses;

		for (int i=0 ; i<naddr ; i++)
		{
			auto timestamp = consume_little_endian<std::uint32_t>(sv);
			auto type      = consume_little_endian<std::uint64_t>(sv);
			std::array<unsigned char, 16> ipv6;
			consume_bytes(sv, (char*)&ipv6[0], 16);

			std::string ip = [&ipv6]() ->std::string
				{
					bool ten_zeroes = std::find_if(&ipv6[0], &ipv6[10], [](unsigned char c) { return c!=0; }) >= &ipv6[10];
					if (ten_zeroes) {
						std::string_view sv((char*)&ipv6[12], 4);
						return boost::asio::ip::address_v4(consume_big_endian<unsigned int>(sv)).to_string();
					} else {
						return boost::asio::ip::address_v6(ipv6).to_string();
					}
				}();
			int port = consume_big_endian<std::uint16_t>(sv);
			//std::cout << "Got peer? " << ip << "  " << port << std::endl;
			known_peers_addresses.insert({ip, port});
		}

		{
			auto conf_proxy = conf.lock();
			for (const auto & t : known_peers_addresses)
				conf_proxy->add_known_peer_address(std::get<0>(t), std::get<1>(t));
		}
	}
};

struct network
{
	utttil::synchronized<ournode::config> & conf;

	std::shared_ptr<boost::asio::io_context> io_context;
	boost::fibers::fiber keep_well_connected_fiber;
	boost::fibers::fiber keep_up_to_date_fiber;

	std::vector<std::shared_ptr<peer>> handshaken_peers;
	bool error;

	network(utttil::synchronized<ournode::config> & conf_)
		: conf(conf_)
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
						std::cout << "Rejecting " << p->get_config().ip << " " << p->get_config().port << std::endl;
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
			std::cout << "Handshaken with " << handshaken_peers.size() << std::endl;
		}
	}
	void keep_up_to_date()
	{
		while (handshaken_peers.empty())
			boost::this_fiber::sleep_for(std::chrono::milliseconds(1));
		

	}
};

} // namespace
