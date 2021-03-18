
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
}

template<typename T>
T consume_low_endian(std::string_view & data)
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
void serialize_low_endian(unsigned char * data, T value)
{
	for (int i=0 ; i<sizeof(T) ; i++, value >>= 8)
		*data++ = value & 0xFF;
}
std::uint64_t consume_var_int(std::string_view & data)
{
	if (data.size() < 1)
		throw std::invalid_argument("data.size() < 1");
	unsigned char first = data[0];
	data.remove_prefix(1);
	if (first == 0xFF) {
		auto result = consume_low_endian<std::uint64_t>(data);
		return result;
	} else if (first == 0xFE) {
		auto result = consume_low_endian<std::uint32_t>(data);
		return result;
	} else if (first == 0xFD) {
		auto result = consume_low_endian<std::uint16_t>(data);
		return result;
	} else {
		return first;
	}
}
void consume_bytes(std::string_view & data, char *buf, size_t len)
{
	if (data.size() < len)
		throw std::invalid_argument("data.size() < 1");
	std::copy(data.data(), data.data()+len, buf);
	data.remove_prefix(len);
}

std::uint32_t calculate_checksum(unsigned char * data, size_t len)
{
	Hash256 hash;
	fill_dbl_sha256(hash, std::string_view((char*)data, len));
	std::string_view sv((char*)hash.h, 4);
	return consume_low_endian<std::uint32_t>(sv);
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

struct message
{
	char header[24];
	std::string body; // might use a custom allocator to avoid zero-init on resize() https://stackoverflow.com/questions/21028299/is-this-behavior-of-vectorresizesize-type-n-under-c11-and-boost-container/21028912#21028912

	std::uint32_t magic_number;
	std::string command;
	std::uint32_t len;
	std::uint32_t checksum;

	message() = default;
	message(std::string type)
	{
		serialize_low_endian((unsigned char*)header, testnet_magic_number);
		std::strncpy((char*)&header[4], type.data(), 12);
	}

	bool recv(boost::asio::ip::tcp::socket & socket, std::chrono::seconds timeout)
	{
		if ( ! recv_bytes(socket, boost::asio::buffer(header, 24), timeout))
			return false;
		
		std::string_view sv(header, 24);

		magic_number = consume_low_endian<decltype(magic_number)>(sv);
		for (char *ptr=&header[4] ; ptr<&header[16] && *ptr!=0 ; ++ptr)
			command.push_back(*ptr);
		sv.remove_prefix(12);
		len = consume_low_endian<decltype(len)>(sv);
		checksum = consume_low_endian<decltype(checksum)>(sv);

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
		header[16] = len & 0xFF;
		header[17] = (len >> 8) & 0xFF;
		header[18] = (len >> 16) & 0xFF;
		header[19] = (len >> 24) & 0xFF;
		Hash256 dblsha;
		fill_dbl_sha256(dblsha, std::string_view(body.data(), len));
		header[20] = dblsha[0];
		header[21] = dblsha[1];
		header[22] = dblsha[2];
		header[23] = dblsha[3];

		return send_bytes(socket, boost::asio::buffer((char*)header, 24), std::chrono::seconds(5))
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

	std::map<std::string, boost::fibers::promise<message>> expected_messages;

	boost::fibers::fiber this_fiber;

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
		this_fiber.join();
	}

	const config::peer & get_config() const { return peer_config; }

	void start()
	{
		this_fiber = boost::fibers::fiber([this](){ run(); });
	}

	void run()
	{
		if ( !connect())
			return;

		// handshake
		send_version_msg();
		auto handshake_fiber = boost::fibers::fiber([this](){
				handshaken = expect({"version","verack"}, std::chrono::seconds(5));
				error = ! handshaken;
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
		message m("version");
		unsigned char version_msg[] = {	  
			0x00, 0x00, 0x00, 0x00, // version field
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // services
			0x11, 0xb2, 0xd0, 0x50, 0x00, 0x00, 0x00, 0x00, // time
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x3b, 0x2e, 0xb3, 0x5d, 0x8c, 0xe6, 0x17, 0x65, // nonce
			0x0a, 0x6d, 0x79, 0x6e, 0x6f, 0x64, 0x65, 0x3a, 0x30, 0x2e, 0x30, // user agent mynode:0.0
			0x00, 0x00, 0x00, 0x00, // start_height
		};
		serialize_low_endian(version_msg, version);
		std::int64_t unix_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		serialize_low_endian(&version_msg[4+8], unix_time);
		serialize_low_endian(&version_msg[4+8+8+26+26], nonce);

		m.body.insert(m.body.end(), version_msg, version_msg+sizeof(version_msg));
		m.send(socket);

		std::cout << "sent " << m.len << " bytes of -version- to " << peer_config.ip << " " << peer_config.port << std::endl;
		//px((char*)header, 24);
		//px((char*)buf, len);
		//std::cout << std::endl;
	}

	bool expect(const std::vector<std::string> msg_types, std::chrono::seconds timeout)
	{
		for (const std::string & msg_type : msg_types)
		{
			//std::cout << "expecting " << msg_type << " " << peer_config.ip << "  " << peer_config.port << std::endl;
			expected_messages.emplace(msg_type,boost::fibers::promise<message>());
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
			auto timestamp = consume_low_endian<std::uint32_t>(sv);
			auto type      = consume_low_endian<std::uint64_t>(sv);
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
