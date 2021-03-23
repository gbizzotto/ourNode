
#pragma once

#include <algorithm>
#include <numeric>
#include <cstring>
#include <string>
#include <string_view>
#include <deque>
#include <vector>
#include <iostream>
#include <iomanip>
#include <type_traits>

inline void px(const std::string_view sv)
{
	for (auto s: sv)
		printf("%02x", (unsigned char)s);
}
inline void pxln(const std::string_view sv)
{
	for (auto s: sv)
		printf("%02x", (unsigned char)s);
	printf("\n");
}
template<typename O>
inline void px(O & o, const std::string_view sv)
{
	auto s = o.rdstate();
	for (auto s: sv)
		o << std::setw(2) << std::setfill('0') << std::hex << (unsigned(s)&0xff) << std::dec;
	o.setstate(s);
}
template<typename O>
inline void pxln(O & o, const std::string_view sv)
{
	auto s = o.rdstate();
	for (auto s: sv)
		o << std::setw(2) << std::setfill('0') << std::hex << (unsigned(s)&0xff) << std::dec;
	o << std::endl;
	o.setstate(s);
}

template< class T>
inline T ror( T v, unsigned int shift)
{
	auto lshift = sizeof(v)*8 - shift;
	return (v >> shift) | (v << lshift);
}
template< class T>
inline T rol( T v, unsigned int shift)
{
	auto rshift = sizeof(v)*8 - shift;
	return (v << shift) | (v >> rshift);
}


struct sha256_padding
{
	inline static const size_t min_size = 9;

	size_t padding_size;
	unsigned char padding[63+min_size];
	sha256_padding()
		: padding_size(min_size) // min size
	{
		padding[0] = 0x80;
		memset((char*)padding+1, 0, 63);
		//pxln(to_string_view());
	}
	sha256_padding(size_t s)
	{
		padding_size = 64 - (s%64);
		if (padding_size < min_size)
			padding_size += 64;

		padding[0] = 0x80;
		memset((char*)padding+1, 0, padding_size-min_size);

		// serialize size big endian
		s *= 8;
		unsigned char * ptr = &padding[padding_size-1];
		for (int i=0 ; i<8 ; i++,ptr--,s>>=8)
			*ptr = s & 0xFF;
	}
	void set_data_size(size_t s)
	{
		size_t new_padding_size = 64 - (s%64);
		if (new_padding_size < min_size)
			new_padding_size += 64;
		memset(padding+padding_size-8, 0, 8);
		padding_size = new_padding_size;
		// serialize size in bits, big endian
		s *= 8;
		unsigned char * ptr = &padding[padding_size-1];
		for (int i=0 ; i<8 ; i++,ptr--,s>>=8)
			*ptr = s & 0xFF;
	}
	std::string_view to_string_view() const
	{
		return std::string_view((char*)padding, padding_size);
	}
};

struct svistreamN
{
	std::deque<std::string_view> svs;
	size_t count;
	bool eof_;
	inline svistreamN(std::initializer_list<std::string_view> values)
		: svs(values)
		, eof_(false)
	{
		assert((std::accumulate(svs.begin(), svs.end(), 0, [](int x, const std::string_view & s) { return x+s.size(); }) % 64) == 0);
		//for (const auto & s: svs)
		//	px(s);
		//std::cout << std::endl;
	}
	bool eof() const { return eof_; }
	unsigned char get()
	{
		while ( ! svs.empty() && svs.front().empty())
			svs.pop_front();
		eof_ = svs.empty();
		if (eof())
			return 0;
		unsigned char c = (unsigned char) svs.front().front();
		svs.front().remove_prefix(1);
		//std::cout << std::hex << std::setfill('0') << std::setw(2) << ((unsigned int)c) << std::dec;
		return c;
	}
};

struct Hash256
{
	inline static const sha256_padding padding_for_sha256 = sha256_padding((size_t)32);

	union {
		uint32_t hash_hash;
		unsigned char h[32];
	};
	inline void zero() { memset(h, 0, 32); };
	bool operator==(const Hash256 & other) const {
		return memcmp(h, other.h, 32) == 0;
	}
	bool operator==(const unsigned char * other) const {
		return memcmp(h, other, 32) == 0;
	}
	inline unsigned char & operator[](size_t idx) {
		return h[idx & 31];
	}
	inline unsigned char   operator[](size_t idx) const {
		return h[idx & 31];
	}
	inline Hash256& operator=(const Hash256 & other) {
		std::copy(other.h, other.h+32, h);
		return *this;
	}
	std::string_view to_string_view() const {
		return std::string_view((char*)h, 32);
	}
};

Hash256 operator "" _littleendian_sha256(const char * literal)
{
	static char val[256] = {
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,1,2,3,4,5,6,7,8,9,
		0,0,0,0,0,0,0,
		10,11,12,13,14,15,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		10,11,12,13,14,15,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	};

	Hash256 result;
	int it = 0;
	for (const char *l=literal+2 ; *l!=0 && *(l+1)!=0 && it<32 ; ++it,++++l)
		result[it] = (val[*l]<<4) + val[*(l+1)];
	return result;
}
Hash256 operator "" _bigendian_sha256(const char * literal)
{
	auto result = operator ""_littleendian_sha256(literal);
	std::reverse(result.h, result.h+32);
	return result;
}

template<typename O>
O & operator<<(O & out, const Hash256 & hash)
{
	std::ios_base::fmtflags f(out.flags());
	for (int i=31 ; i>=0 ; i--)
		out << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i] << std::dec;
	out.flags(f);
	return out;
}

template<typename STREAM>
void fill_sha256(Hash256 & result, STREAM & reader)
{
	unsigned int k[64] =
	{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	unsigned int h0 = 0x6a09e667;
	unsigned int h1 = 0xbb67ae85;
	unsigned int h2 = 0x3c6ef372;
	unsigned int h3 = 0xa54ff53a;
	unsigned int h4 = 0x510e527f;
	unsigned int h5 = 0x9b05688c;
	unsigned int h6 = 0x1f83d9ab;
	unsigned int h7 = 0x5be0cd19;

	for (;;)
	{
		unsigned int w[64];
		//memset(w, 0, 64*4);
		for (int i=0 ; i<16 ; i++)
			w[i] = (reader.get() << 24) + (reader.get() << 16) + (reader.get() << 8) + reader.get();

		if (reader.eof())
			break;

		for (int i=16 ; i<64 ; i++)
		{
			unsigned int s0 = ror(w[i-15],  7) ^ ror(w[i-15], 18) ^ (w[i-15] >>  3);
			unsigned int s1 = ror(w[i- 2], 17) ^ ror(w[i- 2], 19) ^ (w[i- 2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}
		auto a = h0;
		auto b = h1;
		auto c = h2;
		auto d = h3;
		auto e = h4;
		auto f = h5;
		auto g = h6;
		auto h = h7;

		for (int i=0 ; i<64 ; i++)
		{
			unsigned int S1    = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
			unsigned int ch    = (e & f) ^ ((~e) & g);
			unsigned int temp1 = h + S1 + ch + k[i] + w[i];
			unsigned int S0    = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
			unsigned int maj   = (a & b) ^ (a & c) ^ (b & c);
			unsigned int temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}


		// Add the compressed chunk to the current hash value:
		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		h5 = h5 + f;
		h6 = h6 + g;
		h7 = h7 + h;
	}

	result[ 0] = (h0 >> 24) & 0xFF;
	result[ 1] = (h0 >> 16) & 0xFF;
	result[ 2] = (h0 >>  8) & 0xFF;
	result[ 3] = (h0 >>  0) & 0xFF;
	result[ 4] = (h1 >> 24) & 0xFF;
	result[ 5] = (h1 >> 16) & 0xFF;
	result[ 6] = (h1 >>  8) & 0xFF;
	result[ 7] = (h1 >>  0) & 0xFF;
	result[ 8] = (h2 >> 24) & 0xFF;
	result[ 9] = (h2 >> 16) & 0xFF;
	result[10] = (h2 >>  8) & 0xFF;
	result[11] = (h2 >>  0) & 0xFF;
	result[12] = (h3 >> 24) & 0xFF;
	result[13] = (h3 >> 16) & 0xFF;
	result[14] = (h3 >>  8) & 0xFF;
	result[15] = (h3 >>  0) & 0xFF;
	result[16] = (h4 >> 24) & 0xFF;
	result[17] = (h4 >> 16) & 0xFF;
	result[18] = (h4 >>  8) & 0xFF;
	result[19] = (h4 >>  0) & 0xFF;
	result[20] = (h5 >> 24) & 0xFF;
	result[21] = (h5 >> 16) & 0xFF;
	result[22] = (h5 >>  8) & 0xFF;
	result[23] = (h5 >>  0) & 0xFF;
	result[24] = (h6 >> 24) & 0xFF;
	result[25] = (h6 >> 16) & 0xFF;
	result[26] = (h6 >>  8) & 0xFF;
	result[27] = (h6 >>  0) & 0xFF;
	result[28] = (h7 >> 24) & 0xFF;
	result[29] = (h7 >> 16) & 0xFF;
	result[30] = (h7 >>  8) & 0xFF;
	result[31] = (h7 >>  0) & 0xFF;
}

void fill_dbl_sha256(Hash256 & h, std::string_view sv_)
{	
	thread_local sha256_padding padding;
	padding.set_data_size(sv_.size());

	svistreamN svi({sv_, padding.to_string_view()});
	fill_sha256(h, svi);
	//{
	//	std::cout << h << std::endl;
	//	svistreamN svi_tmp({h.to_string_view(), Hash256::padding_for_sha256.to_string_view()});
	//	for (;;)
	//	{
	//		unsigned c = svi_tmp.get();
	//		if (svi_tmp.eof())
	//			break;
	//		std::cout << std::hex << std::setfill('0') << std::setw(2) << (((unsigned int)c) & 0xFF) << std::dec;
	//	}
	//	std::cout << std::endl;
	//}
	svistreamN svi2({h.to_string_view(), Hash256::padding_for_sha256.to_string_view()});
	fill_sha256(h, svi2);
}

void fill_merkle_root(Hash256 & h, const Hash256 & left, const Hash256 & right)
{
	thread_local sha256_padding padding;
	padding.set_data_size(64);

	svistreamN sv1({left.to_string_view(), right.to_string_view(), padding.to_string_view()});
	fill_sha256(h, sv1);
	svistreamN sv2({h.to_string_view(), Hash256::padding_for_sha256.to_string_view()});
	fill_sha256(h, sv2);
}

void fill_merkle_root(Hash256 & mr, std::vector<Hash256> && tmp_hashes)
{
	if (tmp_hashes.size() == 1) {
		mr = tmp_hashes[0];
		return;
	} if (tmp_hashes.size() == 2) {
		return fill_merkle_root(mr, tmp_hashes[0], tmp_hashes[1]);
	}

	for (int i=0,j=0 ; i<tmp_hashes.size() ; i+=2,j++)
	{
		if (i == tmp_hashes.size()-1)
			fill_merkle_root(tmp_hashes[j], tmp_hashes[i], tmp_hashes[i]);
		else
			fill_merkle_root(tmp_hashes[j], tmp_hashes[i], tmp_hashes[i+1]);
	}
	tmp_hashes.resize((tmp_hashes.size()+1)/2);
	return fill_merkle_root(mr, std::move(tmp_hashes));
}
void fill_merkle_root(Hash256 & mr, const std::vector<std::reference_wrapper<const Hash256>> & hashes)
{
	if (hashes.size() == 1) {
		mr = hashes[0];
		return;
	} if (hashes.size() == 2) {
		return fill_merkle_root(mr, hashes[0], hashes[1]);
	}

	std::vector<Hash256> tmp_hashes;
	for (int i=0 ; i<hashes.size() ; i+=2)
	{
		tmp_hashes.emplace_back();
		if (i == hashes.size()-1)
			fill_merkle_root(tmp_hashes.back(), hashes[i], hashes[i]);
		else
			fill_merkle_root(tmp_hashes.back(), hashes[i], hashes[i+1]);
	}
	return fill_merkle_root(mr, std::move(tmp_hashes));
}
