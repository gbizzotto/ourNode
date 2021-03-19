
#pragma once

#include <cstring>
#include <string>
#include <string_view>
#include <iostream>
#include <iomanip>
#include <type_traits>

struct Hash256
{
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
		memcpy(h, other.h, 32);
		return *this;
	}
};

Hash256 operator "" _bigendian_sha256(const char * literal)
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

template<typename O>
O & operator<<(O & out, const Hash256 & hash)
{
	std::ios_base::fmtflags f(out.flags());
	for (int i=0 ; i<32 ; i++)
		out << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
	out.flags(f);
	return out;
}


template<typename STREAM>
struct SHA256PaddingStream
{
	STREAM & in;
	size_t count;
	size_t size;
	inline SHA256PaddingStream(STREAM & i)
		: in(i)
		, count(0)
		, size(0)
	{}
	inline bool eof() const { return count > size && (count%64) == 0; }
	inline unsigned char next()
	{
		if ( ! in.eof())
		{
			unsigned char b = in.get();
			if ( ! in.eof())
			{
				size++;
				count++;
				return (unsigned char)b;
			}
		}
		
		if (size == count) {
			count++;
			return 0x80;
		}
		
		if (((size+1+8) % 64) < 8 && count-size < 8) {
			count++;
			return 0;
		}
		if (((count+8) % 64) >= 8) {
			count++;
			return 0;
		}
		count++;
		return ((size*8) >> (8*(64-count))) & 0xFF;
	}
};

struct svistream
{
	const std::string_view sv;
	size_t count;
	bool eof_;
	inline svistream(const std::string & str)
		: sv(str)
		, count(0)
		, eof_(false)
	{}
	inline svistream(const std::string_view sv_)
		: sv(sv_)
		, count(0)
		, eof_(false)
	{}
	bool eof() const { return eof_; }
	unsigned char get()
	{
		eof_ = count == sv.size();
		if (eof())
			return 0;
		else
			return (sv[count++] & 0xFF);
	}
};


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

template<typename STREAM>
void fill_sha256(Hash256 & result, STREAM & s)
{
	SHA256PaddingStream reader(s);
	
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
		if (reader.eof())
			break;

		unsigned int w[64];
		memset(w, 0, 64*4);
		for (int i=0 ; i<16 ; i++)
			w[i] = (reader.next() << 24) + (reader.next() << 16) + (reader.next() << 8) + reader.next();

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
	svistream sv(sv_);
	fill_sha256(h, sv);
	svistream sv2(std::string_view((char*)h.h, 32));
	fill_sha256(h, sv2);
}
