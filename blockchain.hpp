
#pragma once

#include <vector>
#include <deque>
#include <memory>
#include <string_view>
#include "sha256sum.hpp"

namespace ournode {

struct txin
{
	Hash256 txid;
	std::uint32_t idx;
	std::uint32_t script_size;
	std::shared_ptr<unsigned char> scriptsig;
	std::uint32_t sequence;
};
struct txout
{
	int64_t amount;
	std::uint32_t script_size;
	std::shared_ptr<unsigned char> scriptpubkey;
};
struct transaction
{
	bool has_witness = false;
	std::vector<txin> inputs;
	std::vector<txout> outputs;
	std::uint32_t locktime;
};
struct block
{
	// all 6 fields required to calculate the block's hash
	std::int32_t  version;
	Hash256 prev_block_hash;
	Hash256 merkle_root;
	std::uint32_t timestamp;
	std::uint32_t difficulty;
	std::uint32_t nonce;
	std::vector<transaction> txs;
};

template<typename O>
O & operator<<(O & out, const transaction & tx)
{
	out << "vin: " << std::endl;
	for (int i=0 ; i<tx.inputs.size() ; i++)
	{
				out << "  txid: ";
				pxln(out, std::string_view((char*)tx.inputs[i].txid.h, 32));
				out << "  idx: " << tx.inputs[i].idx << std::endl;
				out << "  scriptsig: ";
				px(out, std::string_view((char*)tx.inputs[i].scriptsig.get(), tx.inputs[i].script_size));
				out << std::endl;
				out << "  scriptsig: ";
				for (unsigned char *ptr=tx.inputs[i].scriptsig.get(),*end=ptr+tx.inputs[i].script_size ; ptr<end ; )
				{
					if (*ptr == 0 || *ptr>75) {
						printf("%02X ", *ptr);
						ptr++;
					} else {
						px(out, std::string_view((char*)ptr+1, *ptr));
						out << " ";
						ptr += *ptr + 1;
					}
				}
				out << std::endl;
				out << "  sequence: " << std::hex << tx.inputs[i].sequence << std::dec << std::endl;
	}
	out << "vout: " << std::endl;
	for (int i=0 ; i<tx.outputs.size() ; i++)
	{
				out << "  amount: " << tx.outputs[i].amount << std::endl;
				out << "  scriptpubkey: ";
				px(out, std::string_view((char*)tx.outputs[i].scriptpubkey.get(), tx.outputs[i].script_size));
				out << std::endl;
				out << "  scriptpubkey: ";
				for (unsigned char *ptr=tx.outputs[i].scriptpubkey.get(),*end=ptr+tx.outputs[i].script_size ; ptr<end ; )
				{
					if (*ptr == 0 || *ptr>75) {
						printf("%02X ", *ptr);
						ptr++;
					} else {
						px(out, std::string_view((char*)ptr+1, *ptr));
						out << " ";
						ptr += *ptr + 1;
					}
				}
				out << std::endl;
	}
	return out;
}


struct block_hash_map
{
	using index_list = std::vector<uint32_t>;
	int bits;
	inline static const uint32_t no_height = uint32_t(-1);

	std::deque<block> blocks;
	index_list index_by_hash_hash;

	Hash256 last_block_hash;

	block_hash_map()
		: bits(0xFF)
		, index_by_hash_hash((bits+1)*2, no_height)
	{
		last_block_hash.zero();
	}

	inline uint32_t best_height() const { return blocks.size()-1; }
	inline const block & by_height_nocheck(uint32_t height) const { return blocks[height]; }

	inline uint32_t height(const Hash256 & hash) const
	{
		for (uint32_t hash_hash = (hash.hash_hash & bits) *2 ; index_by_hash_hash[hash_hash] != no_height ; hash_hash=(hash_hash+1)&bits)
		{
			if (index_by_hash_hash[hash_hash] == best_height())
			{
				if (hash == last_block_hash)
					return index_by_hash_hash[hash_hash];
			}
			else if (hash == blocks[index_by_hash_hash[hash_hash]+1].prev_block_hash)
				return index_by_hash_hash[hash_hash];
		}
		return no_height;
	}
	inline void add_nocheck(block && b, const Hash256 & block_hash)
	{
		if (best_height() != no_height && best_height() > bits)
			double_size();
		index_by_hash_hash[index_slot(b, block_hash)] = blocks.size();
		blocks.push_back(std::move(b));
		last_block_hash = block_hash;
	}
	inline void double_size()
	{
		bits = bits*2 + 1;
		index_by_hash_hash = index_list((bits+1)*2, no_height);
		for (int i=0 ; i<blocks.size()-1 ; i++)
			index_by_hash_hash[index_slot(blocks[i], blocks[i+1].prev_block_hash)] = i;
		index_by_hash_hash[index_slot(blocks[blocks.size()-1], last_block_hash)] = blocks.size()-1;
	}
	std::uint32_t index_slot(const block & b, const Hash256 & block_hash) const
	{
		uint32_t hash_hash = (block_hash.hash_hash & bits)*2;
		while (index_by_hash_hash[hash_hash] != no_height)
			hash_hash = (hash_hash+1) & bits;
		return hash_hash;
	}
	const Hash256 & get_last_known_block_hash() const { return last_block_hash; }
};

struct blockchain
{
	static inline const Hash256 testnet_genesis_block_hash = 0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943_bigendian_sha256;
	//static inline const Hash256 testnet_genesis_block_hash = 0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105_bigendian_sha256;
	inline static const uint32_t no_height = block_hash_map::no_height;

	block_hash_map root_chain;
	std::deque<block_hash_map> extra_tips;
	
	const Hash256 & get_last_known_block_hash() const { return root_chain.get_last_known_block_hash(); }
	inline uint32_t best_height() const { return root_chain.best_height(); }

	bool has(const Hash256 & hash) const
	{
		return root_chain.height(hash) != no_height;
	}

	bool add(block && bl, const Hash256 & hash)
	{
		if (root_chain.get_last_known_block_hash() != bl.prev_block_hash) {
			std::cout << "NO root_chain.get_last_known_block_hash(): " << root_chain.get_last_known_block_hash()
			          << ", hash: " << hash
					  << ", bl.prev_hash: " << bl.prev_block_hash << std::endl;
			return false;
		}
		root_chain.add_nocheck(std::move(bl), hash);
		return true;
	}
};

} // namespace
