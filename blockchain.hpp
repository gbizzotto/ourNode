
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

	void merge_nocheck(block_hash_map & other)
	{
		while (size()+other.size() > bits)
			double_size();
		for (int i=0 ; i<other.blocks.size()-1 ; i++)
			index_by_hash_hash[index_slot(other.blocks[i], other.blocks[i+1].prev_block_hash)] = i;
		index_by_hash_hash[index_slot(other.blocks[other.blocks.size()-1], other.last_block_hash)] = other.blocks.size()-1;
	}

	inline size_t size() const { return blocks.size(); }
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
		if (size() > bits)
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
	std::deque<std::unique_ptr<blockchain>> branches;
	std::deque<std::unique_ptr<blockchain>> orphan_chains;
	
	const Hash256 & get_last_known_block_hash() const { return root_chain.get_last_known_block_hash(); }
	inline uint32_t best_height() const { return root_chain.best_height(); }

	bool has(const Hash256 & hash) const
	{
		return root_chain.height(hash) != no_height
		    || std::find_if(branches     .begin(), branches     .end(), [&hash](const std::unique_ptr<blockchain> & bcp){ return bcp->has(hash); }) != branches     .end()
		    || std::find_if(orphan_chains.begin(), orphan_chains.end(), [&hash](const std::unique_ptr<blockchain> & bcp){ return bcp->has(hash); }) != orphan_chains.end()
			;
	}

	void check_root_vs_orphans()
	{
		for (int i=0 ; i<orphan_chains.size() ; i++)
		{
			auto & orphan = orphan_chains[i];
			if (orphan->root_chain.by_height_nocheck(0).prev_block_hash == root_chain.get_last_known_block_hash())
			{
				if ( ! orphan->orphan_chains.empty())
					std::cout << "orphan shouldn't have orphans" << std::endl;
				root_chain.merge_nocheck(orphan->root_chain);
				for (auto & branch : orphan->branches)
					branches.push_back(std::move(branch));
				orphan_chains.erase(std::next(orphan_chains.begin(), i));
				return check_root_vs_orphans();
			}
		}
	}

	void add(block && bl, const Hash256 & hash, bool is_orphan=false)
	{
		Hash256 & prev_block_hash = bl.prev_block_hash;

		std::cout << "root_chain.size(): " << root_chain.size() << std::endl;
		if (root_chain.size() == 0)
		{
			if (hash == testnet_genesis_block_hash || is_orphan)
			{
				root_chain.add_nocheck(std::move(bl), hash);
				return;
			}
			else
			{
				std::cout << "Added as new orphan block line" << std::endl;
				orphan_chains.push_back(std::make_unique<blockchain>());
				orphan_chains.back()->add(std::move(bl), hash);
				return;
			}
		}
		// check root chain tip
		if (root_chain.get_last_known_block_hash() == prev_block_hash) {
			std::cout << "Added to root chain" << std::endl;
			root_chain.add_nocheck(std::move(bl), hash);
			check_root_vs_orphans();
			return;
		}
		// check branches tips
		for (auto & branch : branches)
			if (branch->get_last_known_block_hash() == prev_block_hash) {
				std::cout << "Added to an extra tip" << std::endl;
				branch->add(std::move(bl), hash);
				return;
			}
		// orphan chains tips
		for (auto & orphan_chain : orphan_chains)
			if (orphan_chain->get_last_known_block_hash() == prev_block_hash) {
				std::cout << "Added to orphan block chain" << std::endl;
				orphan_chain->add(std::move(bl), hash);
				return;
			}

		// root chain new branch?
		if (root_chain.height(prev_block_hash) != no_height) {
			std::cout << "Added as new extra tip line" << std::endl;
			branches.push_back(std::make_unique<blockchain>());
			branches.back()->add(std::move(bl), hash);;
			return;
		}
		// branch branch?
		for (auto & branch : branches)
			if (branch->has(prev_block_hash)) {
				std::cout << "Added as new extra branch" << std::endl;
				branch->add(std::move(bl), hash);
				return;
			}
		// orphan chain new branch?
		for (auto & orphan : orphan_chains)
			if (orphan->has(prev_block_hash)) {
				std::cout << "Added as new extra branch" << std::endl;
				orphan->add(std::move(bl), hash);
				return;
			}
		
		std::cout << "Added as new orphan block line as orphan" << std::endl;
		orphan_chains.push_back(std::make_unique<blockchain>());
		orphan_chains.back()->add(std::move(bl), hash, true);
	}
	size_t size()
	{
		return root_chain.size()
		     + std::accumulate(branches     .begin(), branches     .end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> & bhm){ return s+bhm->size(); })
			 + std::accumulate(orphan_chains.begin(), orphan_chains.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> & bhm){ return s+bhm->size(); })
			 ;
	}
};

} // namespace
