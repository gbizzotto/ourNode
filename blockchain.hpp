
#pragma once

#include <vector>
#include <deque>
#include <memory>
#include <string_view>
#include <filesystem>
#include <fstream>
#include "sha256sum.hpp"
#include "misc.hpp"
#include "block_serialization.hpp"
#include "tx_serialization.hpp"

namespace ournode {

/*
struct tx_handle
{
	std::uint32_t block_height;
	std::uint16_t tx_idx;
	std::uint16_t output_idx;
};
*/
template<typename Persistence>
struct tx_hash_map
{
	using index_list = std::vector<uint32_t>;
	inline static const uint32_t none = uint32_t(-1);
	inline static Hash256 no_hash;

	int bits;
	std::deque<typename Persistence::index_block> tx_handles;
	index_list index_by_hash_hash;

	Persistence persistence;

	tx_hash_map()
		: bits(0xFFFF) // start with any 2^n-1
		, index_by_hash_hash((bits+1)*2, none)
	{
		no_hash.zero();
	}
	tx_hash_map(std::filesystem::path p)
		: bits(0xFFFF) // start with any 2^n-1
		, index_by_hash_hash((bits+1)*2, none)
		, persistence(p)
	{
		no_hash.zero();

		accomodate_new_size(persistence.size());
		persistence.get_tx_pib([&](const typename Persistence::persistent_index_block & pib)
			{
				index_by_hash_hash[index_slot(pib.hash)] = tx_handles.size();
				tx_handles.push_back(pib);
			});
	}

	inline size_t size() const { return tx_handles.size(); }

	//template<typename F>
	//void get_tx_raw_data(F callback)
	//{
	//	persistence.get_tx_raw_data(callback);
	//}

	inline std::uint32_t make_hash_index(std::uint32_t hash_hash) const
	{
		return (hash_hash & bits) *2;
	}

	inline void accomodate_new_size(size_t new_size)
	{
		bool resize = new_size > bits;
		if ( ! resize)
			return;
		while(new_size > bits)
			bits = bits*2 +1; // keep it 2^n-1
		index_by_hash_hash.clear();
		index_by_hash_hash.resize((bits+1)*2, none);
		int i = 0;
		for (const auto & handle : tx_handles)
			index_by_hash_hash[index_slot(handle.hash)] = i++;
	}
	
	inline void add_nocheck(std::vector<txout> outputs, const Hash256 & tx_hash)
	{
		typename Persistence::index_block ib = persistence.store(outputs, tx_hash);
		
		accomodate_new_size(size()+1);
		index_by_hash_hash[index_slot(tx_hash)] = tx_handles.size();
		tx_handles.push_back(ib);
	}

	inline std::uint32_t index_slot(std::uint32_t hash_idx) const
	{
		while(index_by_hash_hash[hash_idx] != none)
			hash_idx = (hash_idx+1) & bits;
		return hash_idx;
	}
	inline std::uint32_t index_slot(const Hash256 & tx_hash) const
	{
		return index_slot(make_hash_index(tx_hash.hash_hash));
	}
};


template<typename Persistence>
struct block_hash_map
{
	using index_list = std::vector<uint32_t>;
	inline static const uint32_t no_height = uint32_t(-1);
	inline static Hash256 no_hash;

	int bits;
	std::deque<typename Persistence::index_block> block_handles;
	index_list height_by_hash_idx;

	Persistence persistence;

	Hash256 last_known_hash;

	block_hash_map<memory_block_persistence>()
		: bits(0xFF) // start with any 2^n-1
		, height_by_hash_idx((bits+1)*2, no_height)
	{
		no_hash.zero();
		last_known_hash.zero();
	}
	block_hash_map<file_block_persistence>(std::filesystem::path p)
		: bits(0xFF) // start with any 2^n-1
		, height_by_hash_idx((bits+1)*2, no_height)
		, persistence(p)
	{
		no_hash.zero();
		last_known_hash.zero();

		accomodate_new_size(persistence.size());
		persistence.get_blocks_pib([&](const typename Persistence::persistent_index_block & pib)
			{
				height_by_hash_idx[index_slot(pib.hash)] = block_handles.size();
				block_handles.push_back(pib);
				last_known_hash = pib.hash;
			});
	}

	inline size_t size() const { return block_handles.size(); }
	inline uint32_t best_height() const { return block_handles.size()-1; }
	inline const typename Persistence::index_block & by_height_nocheck(uint32_t height) const { return block_handles[height]; }

	template<typename F>
	void get_blocks_raw_data(F callback)
	{
		persistence.get_blocks_raw_data(callback);
	}

	inline std::uint32_t make_hash_index(std::uint32_t hash_hash) const
	{
		return (hash_hash & bits) *2;
	}

	inline uint32_t height(const Hash256 & hash)
	{
		for (uint32_t hash_idx = make_hash_index(hash.hash_hash) ; height_by_hash_idx[hash_idx] != no_height ; hash_idx=(hash_idx+1)&bits)
			if (hash.hash_hash == persistence.get_hash_hash(block_handles[height_by_hash_idx[hash_idx]]))
				if (hash == persistence.get_hash(height_by_hash_idx[hash_idx]))
					return height_by_hash_idx[hash_idx];
		return no_height;
	}
	inline void add_nocheck(std::string_view block_data, const Hash256 & block_hash)
	{
		typename Persistence::index_block ib = persistence.store(block_data, block_hash);
		
		accomodate_new_size(size()+1);
		height_by_hash_idx[index_slot(block_hash)] = block_handles.size();
		block_handles.push_back(ib);
		last_known_hash = block_hash;
	}
	template<typename P>
	void merge_nocheck(block_hash_map<P> && other)
	{
		accomodate_new_size(size() + other.size());
		std::uint32_t i = 0;
		for (auto & handle : other.block_handles)
			add_nocheck(other.persistence.get_raw_data(handle), other.persistence.get_hash(i++));
	}
	inline void accomodate_new_size(size_t new_size)
	{
		bool resize = new_size > bits;
		if ( ! resize)
			return;
		while(new_size > bits)
			bits = bits*2 +1; // keep it 2^n-1
		//height_by_hash_idx = index_list((bits+1)*2, no_height);
		height_by_hash_idx.clear();
		height_by_hash_idx.resize((bits+1)*2, no_height);
		int i = 0;
		for (const auto & handle : block_handles)
			height_by_hash_idx[index_slot(make_hash_index(persistence.get_hash_hash(handle)))] = i++;
	}
	inline std::uint32_t index_slot(std::uint32_t hash_idx) const
	{
		while(height_by_hash_idx[hash_idx] != no_height)
			hash_idx = (hash_idx+1) & bits;
		return hash_idx;
	}
	inline std::uint32_t index_slot(const Hash256 & block_hash) const
	{
		return index_slot(make_hash_index(block_hash.hash_hash));
	}
	inline const Hash256 get_last_known_block_hash()
	{
		return last_known_hash;
	}
};


template<typename BlockPersistence, typename TxPersistence>
struct blockchain
{
	static inline const Hash256 testnet_genesis_block_hash = 0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943_bigendian_sha256;
	static inline const uint32_t no_height = -1;

	block_hash_map<BlockPersistence> root_chain;
	std::deque<std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>>> branches;
	std::deque<std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>>> orphan_chains;

	tx_hash_map<TxPersistence> root_chain_txs;

	Hash256 parent_block_hash;

	blockchain<memory_block_persistence, memory_tx_persistence>() {}
	blockchain<  file_block_persistence, memory_tx_persistence>(std::filesystem::path folder)
		: root_chain(folder)
		, root_chain_txs()
	{}

	template<typename F>
	void get_blocks_raw_data(F callback)
	{
		root_chain.get_blocks_raw_data(callback);
	}

	const Hash256 get_last_known_block_hash() { return root_chain.get_last_known_block_hash(); }
	inline uint32_t best_height() const { return root_chain.best_height(); }

	bool has(const Hash256 & hash)
	{
		return root_chain.height(hash) != no_height
		    || std::find_if(     branches.begin(),      branches.end(), [&hash](const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> & bcp) { return bcp->has(hash); }) != branches.end()
		    || std::find_if(orphan_chains.begin(), orphan_chains.end(), [&hash](const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> & bcp) { return bcp->has(hash); }) != orphan_chains.end()
		    ;
	}

	template<typename P>
	void check_vs_orphans(block_hash_map<P> & bhm)
	{
		auto it = orphan_chains.begin();
		while (it != orphan_chains.end())
		{
			auto & orphan = *it;
			if (orphan->parent_block_hash == bhm.get_last_known_block_hash())
			{
				if ( ! orphan->orphan_chains.empty())
					utttil::error() << "orphan shouldn't have orphans" << std::endl;
				//utttil::debug() << "bhm.merge_nocheck(std::move(orphan->root_chain));" << std::endl;
				//utttil::debug() << "orphan's parent: " << orphan->parent_block_hash << std::endl;
				//utttil::debug() << "orphan's first hash: " << orphan->root_chain.by_height_nocheck(0).hash << std::endl;
				//utttil::debug() << "bhm's last hash: " << bhm.get_last_known_block_hash() << std::endl;
				bhm.merge_nocheck(std::move(orphan->root_chain));
				for (auto & branch : orphan->branches)
					branches.push_back(std::move(branch));
				orphan_chains.erase(it);
				it = orphan_chains.begin();
				continue;
			}
			++it;
		}
	}

	void add(std::string_view block_data, const Hash256 & hash, const block & bl, bool is_orphan=false)
	{
		const Hash256 & prev_block_hash = bl.prev_block_hash;

		//utttil::debug() << "Trying to add block with prev_block_hash: " << prev_block_hash << std::endl;
		//utttil::debug() << "root_chain.get_last_known_block_hash(): " << root_chain.get_last_known_block_hash() << std::endl;
		//utttil::debug() << "root_chain.size(): " << root_chain.size() << std::endl;
		if (root_chain.size() == 0) {
			if (hash == testnet_genesis_block_hash || is_orphan) {
				this->parent_block_hash = prev_block_hash;
				//utttil::debug() << "size 0 root_chain.add_nocheck(block_data, hash);" << std::endl;
				root_chain.add_nocheck(block_data, hash);
				check_vs_orphans(root_chain);
				return;
			}
		}
		// check root chain tip
		if (root_chain.get_last_known_block_hash() == prev_block_hash) {
			//utttil::debug() << "root_chain.add_nocheck(block_data, hash);" << std::endl;
			root_chain.add_nocheck(block_data, hash);
			check_vs_orphans(root_chain);
			return;
		}
		// check branches tips
		for (auto & branch : branches)
			if (branch->get_last_known_block_hash() == prev_block_hash) {
				//utttil::debug() << "Added to an extra tip" << std::endl;
				branch->add(block_data, hash, bl);
				return;
			}
		// orphan chains tips
		for (auto & orphan_chain : orphan_chains)
			if (orphan_chain->get_last_known_block_hash() == prev_block_hash) {
				//utttil::debug() << "Added to orphan block chain" << std::endl;
				orphan_chain->add(block_data, hash, bl);
				return;
			}

		// root chain new branch?
		if (root_chain.height(prev_block_hash) != no_height) {
			//utttil::debug() << "Added as new extra tip line" << std::endl;
			branches.push_back(std::make_unique<blockchain<memory_block_persistence, memory_tx_persistence>>());
			branches.back()->add(block_data, hash, bl);
			return;
		}
		// branch branch?
		for (auto & branch : branches)
			if (branch->has(prev_block_hash)) {
				//utttil::debug() << "Added as new extra branch" << std::endl;
				branch->add(block_data, hash, bl);
				return;
			}
		// orphan chain new branch?
		for (auto & orphan : orphan_chains)
			if (orphan->has(prev_block_hash)) {
				//utttil::debug() << "Added as new extra branch" << std::endl;
				orphan->add(block_data, hash, bl);
				return;
			}

		//utttil::debug() << "Added as new orphan block line as orphan" << std::endl;
		auto new_orphan = std::make_unique<blockchain<memory_block_persistence, memory_tx_persistence>>();
		new_orphan->add(block_data, hash, bl, true);
		check_vs_orphans(new_orphan->root_chain);
		orphan_chains.emplace_back(std::move(new_orphan));
	}
	size_t size() const
	{
		return root_chain.size()
		     + std::accumulate(branches     .begin(), branches     .end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> & bhm) { return s + bhm->size(); })
		     + std::accumulate(orphan_chains.begin(), orphan_chains.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> & bhm) { return s + bhm->size(); })
			 ;
	}

	void print()
	{
		utttil::info() << "root chain " << root_chain.size() << std::endl;
		//for (auto & block : root_chain.blocks)
		//	utttil::info() << std::string(2*indent+2, ' ') << block.prev_block_hash << std::endl;
		//if (root_chain.size() != 0)
		//	utttil::info() << std::string(2*indent+2, ' ') << root_chain.get_last_known_block_hash() << std::endl;

		//utttil::info() << std::string(2*indent, ' ') << "branch chains:" << std::endl;
		//for (auto & branch : branches)
		//	branch->print(indent+1);
		//utttil::info() << std::string(2*indent, ' ') << "orphan chains:" << std::endl;
		//for (auto & orphan : orphan_chains)
		//	orphan->print(indent+1);
		utttil::info()
		    << std::accumulate(branches.begin(), branches.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> &bhm) { return s + bhm->size(); })
		    << " in " << branches.size() << " branched chains." << std::endl;
		utttil::info()
		    << std::accumulate(orphan_chains.begin(), orphan_chains.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain<memory_block_persistence, memory_tx_persistence>> &bhm) { return s + bhm->size(); })
		    << " in " << orphan_chains.size() << " orphan chains." << std::endl;
	}
};

} // namespace
