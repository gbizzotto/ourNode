
#pragma once

#include <vector>
#include <deque>
#include <memory>
#include <string_view>
#include <filesystem>
#include <fstream>
#include "sha256sum.hpp"
#include "misc.hpp"

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

struct block_handle
{
	Hash256 hash;
	std::uint32_t file_number;
	std::uint32_t offset;
	std::string block_data;

	block get_block()
	{
		block bl;
		// TODO read from file
		return bl;
	}
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
		for (unsigned char *ptr = tx.inputs[i].scriptsig.get(), *end = ptr + tx.inputs[i].script_size; ptr < end;)
		{
			if (*ptr == 0 || *ptr > 75)
			{
				printf("%02X ", *ptr);
				ptr++;
			}
			else
			{
				px(out, std::string_view((char*)ptr + 1, *ptr));
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
		for (unsigned char *ptr = tx.outputs[i].scriptpubkey.get(), *end = ptr + tx.outputs[i].script_size; ptr < end;)
		{
			if (*ptr == 0 || *ptr > 75)
			{
				printf("%02X ", *ptr);
				ptr++;
			}
			else
			{
				px(out, std::string_view((char*)ptr + 1, *ptr));
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

	std::deque<block_handle> block_handles;
	index_list index_by_hash_hash;

	std::filesystem::path folder;

	std::ofstream foutdata;
	std::uint32_t file_number=0;
	std::ofstream foutindex;

	static inline Hash256 no_hash;

	block_hash_map()
		: bits(0xFF) // start with any 2^n-1
		, index_by_hash_hash((bits+1)*2, no_height)
	{
		no_hash.zero();
	}

	void load(std::filesystem::path p)
	{
		folder = p;
		std::filesystem::create_directory(folder);
		
		auto index_path = folder / "index";
		if (std::filesystem::exists(index_path))
		{
			auto index_entries_count = std::filesystem::file_size(index_path) / (32+4+4);
			accomodate_new_size(index_entries_count);

			std::ifstream fin(index_path, std::ios_base::in | std::ios_base::binary);
			for (;;)
			{
				block_handle handle;
				consume_bytes(fin, (char*)handle.hash.h, 32);
				if (fin.eof())
					break;
				handle.file_number = consume_little_endian<decltype(handle.file_number)>(fin);
				handle.offset      = consume_little_endian<decltype(handle.offset     )>(fin);
				if (fin.eof())
					break;
				this->add_nocheck(handle, false);
				file_number = handle.file_number;
			}
			fin.close();
			std::cout << "Resuming from block height: " << best_height() << ' ' << get_last_known_block_hash() << std::endl;
		}
		foutindex.open(index_path, std::ios_base::app | std::ios_base::binary);
		foutdata.open(folder / std::to_string(file_number), std::ios_base::app | std::ios_base::binary);
	}
	block_handle write_block_data(std::string_view sv, const Hash256 & block_hash)
	{
		block_handle result;
		result.hash = block_hash;

		// determine file and offset
		fill_file_pos(result);

		// write at file+offset
		serialize_little_endian(foutdata, (std::uint32_t)sv.size());
		serialize_bytes(foutdata, (char*)sv.data(), sv.size());

		write_index(result);

		return result;
	}
	block_handle copy_block_data(std::string_view sv, const Hash256 & block_hash)
	{
		block_handle result;
		result.hash = block_hash;
		result.block_data = sv;
		result.file_number = 0;
		result.offset      = 0;
		return result;
	}
	void write(block_handle & handle)
	{
		fill_file_pos(handle);

		// write at file+offset
		serialize_little_endian(foutdata, (std::uint32_t)handle.block_data.size());
		serialize_bytes(foutdata, (char*)handle.block_data.data(), handle.block_data.size());
		handle.block_data = std::string();

		write_index(handle);
	}
	void fill_file_pos(block_handle & handle)
	{
		// determine file and offset
		if (block_handles.empty()) {
			handle.file_number = 0;
			handle.offset      = 0;
		} else {
			std::filesystem::path file_path = folder / std::to_string(file_number);
			auto file_size = std::filesystem::file_size(file_path);
			if (file_size > 4'000'000'000ull) {
				file_number++;
				handle.file_number = file_number;
				handle.offset      = 0;
				foutdata.close();
				foutdata.open(folder / std::to_string(file_number), std::ios_base::app | std::ios_base::binary);
			} else {
				handle.file_number = file_number;
				handle.offset      = file_size;
			}
		}
	}
	void write_index(block_handle & handle)
	{
		auto index_path = folder / "index";
		serialize_bytes(foutindex, (char*)handle.hash.h, 32);
		serialize_little_endian(foutindex, handle.file_number);
		serialize_little_endian(foutindex, handle.offset);
	}

	template <typename F>
	void get_raw_block_headers(F callback) const
	{
		std::ifstream fin;
		int file_name = -1;
		for (const block_handle & bh : block_handles)
		{
			if (file_name != bh.file_number)
			{
				auto new_file_name = folder / std::to_string(bh.file_number);
				if ( ! std::filesystem::exists(new_file_name))
					return;
				fin.close();
				fin.open(new_file_name, std::ios_base::in | std::ios_base::binary);
				file_name = bh.file_number;
			}
			if (fin.eof())
				return;
			fin.seekg(bh.offset);
			char buffer[81];
			consume_little_endian<std::uint32_t>(fin);
			consume_bytes(fin, buffer, 81);
			if ( ! callback(std::string_view(buffer, 81)))
				break;
		}
	}

	void merge_nocheck(block_hash_map && other)
	{
		accomodate_new_size(size() + other.size());
		for (auto & handle : other.block_handles)
			add_nocheck(handle, true);
	}

	inline size_t size() const { return block_handles.size(); }
	inline uint32_t best_height() const { return block_handles.size()-1; }
	inline const block_handle & by_height_nocheck(uint32_t height) const { return block_handles[height]; }

	inline uint32_t height(const Hash256 & hash) const
	{
		for (uint32_t hash_hash = (hash.hash_hash & bits) *2 ; index_by_hash_hash[hash_hash] != no_height ; hash_hash=(hash_hash+1)&bits)
			if (hash == block_handles[index_by_hash_hash[hash_hash]].hash)
				return index_by_hash_hash[hash_hash];
		return no_height;
	}
	inline void add_nocheck(std::string_view block_data, const Hash256 & block_hash)
	{
		block_handle handle = [&](bool write) {
				if (write) return write_block_data(block_data, block_hash);
				else       return  copy_block_data(block_data, block_hash);
			}( ! folder.empty());

		accomodate_new_size(size()+1);
		index_by_hash_hash[index_slot(block_hash)] = block_handles.size();
		block_handles.push_back(std::move(handle));
	}
	inline void add_nocheck(block_handle & handle, bool write_to_persistent_memory)
	{
		if (write_to_persistent_memory && ! folder.empty()) {
			write(handle);
			handle.block_data = std::string(); // was cached in a branch or an orphan, now it's on disk
		}

		accomodate_new_size(size()+1);
		index_by_hash_hash[index_slot(handle.hash)] = block_handles.size();
		block_handles.push_back(std::move(handle));
	}
	inline void accomodate_new_size(size_t new_size)
	{
		bool resize = new_size > bits;
		if ( ! resize)
			return;
		while(new_size > bits)
			bits = bits*2 +1; // keep it 2^n-1
		//index_by_hash_hash = index_list((bits+1)*2, no_height);
		index_by_hash_hash.clear();
		index_by_hash_hash.resize((bits+1)*2, no_height);
		int i = 0;
		for (const auto & handle : block_handles)
			index_by_hash_hash[index_slot(handle.hash)] = i++;
	}
	std::uint32_t index_slot(const Hash256 & block_hash) const
	{
		uint32_t hash_hash = (block_hash.hash_hash & bits)*2;
		while(index_by_hash_hash[hash_hash] != no_height)
			hash_hash = (hash_hash+1) & bits;
		return hash_hash;
	}
	const Hash256 & get_last_known_block_hash() const
	{
		if (block_handles.empty())
			return no_hash;
		else
			return block_handles.back().hash;
	}
};

struct blockchain
{
	static inline const Hash256 testnet_genesis_block_hash = 0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943_bigendian_sha256;
	//static inline const Hash256 testnet_genesis_block_hash = 0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105_bigendian_sha256;
	static inline const uint32_t no_height = block_hash_map::no_height;

	block_hash_map root_chain;
	std::deque<std::unique_ptr<blockchain>> branches;
	std::deque<std::unique_ptr<blockchain>> orphan_chains;

	Hash256 parent_block_hash;

	void load(std::filesystem::path folder)
	{
		root_chain.load(folder);
	}
	template <typename F>
	void get_raw_block_headers(F callback) const
	{
		root_chain.get_raw_block_headers(callback);
	}

	const Hash256 & get_last_known_block_hash() const { return root_chain.get_last_known_block_hash(); }
	inline uint32_t best_height() const { return root_chain.best_height(); }

	bool has(const Hash256 & hash) const
	{
		return root_chain.height(hash) != no_height
		    || std::find_if(branches.begin(), branches.end(), [&hash](const std::unique_ptr<blockchain> & bcp) { return bcp->has(hash); }) != branches.end()
		    || std::find_if(orphan_chains.begin(), orphan_chains.end(), [&hash](const std::unique_ptr<blockchain> & bcp) { return bcp->has(hash); }) != orphan_chains.end()
		    ;
	}

	void check_vs_orphans(block_hash_map & bhm)
	{
		auto it = orphan_chains.begin();
		while (it != orphan_chains.end())
		{
			auto & orphan = *it;
			if (orphan->parent_block_hash == bhm.get_last_known_block_hash())
			{
				if ( ! orphan->orphan_chains.empty())
					std::cout << "orphan shouldn't have orphans" << std::endl;
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

	void add(std::string_view block_data, const Hash256 & hash, const Hash256 & prev_block_hash, bool is_orphan=false)
	{
		//std::cout << "root_chain.size(): " << root_chain.size() << std::endl;
		if (root_chain.size() == 0) {
			if (hash == testnet_genesis_block_hash || is_orphan) {
				this->parent_block_hash = prev_block_hash;
				root_chain.add_nocheck(block_data, hash);
				check_vs_orphans(root_chain);
				return;
			}
		}
		// check root chain tip
		if (root_chain.get_last_known_block_hash() == prev_block_hash) {
			//std::cout << "Added to root chain" << std::endl;
			root_chain.add_nocheck(block_data, hash);
			check_vs_orphans(root_chain);
			return;
		}
		// check branches tips
		for (auto & branch : branches)
			if (branch->get_last_known_block_hash() == prev_block_hash) {
				//std::cout << "Added to an extra tip" << std::endl;
				branch->add(block_data, hash, prev_block_hash);
				return;
			}
		// orphan chains tips
		for (auto & orphan_chain : orphan_chains)
			if (orphan_chain->get_last_known_block_hash() == prev_block_hash) {
				//std::cout << "Added to orphan block chain" << std::endl;
				orphan_chain->add(block_data, hash, prev_block_hash);
				return;
			}

		// root chain new branch?
		if (root_chain.height(prev_block_hash) != no_height) {
			//std::cout << "Added as new extra tip line" << std::endl;
			branches.push_back(std::make_unique<blockchain>());
			branches.back()->add(block_data, hash, prev_block_hash);
			return;
		}
		// branch branch?
		for (auto & branch : branches)
			if (branch->has(prev_block_hash)) {
				//std::cout << "Added as new extra branch" << std::endl;
				branch->add(block_data, hash, prev_block_hash);
				return;
			}
		// orphan chain new branch?
		for (auto & orphan : orphan_chains)
			if (orphan->has(prev_block_hash)) {
				//std::cout << "Added as new extra branch" << std::endl;
				orphan->add(block_data, hash, prev_block_hash);
				return;
			}

		//std::cout << "Added as new orphan block line as orphan" << std::endl;
		auto new_orphan = std::make_unique<blockchain>();
		new_orphan->add(block_data, hash, prev_block_hash, true);
		check_vs_orphans(new_orphan->root_chain);
		orphan_chains.emplace_back(std::move(new_orphan));
	}
	size_t size() const
	{
		return root_chain.size()
		     + std::accumulate(branches     .begin(), branches     .end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> & bhm) { return s + bhm->size(); })
		     + std::accumulate(orphan_chains.begin(), orphan_chains.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> & bhm) { return s + bhm->size(); })
			 ;
	}

	void print(int indent)
	{
		std::cout << std::string(2*indent, ' ') << "root chain " << root_chain.size() << std::endl;
		//for (auto & block : root_chain.blocks)
		//	std::cout << std::string(2*indent+2, ' ') << block.prev_block_hash << std::endl;
		//if (root_chain.size() != 0)
		//	std::cout << std::string(2*indent+2, ' ') << root_chain.get_last_known_block_hash() << std::endl;

		//std::cout << std::string(2*indent, ' ') << "branch chains:" << std::endl;
		//for (auto & branch : branches)
		//	branch->print(indent+1);
		//std::cout << std::string(2*indent, ' ') << "orphan chains:" << std::endl;
		//for (auto & orphan : orphan_chains)
		//	orphan->print(indent+1);
		std::cout << std::string(2*indent, ' ')
		          << std::accumulate(branches.begin(), branches.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> &bhm) { return s + bhm->size(); })
		          << " in " << branches.size() << " branched chains." << std::endl;
		std::cout << std::string(2*indent, ' ')
		          << std::accumulate(orphan_chains.begin(), orphan_chains.end(), (size_t)0, [](size_t s, const std::unique_ptr<blockchain> &bhm) { return s + bhm->size(); })
		          << " in " << orphan_chains.size() << " orphan chains." << std::endl;
	}
};

} // namespace
