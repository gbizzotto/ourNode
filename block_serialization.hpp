
#pragma once

#include <fstream>
#include <filesystem>
#include <string_view>
#include "on_scope_exit.hpp"
#include "sha256sum.hpp"
#include "misc.hpp"
#include "block.hpp"

namespace ournode {

struct file_block_persistence
{
	struct index_block
	{
		std::uint32_t file_number;
		std::uint32_t offset;
		std::uint32_t size;
		std::uint32_t hash_hash;
	};
	struct persistent_index_block : index_block
	{
		Hash256 hash;
	};

	static inline const size_t max_file_size = 4'000'000'000ull;

	std::filesystem::path folder;
	std::fstream fio_index;
	std::deque<std::ifstream> fin_blocks;
	std::ofstream fo_blocks;

	file_block_persistence(std::filesystem::path p)
		: folder(p / "blocks")
	{
		std::filesystem::create_directories(folder);
		fio_index.open(folder / "index", std::ios_base::app | std::ios_base::binary);

		auto filename = folder / "0";
		size_t blocks_file_count = 0;
		while(std::filesystem::exists(folder / std::to_string(blocks_file_count)))
			blocks_file_count++;
		if (blocks_file_count != 0) {
			for (size_t i=0 ; i<blocks_file_count ; i++)
				fin_blocks.emplace_back(folder / std::to_string(i), std::ios_base::in | std::ios_base::binary);
			fo_blocks.open(folder / std::to_string(blocks_file_count-1), std::ios_base::app | std::ios_base::binary);
		} else {
			fo_blocks.open(folder / "0", std::ios_base::app | std::ios_base::binary);
			fin_blocks.emplace_back(folder / "0", std::ios_base::in | std::ios_base::binary);
		}
	}

	size_t size()
	{
		return fio_index.tellp() / 44;
	}

	void serialize(const file_block_persistence::persistent_index_block & pib)
	{
		serialize_little_endian<std::uint32_t>(fio_index, pib.file_number);
		serialize_little_endian<std::uint32_t>(fio_index, pib.offset     );
		serialize_little_endian<std::uint32_t>(fio_index, pib.size       );
		serialize_bytes(fio_index, (char*)pib.hash.h, 32);
	}
	static persistent_index_block consume_pib(std::istream & in)
	{
		persistent_index_block result;
		result.file_number = consume_little_endian<std::uint32_t>(in);
		result.offset      = consume_little_endian<std::uint32_t>(in);
		result.size        = consume_little_endian<std::uint32_t>(in);
		consume_bytes(in, (char*)result.hash.h, 32);
		result.hash_hash   = result.hash.hash_hash;
		return result;
	}

	const std::uint32_t get_hash_hash(const index_block & bh) const
	{
		return bh.hash_hash;
	}
	Hash256 get_hash(std::uint32_t idx)
	{
		std::ifstream in(folder/"index", std::ios_base::binary);
		in.seekg(idx * 44);
		auto pib = consume_pib(in);
		return pib.hash;
	}
	const std::string get_raw_data(const index_block & bh)
	{
		std::ifstream & fin = fin_blocks[bh.file_number];
		fin.seekg(bh.offset);
		std::string buffer(bh.size, 0);
		consume_bytes(fin, buffer.data(), bh.size);
		return buffer;
	}

	size_t get_current_data_file_write_position()
	{
		return fo_blocks.tellp();
	}
	size_t get_current_data_file_index() const
	{
		return fin_blocks.size() - 1;
	}

	void adjust_for_added_size(size_t added_size)
	{
		auto pos = get_current_data_file_write_position();
		if (pos+added_size >= max_file_size)
		{
			size_t i = get_current_data_file_index() + 1;
			auto filename = folder / std::to_string(i);
			fo_blocks.close();
			fo_blocks.open(filename, std::ios_base::app | std::ios_base::binary);
			fin_blocks.emplace_back(filename, std::ios_base::in | std::ios_base::binary);
		}
	}

	index_block store(std::string_view block_data, const Hash256 & hash)
	{
		adjust_for_added_size(block_data.size());
		persistent_index_block pib;
		pib.file_number = get_current_data_file_index();
		pib.offset      = get_current_data_file_write_position();
		pib.size        = block_data.size();
		pib.hash_hash   = hash.hash_hash;
		pib.hash        = hash;
		serialize_bytes(fo_blocks, (char*)block_data.data(), block_data.size());
		serialize(pib);
		return pib;
	}

	template<typename Callback>
	void get_blocks_pib(Callback callback)
	{
		std::ifstream fin_index(folder / "index", std::ios_base::in | std::ios_base::binary);
		while(fin_index.good())
		{
			persistent_index_block pib = consume_pib(fin_index);
			if (fin_index.eof())
				break;
			callback(pib);
		}
	}

	template<typename Callback>
	void get_blocks_hash(Callback callback)
	{
		get_blocks_pib([&](persistent_index_block & pib)
			{
				callback(pib.hash);
			});
	}
	template<typename Callback>
	void get_blocks_raw_data(Callback callback)
	{
		get_blocks_pib([&](persistent_index_block & pib)
			{
				auto raw_data = get_raw_data(pib);
				callback(pib, raw_data);
			});
	}
};

struct memory_block_persistence
{
	std::deque<std::string> blocks_data;
	std::deque<Hash256>     blocks_hash;

	using index_block = std::uint32_t;

	size_t size() const
	{
		return blocks_data.size();
	}

	const Hash256 & get_hash(const index_block & idx) const
	{
		return blocks_hash[idx];
	}
	const std::uint32_t get_hash_hash(const index_block & idx) const
	{
		return blocks_hash[idx].hash_hash;
	}
	const std::string_view get_raw_data(const index_block & idx) const
	{
		return blocks_data[idx];
	}

	index_block store(std::string_view block_data, const Hash256 & hash)
	{
		blocks_data.emplace_back(std::move(block_data));
		blocks_hash.emplace_back(std::move(hash      ));
		return blocks_data.size()-1;
	}

	template<typename Callback>
	void get_blocks_pib(Callback callback)
	{
		for (index_block ib=0 ; ib<blocks_data.size() ; ib++)
			callback(ib);
	}
	template<typename F>
	void get_blocks_hash(F callback)
	{
		for (std::uint32_t i=0 ; i<blocks_data.size() ; i++)
			callback(blocks_hash[i]);
	}
	template<typename F>
	void get_blocks_raw_data(F callback)
	{
		for (std::uint32_t i=0 ; i<blocks_data.size() ; i++)
			callback({i, blocks_hash[i]}, blocks_data[i]);
	}
};

} // namespace
