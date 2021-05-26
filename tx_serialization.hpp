
#pragma once

#include <cstdint>
#include <deque>
#include <list>

#include "block.hpp"

namespace ournode {

struct memory_tx_persistence
{
	// utxos by block height
	std::deque<std::list<txout>> utxos;

	using index_block = std::uint32_t;

	size_t size() const
	{
		return utxos.size();
	}

	index_block store(std::list<txout> && block_utxos, const Hash256 & tx_hash)
	{
		utxos.emplace_back(std::move(block_utxos));
		return utxos.size()-1;
	}

	template<typename Callback>
	void get_txs_pib(Callback callback)
	{
		for (index_block ib=0 ; ib<utxos.size() ; ib++)
			callback(ib);
	}
};

} // namespace
