
#pragma once

#include <cstdint>
#include <memory>
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

	size_t bytes_size() const { return 8 + 4 + script_size; }
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
	std::uint32_t bits;
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

} // namespace
