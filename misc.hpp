
#pragma once


template<typename C>
bool in(const typename C::value_type & t, const C & c)
{
	return std::find(std::begin(c), std::end(c), t) != std::end(c);
}
template<typename C>
bool in(const typename C::key_type & t, const C & c)
{
	return c.find(t) != std::end(c);
}
template<typename C>
const typename C::value_type & random(const C & c)
{
	if (c.size() == 1)
		return *c.begin();
	return *std::next(c.begin(), rand()%(c.size()-1));
}


template<typename T>
T consume_little_endian(std::string_view & data)
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
void serialize_little_endian(unsigned char * data, T value)
{
	for (int i=0 ; i<sizeof(T) ; i++, value >>= 8)
		*data++ = (value & 0xFF);
}
template<typename T>
void serialize_big_endian(unsigned char * data, T value)
{
	for (int i=sizeof(T)-1 ; i>0 ; i--)
		*data++ = ((value >> (8*i)) & 0xFF);
}
std::uint64_t consume_var_int(std::string_view & data)
{
	if (data.size() < 1)
		throw std::invalid_argument("data.size() < 1");
	unsigned char first = data[0];
	data.remove_prefix(1);
	if (first == 0xFF) {
		auto result = consume_little_endian<std::uint64_t>(data);
		return result;
	} else if (first == 0xFE) {
		auto result = consume_little_endian<std::uint32_t>(data);
		return result;
	} else if (first == 0xFD) {
		auto result = consume_little_endian<std::uint16_t>(data);
		return result;
	} else {
		return first;
	}
}
void consume_bytes(std::string_view & src, char *dst, size_t len)
{
	if (src.size() < len)
		throw std::invalid_argument("data.size() < 1");
	std::copy(src.data(), src.data()+len, dst);
	src.remove_prefix(len);
}
std::string consume_var_str(std::string_view & sv)
{
	size_t size = consume_var_int(sv);
	std::string result(size, 0);
	consume_bytes(sv, result.data(), size);
	return result;
}

template<typename T>
T consume_little_endian(std::istream & is)
{
	T result = 0;
	for (int i=0 ; i < sizeof(T) ; i++) {
		result += (((T)is.get()) & 0xFF) << (i*8);
		if (is.eof())
			break;
	}
	return result;
}
void consume_bytes(std::istream & is, char *dst, size_t len)
{
	is.read(dst, len);
}

template<typename T>
void serialize_little_endian(std::ostream & out, T value)
{
	for (int i=0 ; i<sizeof(T) ; i++, value >>= 8)
		out.put(value & 0xFF);
}
void serialize_bytes(std::ostream & out, char *dst, size_t len)
{
	out.write(dst, len);
}