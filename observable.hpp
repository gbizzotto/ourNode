
#pragma once

namespace utttil {

template<typename T>
struct observable
{
	using Callback = std::function<void(const T&, const T&)>;
	T t;

	std::vector<Callback> callbacks;

	observable() = default;
	observable(const T & t_) : t(t_) {}
	observable(T && t_) : t(std::move(t_)) {}
	void operator=(const T & other)
	{
		T old = std::move(t);
		t = other;
		callback(old);
	}
	void operator=(T && other)
	{
		T old = std::move(t);
		t = std::move(other);
		callback(old);
	}

	bool operator==(const observable<T> & other)
	{
		return t == other.t;
	}
	bool operator==(const T & other)
	{
		return t == other;
	}

	operator       T&()      { return t; }
	operator const T&() const{ return t; }

	void observe(Callback c)
	{
		callbacks.push_back(std::move(c));
	}
	void callback(const T & old)
	{
		if (old == *this)
			return;
		for (auto & c : callbacks)
			c(old, *this);
	}
};

} // namespace
