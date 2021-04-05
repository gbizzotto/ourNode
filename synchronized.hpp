
#pragma once

#include <mutex>
#include <condition_variable>
#include "on_scope_exit.hpp"

namespace utttil {

template<typename T, class Mutex>
class synchronized_proxy
{
	template<typename X, class Y, class Z>
	friend class synchronized;

private:
	synchronized_proxy() = delete;
	synchronized_proxy(const synchronized_proxy &) = delete;
	synchronized_proxy & operator=(const synchronized_proxy &) = delete;
	synchronized_proxy & operator=(synchronized_proxy &&) = delete;
	
	synchronized_proxy(Mutex & m, T & obj)
		:lock(m)
		,t(&obj)
	{}
	synchronized_proxy(Mutex & m, T & obj, int)
		:lock(m, std::try_to_lock)
		,t((lock)?&obj:nullptr)
	{}

public:
	synchronized_proxy(synchronized_proxy && other)
		:lock(*other.lock.mutex(), std::adopt_lock)
		,t(std::move(other.t))
	{
		other.t = nullptr;
	}

	bool operator!() { return !lock; }

	const T * operator->() const { return t; }
	      T * operator->()       { return t; }

	const T & operator*() const { return *t; }
	      T & operator*()       { return *t; }

private:
	std::unique_lock<Mutex> lock;
	T * t;
};


template<typename T, class Mutex=std::mutex, class CV=std::condition_variable>
class synchronized
{
public:
	// Convenience typefed for subclasses to use
	using value_type = T;
	using proxy_type = synchronized_proxy<T,Mutex>;
	
	synchronized() = default;
	synchronized(const T  & t) : t(          t ) {}
	synchronized(      T && t) : t(std::move(t)) {}
	synchronized(const proxy_type  & sp) : t(          *sp.t ) {}
	synchronized(      proxy_type && sp) : t(std::move(*sp.t)) {}

	template<typename... Args>
	synchronized(Args... args)
		:t(args...)
	{}

	proxy_type     lock() { return proxy_type(mutex, t   ); }
	proxy_type try_lock() { return proxy_type(mutex, t, 0); }

	proxy_type operator->() {
		return proxy_type(mutex, t);
	}
	proxy_type operator*() {
		return proxy_type(mutex, t);
	}

	template<typename Check>
	proxy_type wait_for_notification(Check check)
	{
		auto s = proxy_type(mutex, t);
		if (check(t))
			return s;
		cv_counter++;
		ON_SCOPE_EXIT([&](){ cv_counter--; });
		cv.wait(s.lock, [&](){ return check(t); });
		return s;
	}

	void notify_one() { cv.notify_one(); }
	void notify_all() { cv.notify_all(); }

	size_t waiting_count() const { return cv_counter; }

protected:
	T t;
	Mutex mutex;
	CV cv;
	size_t cv_counter = 0;
};

} // namespace
