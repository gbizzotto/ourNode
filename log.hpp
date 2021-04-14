
#pragma once

#include <iostream>
#include <vector>
#include <mutex>
#include <thread>
#include <initializer_list>
#include <boost/fiber/all.hpp>

#include "timestamp.hpp"
#include "on_scope_exit.hpp"

namespace utttil {

template<size_t S=0>
struct Log
{
	std::vector<std::ostream*> & outs;
	std::scoped_lock<std::recursive_mutex> lock;
	bool do_log;

	Log(std::vector<std::ostream*> & outs, std::recursive_mutex & mutex, bool do_log)
		: outs(outs)
		, lock(mutex)
		, do_log(do_log)
	{}

	void flush()
	{
		if ( ! do_log)
			return;
		for (auto & out : outs)
			out->flush();
	}
};
template<typename T, size_t S=0>
std::unique_ptr<Log<S>> operator<<(std::unique_ptr<Log<S>> log, const T & t)
{
	if (log->do_log)
		for (auto & out : log->outs)
			*out << t;
	return log;
}
template<typename T, size_t S=0>
std::unique_ptr<Log<S>> operator<<(std::unique_ptr<Log<S>> log, T && t)
{
	if (log->do_log)
		for (auto & out : log->outs)
			*out << t;
	return log;
}
template<size_t S=0>
std::unique_ptr<Log<S>> operator<<(std::unique_ptr<Log<S>> log, const char * t)
{
	if (log->do_log)
		for (auto & out : log->outs)
			*out << t;
	return log;
}
// support for std::endl and other modifiers
template<size_t S=0>
std::unique_ptr<Log<S>> operator<<(std::unique_ptr<Log<S>> log, std::ostream& (*f)(std::ostream&))
{
	if (log->do_log)
		for (auto & out : log->outs)
			f(*out);
	return log;
}

enum class LogLevel
{
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	FATAL,
	MUST_HAVE,
};
static inline const char * LogLevelNames[] =
{
	"DEBUG",
	"INFO",
	"WARNING",
	"ERROR",
	"FATAL",
	"MUST_HAVE",
};

template<size_t S>
struct LogWithPrefix_
{
	std::string prefix;
	LogLevel level;
	std::vector<std::ostream*> outs;
	std::vector<std::string> funcs;

	static inline std::recursive_mutex cout_mutex;

	LogWithPrefix_(std::string prefix = "")
		: prefix(std::move(prefix))
		, level(LogLevel::INFO)
	{}
	LogWithPrefix_(std::string prefix, LogWithPrefix_ & other)
		: prefix(std::move(prefix))
		, level(other.level)
		, outs(other.outs)
	{}

	void set_prefix(std::string p) { prefix = std::move(p); }
	void set_level(LogLevel l) { level = l; }
	void add(std::ostream & out)
	{
		outs.push_back(&out);
	}
	void flush()
	{
		for (auto & out : outs)
			out->flush();
	}
	void enter(std::string func) { funcs.emplace_back(std::move(func)); }
	void exit() { funcs.pop_back(); }
	std::string trace_stack_string() const
	{
		return std::accumulate(funcs.rbegin(), funcs.rend(), std::string(prefix).append(" stack:"), [](std::string & s, const std::string & elm) -> std::string & { return s.append("\n  ").append(elm); });
	}
};
template<size_t S=0>
std::unique_ptr<Log<S>> operator<<(LogWithPrefix_<S> & log, LogLevel level)
{
	return std::make_unique<Log<S>>(log.outs, LogWithPrefix_<S>::cout_mutex, level >= log.level) << utttil::UTCTimestampISO8601() << " [" << log.prefix << "] [" << LogLevelNames[(int)level] << "] ";
}

using LogWithPrefix = LogWithPrefix_<0>;



LogWithPrefix & default_logger()
{
	static LogWithPrefix log("");
	return log;
}
template<typename... Args>
LogWithPrefix & default_logger(std::ostream & o, Args... args)
{
	LogWithPrefix & df = default_logger();
	df.add(o);
	return default_logger(args...);
}

LogWithPrefix & fiber_local_logger(std::string prefix = "")
{
	thread_local std::map<boost::fibers::fiber::id, LogWithPrefix> logs;
	auto p = logs.insert({boost::this_fiber::get_id(), {prefix, default_logger()}});
	return p.first->second;
}

std::unique_ptr<Log<0>>     debug() { return fiber_local_logger() << LogLevel::DEBUG    ; }
std::unique_ptr<Log<0>>      info() { return fiber_local_logger("a") << LogLevel::INFO     ; }
std::unique_ptr<Log<0>>   warning() { return fiber_local_logger() << LogLevel::WARNING  ; }
std::unique_ptr<Log<0>>     error() { return fiber_local_logger() << LogLevel::ERROR    ; }
std::unique_ptr<Log<0>>     fatal() { return fiber_local_logger() << LogLevel::FATAL    ; }
std::unique_ptr<Log<0>> must_have() { return fiber_local_logger() << LogLevel::MUST_HAVE; }

#define TRACE utttil::fiber_local_logger().enter(__PRETTY_FUNCTION__); \
	ON_SCOPE_GRACEFULLY_EXIT([](){utttil::fiber_local_logger().exit();});

#define PRINT_TRACE	std::cout << utttil::fiber_local_logger().trace_stack_string() << std::endl;

} // namespace
