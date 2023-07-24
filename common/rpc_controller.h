#pragma once

#include <string>

#include <google/protobuf/service.h>

namespace common::proto
{

class RpcController : public google::protobuf::RpcController
{
public:
	RpcController() { _reset(); }
	virtual ~RpcController() {}

	virtual void Reset()
	{
		_reset();
	}

	virtual bool Failed() const { return is_failed_; }
	virtual void SetFailed(const std::string& reason)
	{
		is_failed_ = true;
		error_code_ = reason;
	}
	virtual std::string ErrorText() const { return error_code_; }
	virtual void StartCancel(){};
	virtual bool IsCanceled() const { return false; };
	virtual void NotifyOnCancel(::google::protobuf::Closure* /* callback */){};

private:
	bool is_failed_;
	std::string error_code_;
	void _reset()
	{
		is_failed_ = false;
		error_code_ = "";
	}
};

}
