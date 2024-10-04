#pragma once

#include <string>

#include <google/protobuf/service.h>

namespace common::proto
{

class RpcController : public google::protobuf::RpcController
{
public:
	RpcController() { _reset(); }
	~RpcController() override = default;

	void Reset() override
	{
		_reset();
	}

	[[nodiscard]] bool Failed() const override { return is_failed_; }
	void SetFailed(const std::string& reason) override
	{
		is_failed_ = true;
		error_code_ = reason;
	}
	[[nodiscard]] std::string ErrorText() const override { return error_code_; }
	void StartCancel() override {};
	[[nodiscard]] bool IsCanceled() const override { return false; };
	void NotifyOnCancel(::google::protobuf::Closure* /* callback */) override {};

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
