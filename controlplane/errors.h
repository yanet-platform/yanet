#pragma once

#include <stdexcept>
#include <string>

#include "common/result.h"

class error_result_t : public std::runtime_error
{
public:
	error_result_t(eResult result, const std::string& error) :
	        std::runtime_error(error), code(result)
	{}

	eResult result() const
	{
		return code;
	}

protected:
	eResult code;
};
