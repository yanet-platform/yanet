#pragma once

#include "common/icontrolplane.h"
#include "helper.h"
#include "table_printer.h"

namespace convert
{

inline void logical_module()
{
	interface::controlPlane controlPlane;
	const auto response = controlPlane.convert("logical_module");

	FillAndPrintTable({"id", "name"}, response);
}

} /* namespace convert */
