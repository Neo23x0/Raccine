#pragma once
#include <string>
#include <windows.h>
#include <winevt.h>
#include "Utils.h"

namespace eventloghelper
{
	std::wstring GetEvents();
}