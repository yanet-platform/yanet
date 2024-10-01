#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cli/helper.h"

namespace
{

class CallableClass
{
public:
	void operator()(int a, std::optional<double> b, const std::string& c) const
	{
		EXPECT_EQ(a, 70);
		if (b.has_value())
		{
			EXPECT_DOUBLE_EQ(b.value(), 45.67);
		}
		EXPECT_EQ(c, "test");
	}
};

void CheckIntegerAndString(int a, const std::string& str)
{
	EXPECT_EQ(a, 42);
	EXPECT_EQ(str, "hello");
}

void CheckOptionalIntegerAndStringPresent(int a, std::optional<int> b, const std::string& str)
{
	EXPECT_EQ(a, 42);
	EXPECT_TRUE(b.has_value());
	EXPECT_EQ(b.value(), 100);
	EXPECT_EQ(str, "world");
}

void CheckOptionalIntegerMissing(int a, std::optional<int> b, const std::string& str)
{
	EXPECT_EQ(a, 42);
	EXPECT_FALSE(b.has_value());
	EXPECT_EQ(str, "world");
}

void CheckBooleanTrueAndOptionalString(bool flag, std::optional<std::string> text)
{
	EXPECT_TRUE(flag);
	EXPECT_TRUE(text.has_value());
	EXPECT_EQ(text.value(), "some_text");
}

void CheckBooleanFalseAndMissingOptionalString(bool flag, std::optional<std::string> text)
{
	EXPECT_FALSE(flag);
	EXPECT_FALSE(text.has_value());
}

void CheckCallableClassWithOptional(int a, std::optional<double> b, const std::string& c)
{
	EXPECT_EQ(a, 70);
	EXPECT_TRUE(b.has_value());
	EXPECT_DOUBLE_EQ(b.value(), 45.67);
	EXPECT_EQ(c, "test");
}

void CheckCallableClassWithMissingOptional(int a, std::optional<double> b, const std::string& c)
{
	EXPECT_EQ(a, 70);
	EXPECT_FALSE(b.has_value());
	EXPECT_EQ(c, "test");
}

TEST(CallFunctionTests, IntegerAndString)
{
	std::vector<std::string> args = {"42", "hello"};
	EXPECT_NO_THROW(Call(CheckIntegerAndString, args));
}

TEST(CallFunctionTests, OptionalIntegerPresent)
{
	std::vector<std::string> args = {"42", "100", "world"};
	EXPECT_NO_THROW(Call(CheckOptionalIntegerAndStringPresent, args));
}

TEST(CallFunctionTests, OptionalIntegerMissing)
{
	std::vector<std::string> args = {"42", "", "world"};
	EXPECT_NO_THROW(Call(CheckOptionalIntegerMissing, args));
}

TEST(CallFunctionTests, BooleanTrueAndOptionalStringPresent)
{
	std::vector<std::string> args = {"true", "some_text"};
	EXPECT_NO_THROW(Call(CheckBooleanTrueAndOptionalString, args));
}

TEST(CallFunctionTests, BooleanFalseAndMissingOptionalString)
{
	std::vector<std::string> args = {"false", ""};
	EXPECT_NO_THROW(Call(CheckBooleanFalseAndMissingOptionalString, args));
}

TEST(CallFunctionTests, CallableClassWithOptional)
{
	std::vector<std::string> args = {"70", "45.67", "test"};
	EXPECT_NO_THROW(Call(CheckCallableClassWithOptional, args));
}

TEST(CallFunctionTests, CallableClassWithMissingOptional)
{
	std::vector<std::string> args = {"70", "", "test"};
	EXPECT_NO_THROW(Call(CheckCallableClassWithMissingOptional, args));
}

TEST(CallFunctionTests, LambdaFunction_WithValidArguments)
{
	auto lambda = [](int x, std::optional<std::string> opt, bool flag) {
		EXPECT_EQ(x, 50);
		if (opt.has_value())
		{
			EXPECT_EQ(opt.value(), "optional_text");
		}
		EXPECT_TRUE(flag);
	};

	std::vector<std::string> args = {"50", "optional_text", "true"};
	EXPECT_NO_THROW(Call(lambda, args));
}

TEST(CallFunctionTests, LambdaFunction_WithMissingOptional)
{
	auto lambda = [](int x, std::optional<std::string> opt, bool flag) {
		EXPECT_EQ(x, 50);
		EXPECT_FALSE(opt.has_value());
		EXPECT_FALSE(flag);
	};

	std::vector<std::string> args = {"50", "", "false"};
	EXPECT_NO_THROW(Call(lambda, args));
}

TEST(CallFunctionTests, CallableClass_WithValidArguments)
{
	CallableClass callable_object;
	std::vector<std::string> args = {"70", "45.67", "test"};
	EXPECT_NO_THROW(Call(callable_object, args));
}

TEST(CallFunctionTests, CallableClass_WithMissingOptional)
{
	CallableClass callable_object;
	std::vector<std::string> args = {"70", "", "test"};
	EXPECT_NO_THROW(Call(callable_object, args));
}

}
