#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include <err.h>
#include <sysexits.h>
#include <unistd.h>

#include "fw_dump.h"
#include "fw_parser.h"

static void
usage(const char* name)
{
	std::cerr << "Usage: " << name << "[-h] [-v | -q] [-n] "
	          << "[-f file_name | -c cmd] [-d dns_cache] "
	          << "[-m macros]" << std::endl
	          << "-h            Help. This message." << std::endl
	          << "-n            Parse commands without executing." << std::endl
	          << "-v            Produce more verbose output." << std::endl
	          << "-D            Dump parser state into stderr." << std::endl
	          << "-s            Do extra sanity checks for ruleset." << std::endl
	          << "-q            Be quiet. No output at all." << std::endl
	          << "-d dns_cache  Read DNS cache mappings from file." << std::endl
	          << "-f file_name  Read rules from file." << std::endl
	          << "-m macros     Read macros from file." << std::endl
	          << "-c cmd        Read rule from command line arguments." << std::endl
	          << "              Read rules from stdin if both -f and -c are ommitted." << std::endl;
	exit(EX_USAGE);
}

int main(int argc, char* argv[])
{
	std::shared_ptr<ipfw::fw_config_t> config;
	std::string dname, fname, mname;
	bool cmd_mode = false, quiet_mode = false, test_mode = false, dump = false, success = false, sanity = false;
	int verbose_level = 0;
	char ch = 0;

	cmd_mode = quiet_mode = test_mode = dump = sanity = false;
	while (!cmd_mode && (ch = getopt(argc, argv, "d:f:c:m:Dqsvnh")) != -1)
	{
		switch (ch)
		{
			case 'D':
				dump = true;
				break;
			case 's':
				sanity = true;
				break;
			case 'd':
				dname = optarg;
				break;
			case 'm':
				mname = optarg;
				break;
			case 'f':
				if (cmd_mode)
					errx(EX_USAGE,
					     "-c and -f are mutually exclusive\n");
				fname = optarg;
				break;
			case 'c':
				if (!fname.empty())
					errx(EX_USAGE,
					     "-c and -f are mutually exclusive\n");
				cmd_mode = true;
				break;
			case 'v':
				if (quiet_mode)
					errx(EX_USAGE,
					     "-v and -q are mutually exclusive\n");
				verbose_level++;
				break;
			case 'q':
				if (verbose_level != 0)
					errx(EX_USAGE,
					     "-v and -q are mutually exclusive\n");
				quiet_mode = true;
				break;
			case 'n':
				test_mode = true;
				break;
			default:
				usage(argv[0]);
		}
	}
	if (!cmd_mode && argc - optind > 0)
		usage(argv[0]);

	argc -= optind - 1;
	argv += optind - 1;

	config = std::make_shared<ipfw::fw_config_t>(2); /* autoinc_step = 2*/
	config->set_debug(verbose_level);

	/*
     * For -c option we concatenate all remaining arguments into
     * single spaces delimited string and pass it to the parser.
     *
     * NOTE: the order of scheduled files is matter. DNS cache
     * should be scheduled last, then it will be processed first.
     */
	if (cmd_mode)
	{
		/* Rule from command line arguments */
		std::string cmd;

		std::for_each(argv, argv + argc, [&](const char* arg) { cmd += std::string(arg) + " "; });
		cmd.back() = '\n'; /* replace last space with EOL */
		success = config->schedule_string(cmd);
	}
	else if (!fname.empty())
	{
		/* Rules from file */
		success = config->schedule_file(fname);
	}
	else
	{
		// parse rules from stdin
		success = config->schedule_stdin();
	}

	if (!success)
		return (-1);

	/* Read macros cache */
	if (!mname.empty())
	{
		if (!config->schedule_file(mname))
			return (-2);
	}

	/* Read DNS cache */
	if (!dname.empty())
	{
		if (!config->schedule_file(dname))
			return (-3);
	}

	try
	{
		success = config->parse();
		if (success && sanity)
		{
			success = config->validate();
		}
	}
	catch (std::exception const& e)
	{
		std::cerr << "Exception: " << e.what() << std::endl;
		success = false;
	}
	if (!success)
		return (-4);

	if (!test_mode)
	{
	}

	if (dump)
	{
		ipfw::fw_dump_t dumper(config);

		dumper.dump();
	}
	/* clean up */
	return (0);
}
