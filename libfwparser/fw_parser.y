// require bison version 3.2+
//%require "3.2"
%require "3.0"

// generate C++ source code
%language "C++"

// define custom namespace
%define api.namespace {ipfw}

// define custom parser class name
//%define api.parser.class {fw_parser_t}    // for bison 3.2+
%define parser_class_name {fw_parser_t}     // for bison 3.0

// define type of semantic values
%define api.value.type variant

// define error reporting verbosity
%define parse.error verbose
%define parse.trace
//%define parse.error detailed	// bison 3.2+
//%define parse.lac full	// bison 3.2+

// define symbol prefix for tokens
%define api.token.prefix {TOK_}

// handle symbols as a whole (type, value, location) 
%define api.token.constructor

// generate parser header file
%defines // "fw_parser.h"

// generate cursor location classes
%locations

%code requires {
  #include "common/type.h"

  namespace ipfw {
  // forward declaration of context class
  class fw_config_t;
  class fw_lexer_t;

  // IPv4 addresses in form 1.2.3.4/255.0.255.0
  using ipv4_prefix_mask_t = std::tuple<common::ipv4_address_t,
                                        common::ipv4_address_t>;

  // IPv6 addresses in form 02:6b8:c00::4440:0:0/ffff:ffff:ff00:0:ffff:ffff::
  using ipv6_prefix_mask_t = std::tuple<common::ipv6_address_t,
                                        common::ipv6_address_t>;

  }
}

// specify parser arguments
%parse-param { ipfw::fw_config_t& cfg }

%code provides {
  #include "libfwparser/fw_parser.h"
  #include "libfwparser/fw_config.h"
  #include "libfwparser/fw_lexer.h"

  // replace yylex() function call
  #define yylex cfg.Lex

  #ifdef YYDEBUG
  #define WARN_UNSUPPORTED(msg)	do {	\
	if (debug_level() > 0)		\
		std::cerr << "fw_parser_t: " << msg << std::endl;	\
  } while (0)
  #else
  #define WARN_UNSUPPORTED(msg)
  #endif
}

%start commands

// modern bison versions have this token already defined.
// it has magic meaning, lexer returns it when end of file is reached.

%token                          YYEOF 0

// define variant types for some tokens.
// lexer will return value of those types on match.

%token <float>                  FLOAT 
%token <common::ipv4_address_t> IP
%token <common::ipv6_address_t> IP6
%token <common::ipv4_prefix_t>  NETWORK
%token <common::ipv6_prefix_t>  NETWORK6
%token <common::range_t>        RANGE
%token <ipv4_prefix_mask_t>     IPMASK
%token <ipv6_prefix_mask_t>     IP6MASK

%token <std::string>            LABEL MACRO MACRODEF TOKEN ALGO_NAME FQDN
                                SOCKADDR4 IP6SCOPIED REDPARAM COMMENT TABLENAME

%token <int64_t>                HEXMASK MASKLEN BWBS BWBTS BWKBS BWKBTS BWMBS
                                BWMBTS SIZEK NUMBER

%token <uint8_t>                DSCPSPEC

// these tokens don't need any type, we need to know only fact 
// that token was matched.

%token          ADD ADDRULE ACTUAL STALE ALLOW DENY DENY_IN T_REJECT
		UNREACH UNREACH6 SKIPTO DIVERT TEE COUNT SETDSCP
		SETFIB DSCP CALL RETURN TAG UNTAG TAGGED ALTQ PIPE QUEUE
		REASS CONFIG BW WEIGHT BUCKETS MASK SCHEDMASK NOERROR PLR
		DROPTAIL FLOWID PDELAY SCHED FLOWMASK LINK PRIORITY TYPE
		VALTYPE ALGO FIB PROFILE BURST CHECKSTATE FWD LOG LOGAMOUNT
		LOGDST SETUP ESTABLISHED FRAG MF RF DF OFFSET KEEPSTATE
		ICMPTYPES ICMP6TYPES FROM TO ME ME6 ANY IN OUT VIA XMIT
		RECV OR NOT LIMIT TABLE TCPFLAGS TCPOPTIONS T_IP T_IP4 T_IP6
		IPLEN IPID IPOPTIONS IPTOS IPTTL TCPDATALEN TCPSEQ TCPWIN
		FIN SYN RST PSH ACK URG MSS TCPMSS WINDOW SACK TS CC SSRR
		LSRR RR LOWDELAY THROUGHPUT RELIABILITY MINCOST CONGESTION
		NET HOST PROTO PORT NEEDFRAG SRCFAIL NETUNKNOWN HOSTUNKNOWN
		ISOLATED NETPROHIB HOSTPROHIB TOSNET TOSHOST FILTERPROHIB
		HOSTPRECEDENCE PRECEDENCECUTOFF DIVERTEDLOOPBACK DIVERTED
		DIVERTEDOUTPUT NAT NH4 NETGRAPH SAME_PORTS IF UNREG_ONLY
		VERREVPATH VERSRCREACH ANTISPOOF RESET RESET6 REVERSE
		PROXY_ONLY REDIRECT_ADDR REDIRECT_PORT REDIRECT_PROTO
		SKIP_GLOBAL GLOBAL EXT6HDR HOPOPT ROUTE DSTOPT
		RTHDR0 RTHDR2 IPSEC IPVER CREATE ADDR IFACE T_NUMBER FLOW
		TABLEARG PLAT_PREFIX CLAT_PREFIX ALLOW_PRIVATE INT_PREFIX
		EXT_PREFIX PREFIXLEN PREFIX4 PREFIX6 AGG_LEN AGG_COUNT
		MAX_PORTS STATES_CHUNKS JAIL JMAXLEN PORT_RANGE NH_DEL_AGE
		PG_DEL_AGE TCP_SYN_AGE TCP_EST_AGE TCP_CLOSE_AGE UDP_AGE
		ICMP_AGE TABLE4 TABLE6 SWAP_CONF LAYER2 MAC SRCMAC DSTMAC
		NOTCHAR LOOKUP UID RULENUM OBRACE EBRACE LBRACE RBRACE
		SRCPRJID DSTPRJID RED ALL LMAX DSTIP6 SRCIP6 TCPSETMSS
		NAT64CLAT NAT64LSN NAT64STL NPTV6 SRCADDR QM DSTADDR
		SRCPORT DSTPORT SRCIP DSTIP EQUAL COMMA MINUS EOL M4LQ M4RQ DUMP

// QUEUE could be an argument to *MASK
%nonassoc	QUEUE
%nonassoc	MASK FLOWMASK SCHEDMASK

%%

commands: 
	| commands command
	;
command:
	LABEL EOL
	{
		cfg.add_label($1);
	}
	|
	MACRODEF
	{
		const auto& length = $1.size();
		cfg.set_macro($1.substr(0, length - 1));
	}
	macrovalue EOL
	|
	FQDN
	{
		cfg.set_fqdn($1);
	}
	dnsaddrs dnsstate dnsusers EOL
	|
	table
	|
	add
	|
	nat | pipequeue | extmodules
	;
dnsaddrs:
	dnsip
	|
	dnsaddrs COMMA dnsip
	;
dnsip:
	IP
	{
		cfg.fill_fqdn($1);
	}
	|
	IP6
	{
		cfg.fill_fqdn($1);
	}
	;
dnsstate:
	ACTUAL | STALE
	;
dnsusers:
	/* user may not be specified */
	|
	dnsuser
	|
	dnsusers COMMA dnsuser
	;
dnsuser:
	TOKEN
	|
	HEXMASK
	|
	NUMBER
	;
macrovalue:
	macroitem
	|
	macrovalue COMMA macroitem
	;
macroitem:
	FQDN
	{
		cfg.fill_macro_fqdn($1);
	}
	|
	M4LQ FQDN M4RQ
	{	// FQDN can containt m4 reserverd words, thus it
		// should be enclosed in `' quotes if we want be
		// able to process enitre file with m4.
		cfg.fill_macro_fqdn($2);
	}
	|
	IP
	{
		cfg.fill_macro($1);
	}
	|
	NETWORK
	{
		cfg.fill_macro($1);
	}
	|
	IP6
	{
		cfg.fill_macro($1);
	}
	|
	NETWORK6
	{
		cfg.fill_macro($1);
	}
	|
	IP6MASK
	{
		cfg.fill_macro($1);
	}
	;
add:
	ADDRULE rulenumber action rule comment EOL
	{
		cfg.fill_rule_text();
	}
	|
	ADDRULE rulenumber action actionmods rule comment EOL
	{
		cfg.fill_rule_text();
	}
	|
	ADDRULE rulenumber checkstate EOL
	{
		cfg.fill_rule_text();
	}
	;
actionmods:
	actionmod
	|
	actionmods actionmod
	;
actionmod:
	tag
	|
	altq
	|
	log
	;
comment:
	|
	COMMENT
	{
	}
	;
checkstate:
	CHECKSTATE
	{
		cfg.set_rule_action(rule_action_t::CHECKSTATE);
	}
	|
	CHECKSTATE LABEL
	{
		cfg.set_rule_action(rule_action_t::CHECKSTATE);
	}
	;
table:
	TABLE newtable ADD tablerec tableopts endtable EOL
	|
	createtable
	{
	}
	;
createtable:
	TABLE newtable CREATE defaulttableconfig EOL
	|
	TABLE newtable CREATE tablespec EOL
	;
defaulttableconfig:
	{
		cfg.create_skipto_table();
	}
newtable:
	TABLENAME
	{
		cfg.set_table($1);
	}
	|
	NUMBER
	{
		cfg.set_table(std::to_string($1));
	}
	|
	MACRO
	{
		/* macro name fits into table name, but much stricter */
		cfg.set_table($1);
	}
	;
endtable: { } ;

tablespec:
	tablespecopt
	|
	tablespec tablespecopt
	;
tablespecopt:
	tabletype
	{
	}
	|
	VALTYPE tablevalmask
	{
	}
	|
	ALGO ALGO_NAME
	{
	}
	;
tabletype:
	TYPE ADDR
	{
		cfg.create_skipto_table();
	}
	|
	TYPE IFACE
	{
		cfg.create_iface_table();
	}
	|
	TYPE MAC
	{
		std::cerr << "mac tables aren't supported." << std::endl;
		YYERROR;
	}
	|
	TYPE T_NUMBER
	{
		std::cerr << "number tables aren't supported." << std::endl;
		YYERROR;
	}
	|
	TYPE FLOW
	{
		std::cerr << "flow tables aren't supported." << std::endl;
		YYERROR;
	}
	;

tablevalmask:
	tablevaluetype
	|
	tablevalmask COMMA tablevaluetype
	;
tablevaluetype:
	SKIPTO	{ }
	|
	PIPE	{ }
	|
	FIB	{ }
	|
	NAT	{ }
	|
	DSCP	{ }
	|
	TAG	{ }
	|
	DIVERT	{ }
	|
	NETGRAPH { }
	|
	LIMIT	{ }
	|
	TOKEN
	{
	}
	;
tableopts:
	/* empty table value */
	{
		cfg.fill_table_entry_value("");
	}
	|
	NUMBER
	{
		cfg.fill_table_entry_value($1);
	}
	|
	LABEL
	{
		cfg.fill_table_entry_value($1);
	}
	|
	IP
	{
		cfg.fill_table_entry_value(common::ip_address_t {$1});
	}
	|
	IP6
	{
		cfg.fill_table_entry_value(common::ip_address_t {$1});
	}
	;
tablerec:
	IP
	{
		cfg.fill_table_entry(common::ip_prefix_t {$1});
	}
	|
	NETWORK
	{
		cfg.fill_table_entry(common::ip_prefix_t {$1});
	}
	|
	IP6
	{
		cfg.fill_table_entry(common::ip_prefix_t {$1});
	}
	|
	NETWORK6
	{
		cfg.fill_table_entry(common::ip_prefix_t {$1});
	}
	|
	FQDN
	{
		cfg.fill_table_entry($1);
	}
	|
	TOKEN
	{
		cfg.fill_table_entry($1);
	}
	|
	NUMBER
	{
		// not supported yet
	}
	;
rulenumber:
	{
		cfg.fill_rule_number(0);
	}
	|
	NUMBER
	{
		cfg.fill_rule_number($1);
	}
	;
action:
	NAT natinstance
	{
		cfg.set_rule_action(rule_action_t::NAT);
	}
	|
	COUNT
	{
		cfg.set_rule_action(rule_action_t::COUNT);
	}
	|
	ALLOW
	{
		cfg.set_rule_action(rule_action_t::ALLOW);
	}
	|
	DENY
	{
		cfg.set_rule_action(rule_action_t::DENY);
	}
	|
	DUMP dump_tag
	{
		cfg.set_rule_action(rule_action_t::DUMP);
	}
	|
	T_REJECT
	{
		cfg.set_rule_action(rule_action_t::UNREACH);
		cfg.set_rule_action_arg(1 /* ICMP_UNREACH_HOST */);
	}
	|
	RESET
	{
		cfg.set_rule_action(rule_action_t::UNREACH);
		cfg.set_rule_action_arg(0x100 /* ICMP_REJECT_RST */);
	}
	|
	UNREACH NUMBER
	{
		cfg.set_rule_action(rule_action_t::UNREACH);
		cfg.set_rule_action_arg($2);
	}
	|
	UNREACH6 NUMBER
	{
		cfg.set_rule_action(rule_action_t::UNREACH6);
		cfg.set_rule_action_arg($2);
	}
	|
	RESET6
	{
		cfg.set_rule_action(rule_action_t::UNREACH6);
		cfg.set_rule_action_arg(0x100 /* ICMP6_UNREACH_RST */);
	}
	|
	forwardip4
	{
		cfg.set_rule_action(rule_action_t::FORWARD);
	}
	|
	forwardip6
	{
		cfg.set_rule_action(rule_action_t::FORWARD);
	}
	|
	SETDSCP setdscpspec
	{
		cfg.set_rule_action(rule_action_t::SETDSCP);
	}
	|
	SETFIB setfibspec
	{
		cfg.set_rule_action(rule_action_t::SETFIB);
	}
	|
	SKIPTO NUMBER
	{
		cfg.set_rule_action(rule_action_t::SKIPTO);
		cfg.set_rule_action_arg($2);
	}
	|
	SKIPTO TABLEARG
	{
		cfg.set_rule_action(rule_action_t::SKIPTO);
		cfg.set_rule_action_arg(0 /* IP_FW_TARG */);
	}
	|
	SKIPTO LABEL
	{
		cfg.set_rule_action(rule_action_t::SKIPTO);
		cfg.set_rule_action_arg($2);
	}
	|
	CALL NUMBER
	{
		cfg.set_rule_action(rule_action_t::CALL);
		cfg.set_rule_action_arg($2);
	}
	|
	CALL TABLEARG
	{
		cfg.set_rule_action(rule_action_t::CALL);
		cfg.set_rule_action_arg(0 /* IP_FW_TARG */);
	}
	|
	CALL LABEL
	{
		cfg.set_rule_action(rule_action_t::CALL);
		cfg.set_rule_action_arg($2);
	}
	|
	DIVERT NUMBER
	{
		cfg.set_rule_action(rule_action_t::DIVERT);
		cfg.set_rule_action_arg($2);
	}
	|
	TEE NUMBER
	{
		cfg.set_rule_action(rule_action_t::TEE);
		cfg.set_rule_action_arg($2);
	}
	|
	REASS
	{
		cfg.set_rule_action(rule_action_t::REASS);
	}
	|
	NETGRAPH NUMBER
	{
		cfg.set_rule_action(rule_action_t::NETGRAPH);
		cfg.set_rule_action_arg($2);
	}
	|
	PIPE NUMBER
	{
		cfg.set_rule_action(rule_action_t::PIPE);
		cfg.set_rule_action_arg($2);
	}
	|
	QUEUE NUMBER
	{
		cfg.set_rule_action(rule_action_t::QUEUE);
		cfg.set_rule_action_arg($2);
	}
	|
	NAT64LSN TOKEN
	{
		cfg.set_rule_action(rule_action_t::NAT64LSN);
		cfg.set_rule_action_arg($2);
	}
	|
	NAT64STL TOKEN
	{
		cfg.set_rule_action(rule_action_t::NAT64STL);
		cfg.set_rule_action_arg($2);
	}
	|
	NAT64CLAT TOKEN
	{
		cfg.set_rule_action(rule_action_t::NAT64CLAT);
		cfg.set_rule_action_arg($2);
	}
	|
	NPTV6 TOKEN
	{
		cfg.set_rule_action(rule_action_t::NPTV6);
		cfg.set_rule_action_arg($2);
	}
	|
	SRCPRJID
	{
		cfg.set_rule_action(rule_action_t::SRCPRJID);
	}
	|
	DSTPRJID
	{
		cfg.set_rule_action(rule_action_t::DSTPRJID);
	}
	|
	TCPSETMSS NUMBER
	{
		cfg.set_rule_action(rule_action_t::TCPSETMSS);
		cfg.set_rule_action_arg($2);
	}
	;
forwardip4:
	FWD IP
	{
		cfg.set_rule_action_arg(rule_t::sockaddr_t {$2, 0});
	}
	|
	FWD IP COMMA NUMBER
	{
		cfg.set_rule_action_arg(rule_t::sockaddr_t {$2, (uint16_t)$4});
	}
	;
forwardip6:
	FWD IP6
	{
		cfg.set_rule_action(rule_action_t::ALLOW);
		cfg.set_rule_action_arg(rule_t::sockaddr_t {$2, 0});
	}
	|
	FWD IP6 COMMA NUMBER
	{
		cfg.set_rule_action_arg(rule_t::sockaddr_t {$2, (uint16_t)$4});
	}
	|
	FWD IP6SCOPIED
	{
		cfg.set_rule_action_arg($2);
	}
	|
	FWD IP6SCOPIED COMMA NUMBER
	{
		cfg.set_rule_action_arg($2 + "," + std::to_string($4));
	}
	;
natinstance:
	NUMBER
	{
		cfg.set_rule_action_arg($1);
	}
	|
	GLOBAL
	{
		cfg.set_rule_action_arg(65535 /* IP_FW_NAT44_GLOBAL */);
	}
	;
setdscpspec:
	NUMBER
	{
		if ($1 > 63)  {
			std::cerr << "dscpspec must be < 64" << std::endl;
			YYERROR;
		}
		cfg.set_rule_action_arg(0x8000 + $1);
	}
	|
	DSCPSPEC
	{
		cfg.set_rule_action_arg(0x8000 + $1);
	}
	|
	TABLEARG
	{
		cfg.set_rule_action_arg(0 /* IP_FW_TARG */);
	}
	;
setfibspec:
	NUMBER
	{
		if ($1 > 63)  { // maxfibs
			std::cerr << "fib must be < 64" << std::endl;
			YYERROR;
		}
		cfg.set_rule_action_arg(0x8000 + $1);
	}
	|
	TABLEARG
	{
		cfg.set_rule_action_arg(0 /* IP_FW_TARG */);
	}
	;
altq:
	ALTQ TOKEN
	{
	}
	;
tag:
	TAG tagunique NUMBER
	{
	}
	|
	TAG tagunique TABLEARG
	{
	}
	|
	UNTAG tagunique NUMBER
	{
	}
	|
	UNTAG tagunique TABLEARG
	{
	}
	;
tagunique:
	{
	}
	;
log:
	LOG set_have_log
	|
	LOG set_have_log logopts
	;
set_have_log:
	{
		cfg.set_rule_log();
	}
	;
logopts:
	logopt
	|
	logopts logopt
	;
logopt:
	LOGAMOUNT NUMBER
	{
	}
	|
	LOGDST logdstmask
	{
	}
	;
logdstmask:
	logdsttype
	|
	logdstmask COMMA logdsttype
	;
logdsttype:
	TOKEN
	{
	}
	;
rule:
	proto from to options
	{
	}
	|
	options
	{
	}
	;
from:
	FROM
	{
		cfg.set_rule_src(true);
	}
	statement srcports
	;
to:
	TO
	{
		cfg.set_rule_src(false);
	}
	statement dstports
	;
proto:
	T_IP
	{
		cfg.fill_rule_ipver(rule_t::ip_version_t::ANY);
	}
	|
	T_IP4
	{
		cfg.fill_rule_ipver(rule_t::ip_version_t::IPv4);
	}
	|
	T_IP6
	{
		cfg.fill_rule_ipver(rule_t::ip_version_t::IPv6);
	}
	|
	ALL
	{
		cfg.fill_rule_ipver(rule_t::ip_version_t::ANY);
	}
	|
	prototoken
	|
	OBRACE protoset EBRACE
	;
prototoken:
	TOKEN
	{
		cfg.fill_rule_proto($1);
	}
	|
	NUMBER
	{
		if ($1 > 255)  {
			std::cerr << "proto number must be < 256" << std::endl;
			YYERROR;
		}
		cfg.fill_rule_proto($1);
	}
	/*
	|
	NOT TOKEN
	{
		YYERROR;
	}
	*/
	;
protoset:
	prototoken
	|
	protoset OR prototoken
	;
statement: statementpre statementbody statementpost;

statementpre: { };
statementpost: { };

statementbody:
	statementtoken
	|
	not statementtoken
	|
	OBRACE statementset EBRACE
	;
statementtoken:
	IP
	{
		cfg.add_rule_addr($1);
	}
	|
	IPMASK
	{
		cfg.add_rule_addr($1);
	}
	|
	NETWORK
	{
		cfg.add_rule_addr($1);
	}
	|
	IP6
	{
		cfg.add_rule_addr($1);
	}
	|
	IP6MASK
	{
		cfg.add_rule_addr($1);
	}
	|
	NETWORK6
	{
		cfg.add_rule_addr($1);
	}
	|
	ANY
	{
		cfg.add_rule_addr_any();
	}
	|
	ME
	{
		cfg.add_rule_addr_me();
	}
	|
	ME6
	{
		cfg.add_rule_addr_me6();
	}
	|
	MACRO
	{
		cfg.add_rule_macro($1);
	}
	|
	FQDN
	{
		cfg.add_rule_fqdn($1);
	}
	|
	M4LQ FQDN M4RQ
	{
		cfg.add_rule_fqdn($2);
	}
	|
	TABLE LBRACE tableparam RBRACE
	{
		// XXX: we expect here that table already has all addresses
		cfg.add_table_addresses();
	}
	;
tableparam:
	tablename
	|
	tablename COMMA tablevalue
	;
tablename:
	NUMBER
	{
		cfg.set_rule_tablename(std::to_string($1));
	}
	|
	TABLENAME
	{
		cfg.set_rule_tablename($1);
	}
	|
	MACRO
	{
		cfg.set_rule_tablename($1);
	}
	;
tablevalue:
	NUMBER
	{
		cfg.set_rule_tablevalue($1);
	}
	|
	tvaluename EQUAL NUMBER
	{
		cfg.set_rule_tablevalue($3);
	}
	;
tvaluename:
	TAG
	{
		cfg.set_rule_valuetype(tables::valtype_t::TAG);
	}
	|
	PIPE
	{
		cfg.set_rule_valuetype(tables::valtype_t::PIPE);
	}
	|
	DIVERT
	{
		cfg.set_rule_valuetype(tables::valtype_t::DIVERT);
	}
	|
	SKIPTO
	{
		cfg.set_rule_valuetype(tables::valtype_t::SKIPTO);
	}
	|
	NETGRAPH
	{
		cfg.set_rule_valuetype(tables::valtype_t::NETGRAPH);
	}
	|
	FIB
	{
		cfg.set_rule_valuetype(tables::valtype_t::FIB);
	}
	|
	NAT
	{
		cfg.set_rule_valuetype(tables::valtype_t::NAT);
	}
	|
	NH4
	{
		cfg.set_rule_valuetype(tables::valtype_t::NH4);
	}
	|
	DSCP
	{
		cfg.set_rule_valuetype(tables::valtype_t::DSCP);
	}
	|
	LIMIT
	{
		cfg.set_rule_valuetype(tables::valtype_t::LIMIT);
	}
	;
not:
	NOT
	{
	}
	;
statementset:
	statementtoken
	|
	not statementtoken
	|
	statementset OR statementtoken
	|
	statementset COMMA statementtoken
	;
srcports:
	|
	portsoption
	|
	SRCPORT portsoption
	;
dstports:
	|
	portsoption
	;
portsoption:
	porttoken
	|
	portsoption COMMA porttoken
	;
portdir:
	SRCPORT
	{
		cfg.set_rule_src(true);
	}
	|
	DSTPORT
	{
		cfg.set_rule_src(false);
	}
	;
addrdir:
	SRCADDR
	{
		cfg.set_rule_src(true);
	}
	|
	DSTADDR
	{
		cfg.set_rule_src(false);
	}
	;
porttoken:
	ANY
	{
		// XXX: should we clear ports list?
	}
	|
	TOKEN
	{
		cfg.add_rule_ports($1);
	}
	|
	NUMBER
	{
		cfg.add_rule_ports((uint16_t)$1);
	}
	|
	RANGE
	{
		// XXX: ipfw(8) supports ranges for service names too
		cfg.add_rule_ports($1);
	}
	;
options:
	/* no options */
	|
	optiontoken options
	|
	not optiontoken options
	|
	obrace optionset ebrace options
	;
obrace:
	OBRACE
	{
	}
	;
ebrace:
	EBRACE
	{
	}
	;
viatoken:
	VIA
	{
		cfg.set_iface_direction(iface_direction_t::VIA);
	}
	|
	XMIT
	{
		cfg.set_iface_direction(iface_direction_t::XMIT);
	}
	|
	RECV
	{
		cfg.set_iface_direction(iface_direction_t::RECV);
	}
	;
viatarget:
	IP
	{
		WARN_UNSUPPORTED("via IP");
	}
	|
	TABLE LBRACE tablename RBRACE
	{
		cfg.add_via_table();
	}
	|
	ANY
	|
	FQDN
	{
		// XXX
		cfg.add_rule_iface($1);
	}
	|
	TOKEN
	{
		cfg.add_rule_iface($1);
	}
	;
lookup_spec:
	DSTIP { }
	|
	SRCIP { }
	|
	DSTPORT { }
	|
	SRCPORT { }
	|
	UID { }
	|
	JAIL { }
	|
	DSCP { }
	|
	RULENUM { }
	|
	DSTMAC { }
	|
	SRCMAC { }
	;
addroption:
	statementtoken
	|
	addroption COMMA statementtoken
	;
optiontoken:
	addrdir addroption
	|
	portdir portsoption
	|
	LOOKUP lookup_spec tablename
	{
	}
	|
	PROTO prototoken
	|
	viatoken viatarget
	|
	IN
	{
		cfg.set_rule_opcode(rule_t::opcode_t::DIRECTION);
		cfg.add_rule_opcode(rule_t::direction_t::IN);
	}
	|
	OUT
	{
		cfg.set_rule_opcode(rule_t::opcode_t::DIRECTION);
		cfg.add_rule_opcode(rule_t::direction_t::OUT);
	}
	|
	FRAG
	{
		cfg.set_rule_options(rule_t::flags_options_t::IPOFFSETFLAGS);
	}
	fragspec
	|
	SETUP
	{
		cfg.set_rule_options(rule_t::flags_options_t::TCPFLAGS);
		cfg.set_rule_flag(rule_t::tcp_flags_t::SYN);
		cfg.clear_rule_flag(rule_t::tcp_flags_t::ACK);
	}
	|
	ESTABLISHED
	{
		cfg.set_rule_opcode(rule_t::opcode_t::TCPESTABLISHED);
		cfg.add_rule_opcode(1);
	}
	|
	ICMPTYPES
	{
		cfg.set_rule_opcode(rule_t::opcode_t::ICMPTYPE);
	}
	icmptypes
	|
	ICMP6TYPES
	{
		cfg.set_rule_opcode(rule_t::opcode_t::ICMP6TYPE);
	}
	icmptypes
	|
	keepstate
	{
		cfg.set_rule_opcode(rule_t::opcode_t::KEEPSTATE);
		cfg.add_rule_opcode(1);
	}
	|
	DIVERTED
	{
	}
	|
	DIVERTEDLOOPBACK
	{
	}
	|
	DIVERTEDOUTPUT
	{
	}
	|
	LIMIT source NUMBER statename
	{
	}
	|
	TCPFLAGS
	{
		cfg.set_rule_options(rule_t::flags_options_t::TCPFLAGS);
	}
	tcpflags
	|
	TCPOPTIONS
	{
		cfg.set_rule_options(rule_t::flags_options_t::TCPOPTIONS);
	}
	tcpoptions
	|
	IPID
	{
		cfg.set_rule_opcode(rule_t::opcode_t::IPID);
	}
	rangelist
	|
	IPLEN
	{
		cfg.set_rule_opcode(rule_t::opcode_t::IPLEN);
	}
	rangelist
	|
	IPOPTIONS ipoptions
	{
	}
	|
	IPTOS iptos
	{
	}
	|
	IPTTL
	{
		cfg.set_rule_opcode(rule_t::opcode_t::IPTTL);
	}
	rangelist
	|
	JAIL NUMBER
	{
	}
	|
	TCPDATALEN
	{
		cfg.set_rule_opcode(rule_t::opcode_t::TCPDATALEN);
	}
	rangelist
	|
	TCPSEQ NUMBER
	{
		cfg.set_rule_opcode(rule_t::opcode_t::TCPSEQ);
		cfg.add_rule_opcode((uint32_t)$2);
	}
	|
	TCPMSS
	{
		cfg.set_rule_opcode(rule_t::opcode_t::TCPMSS);
	}
	rangelist
	|
	TCPWIN
	{
		cfg.set_rule_opcode(rule_t::opcode_t::TCPWIN);
	}
	rangelist
	|
	ANTISPOOF
	{
	}
	|
	VERREVPATH
	{
	}
	|
	VERSRCREACH
	{
	}
	|
	EXT6HDR exthdropts
	{
	}
	|
	IPSEC
	{
	}
	|
	IPVER NUMBER
	{
	}
	|
	DSCP dscpspec
	{
	}
	|
	TAGGED rangelist
	{
	}
	|
	LAYER2
	{
	}
	|
	SRCMAC TABLE LBRACE tablename RBRACE
	{
	}
	|
	SRCMAC TABLE LBRACE tablename COMMA NUMBER RBRACE
	{
	}
	|
	DSTMAC TABLE LBRACE tablename RBRACE
	{
	}
	|
	DSTMAC TABLE LBRACE tablename COMMA NUMBER RBRACE
	{
	}
	;
fragspec:
	{
		cfg.set_rule_flag(rule_t::ipoff_flags_t::OFFSET);
	}
	|
	fragtoken
	|
	fragspec COMMA fragtoken
	;
fragtoken:
	RF
	{
		cfg.set_rule_flag(rule_t::ipoff_flags_t::RF);
	}
	|
	NOTCHAR RF
	{
		cfg.clear_rule_flag(rule_t::ipoff_flags_t::RF);
	}
	|
	DF
	{
		cfg.set_rule_flag(rule_t::ipoff_flags_t::DF);
	}
	|
	NOTCHAR DF
	{
		cfg.clear_rule_flag(rule_t::ipoff_flags_t::DF);
	}
	|
	MF
	{
		cfg.set_rule_flag(rule_t::ipoff_flags_t::MF);
	}
	|
	NOTCHAR MF
	{
		cfg.clear_rule_flag(rule_t::ipoff_flags_t::MF);
	}
	|
	OFFSET
	{
		cfg.set_rule_flag(rule_t::ipoff_flags_t::OFFSET);
	}
	|
	NOTCHAR OFFSET
	{
		cfg.clear_rule_flag(rule_t::ipoff_flags_t::OFFSET);
	}
	;
keepstate:
	KEEPSTATE
	|
	KEEPSTATE LABEL
	;
dscpspec:
	dscpspectoken
	|
	dscpspec COMMA dscpspectoken
	;
dscpspectoken:
	DSCPSPEC
	{
	}
	|
	NUMBER
	{
	}
	;
rangelist:
	rangelistpart
	|
	rangelist COMMA rangelistpart
	;
rangelistpart:
	NUMBER
	{
		cfg.add_rule_opcode((uint32_t)$1);
	}
	|
	RANGE
	{
		cfg.add_rule_opcode($1);
	}
	;
optionset:
	optiontoken
	|
	not optiontoken
	|
	optionset OR optiontoken
	;
source:
	SRCADDR
	|
	DSTADDR
	|
	SRCPORT
	|
	DSTPORT
	;
statename:
	LABEL
	{
	}
	|
	{
	}
	;
tcpflagstoken:
	FIN
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::FIN);
	}	
	|
	NOTCHAR FIN
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::FIN);
	}
	|
	SYN
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::SYN);
	}	
	|
	NOTCHAR SYN
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::SYN);
	}	
	|
	RST
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::RST);
	}	
	|
	NOTCHAR RST
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::RST);
	}	
	|
	PSH
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::PUSH);
	}	
	|
	NOTCHAR PSH
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::PUSH);
	}	
	|
	ACK
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::ACK);
	}	
	|
	NOTCHAR ACK
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::ACK);
	}	
	|
	URG
	{
		cfg.set_rule_flag(rule_t::tcp_flags_t::URG);
	}	
	|
	NOTCHAR URG
	{
		cfg.clear_rule_flag(rule_t::tcp_flags_t::URG);
	}	
	;
tcpflags:
	tcpflagstoken
	|
	tcpflags COMMA tcpflagstoken
	;
tcpoptionstoken:
	MSS
	{
		cfg.set_rule_flag(rule_t::tcp_options_t::MSS);
	}
	|
	NOTCHAR MSS
	{
		cfg.clear_rule_flag(rule_t::tcp_options_t::MSS);
	}
	|
	WINDOW
	{
		cfg.set_rule_flag(rule_t::tcp_options_t::WIN);
	}
	|
	NOTCHAR WINDOW
	{
		cfg.clear_rule_flag(rule_t::tcp_options_t::WIN);
	}
	|
	SACK
	{
		cfg.set_rule_flag(rule_t::tcp_options_t::SACK);
	}
	|
	NOTCHAR SACK
	{
		cfg.clear_rule_flag(rule_t::tcp_options_t::SACK);
	}
	|
	TS
	{
		cfg.set_rule_flag(rule_t::tcp_options_t::TIMESTAMP);
	}
	|
	NOTCHAR TS
	{
		cfg.clear_rule_flag(rule_t::tcp_options_t::TIMESTAMP);
	}
	|
	CC
	{
		cfg.set_rule_flag(rule_t::tcp_options_t::CC);
	}
	|
	NOTCHAR CC
	{
		cfg.clear_rule_flag(rule_t::tcp_options_t::CC);
	}
	;
tcpoptions:
	tcpoptionstoken
	|
	tcpoptions COMMA tcpoptionstoken
	;
ipoptionstoken:
	SSRR
	{
	}
	|
	LSRR
	{
	}
	|
	RR
	{
	}
	|
	TS
	{
	}
	;
ipoptions:
	ipoptionstoken
	|
	NOTCHAR ipoptionstoken
	|
	ipoptions COMMA ipoptionstoken
	;
iptostoken:
	LOWDELAY
	{
	}
	|
	THROUGHPUT
	{
	}
	|
	RELIABILITY
	{
	}
	|
	MINCOST
	{
	}
	|
	CONGESTION
	{
	}
	;
iptos:
	iptostoken
	|
	NOTCHAR iptostoken
	|
	iptos COMMA iptostoken
	;
icmptypes:
	icmptype
	|
	icmptypes COMMA icmptype
	;
icmptype:
	NUMBER
	{
		cfg.add_rule_opcode((uint32_t)$1);
	}
	;
exthdropts:
	exthdropt
	|
	exthdropts COMMA exthdropt
	;
exthdropt:
	FRAG
	{
	}
	|
	HOPOPT
	{
	}
	|
	ROUTE
	{
	}
	|
	DSTOPT
	{
	}
	|
	/*
	AH
	{
	}
	|
	ESP
	{
	}
	|
	*/
	RTHDR0
	{
	}
	|
	RTHDR2
	{
	}
	;

/* Unsupported by YaNET */

nat:
	NAT NUMBER CONFIG natconfig EOL
	{
		WARN_UNSUPPORTED("nat");
	}
	;
pipequeue:
	PIPE NUMBER CONFIG pipeconfig EOL
	{
		WARN_UNSUPPORTED("pipe");
	}
	|
	QUEUE NUMBER CONFIG queueconfig EOL
	{
		WARN_UNSUPPORTED("queue");
	}
	|
	SCHED NUMBER CONFIG schedconfig EOL
	{
		WARN_UNSUPPORTED("sched");
	}
	;
extmodules:
	NPTV6 TOKEN CREATE nptv6config EOL
	{
		WARN_UNSUPPORTED("nptv6");
	}
	|
	NAT64LSN TOKEN CREATE nat64lsn_config EOL
	{
		WARN_UNSUPPORTED("nat64lsn");
	}
	|
	NAT64STL TOKEN CREATE nat64stl_config EOL
	{
		WARN_UNSUPPORTED("nat64stl");
	}
	|
	NAT64CLAT TOKEN CREATE nat64clat_config EOL
	{
		WARN_UNSUPPORTED("nat64clat");
	}
	;
natconfig:
	natrule
	|
	natconfig natrule
	;
natrule:
	T_IP IP | IF TOKEN | LOG | DENY_IN | SAME_PORTS
	| SKIP_GLOBAL | UNREG_ONLY | RESET | REVERSE
	| PROXY_ONLY | REDIRECT_ADDR RAspec
	| REDIRECT_PORT TOKEN RPORTspec
	| REDIRECT_PROTO TOKEN RPROTOspec
	;
RPROTOspec:
	IP | IP IP | IP IP IP
	;
RPORTspec:
	RPORTrangeladdr RPORTrangepaddr RPORTrangeraddr
	|
	RPORTsingleladdr RPORTsinglepaddr RPORTsingleraddr
	;
RPORTrangeladdr:
	SOCKADDR4 MINUS NUMBER
	;
RPORTrangepaddr:
	RANGE | SOCKADDR4 MINUS NUMBER
	;
RPORTrangeraddr:
	| IP | SOCKADDR4 MINUS NUMBER
	;
RPORTsingleladdr:
	RPORTladdr | RPORTladdr COMMA RPORTsingleladdr
	;
RPORTladdr:
	SOCKADDR4
	;
RPORTsinglepaddr:
	NUMBER | SOCKADDR4
	;
RPORTsingleraddr:
	| IP | SOCKADDR4
	;
RAspec:
	RAlocaladdr IP
	;
RAlocaladdr:
	RAlocalip
	|
	RAlocaladdr COMMA RAlocalip
	;
RAlocalip:
	IP
	;
pipeconfig:
	pipetoken
	|
	pipeconfig pipetoken 
	;
pipetoken:
	BW bandwidth
	|
	BW TOKEN
	|
	PDELAY NUMBER
	|
	BURST TOKEN
	|
	PROFILE TOKEN
	|
	BUCKETS NUMBER
	|
	MASK mask
	|
	pipequeueopt
	;
queueconfig:
	queuetoken
	|
	queueconfig queuetoken
	;
queuetoken:
	PIPE NUMBER
	|
	BUCKETS NUMBER
	|
	MASK mask
	|
	pipequeueopt
	;
schedconfig:
	schedtoken
	|
	schedconfig schedtoken 
	;
schedtoken:
	TYPE TOKEN
	|
	BUCKETS NUMBER
	|
	MASK mask
	|
	pipequeueopt
	;
pipequeueopt:
	WEIGHT NUMBER
	|
	LMAX NUMBER
	|
	PRIORITY NUMBER
	|
	FLOWMASK mask
	|
	SCHEDMASK mask
	|
	NOERROR
	|
	PLR FLOAT
	|
	QUEUE SIZEK
	|
	QUEUE NUMBER
	|
	DROPTAIL
	|
	RED REDPARAM
	;
bandwidth:
	BWBS
	|
	BWBTS
	|
	BWKBS
	|
	BWKBTS
	|
	BWMBS
	|
	BWMBTS
	;
mask:
	maskopt
	|
	mask maskopt
	;
maskopt:
	DSTIP6 NUMBER
	|
	SRCIP6 NUMBER
	|
	FLOWID masktoken
	|
	DSTIP masktoken
	|
	SRCIP masktoken
	|
	DSTPORT masktoken
	|
	SRCPORT masktoken
	|
	PROTO masktoken
	|
	QUEUE
	|
	ALL
	;
masktoken:
	HEXMASK
	|
	MASKLEN 
	;
nat64clat_config:
	nat64clat_token
	|
	nat64clat_config nat64clat_token
	;
nat64clat_token:
	CLAT_PREFIX NETWORK6
	|
	PLAT_PREFIX NETWORK6
	|
	ALLOW_PRIVATE
	|
	LOG
	;
nat64stl_config:
	nat64stl_token
	|
	nat64stl_config nat64stl_token
	;
nat64stl_token:
	TABLE4 TABLENAME
	|
	TABLE6 TABLENAME
	|
	PREFIX6 NETWORK6
	|
	ALLOW_PRIVATE
	|
	LOG
	;
nat64lsn_config:
	nat64lsn_token
	|
	nat64lsn_config nat64lsn_token
	;
nat64lsn_token:
	PREFIX4 NETWORK
	|
	PREFIX6 NETWORK6
	|
	AGG_LEN NUMBER 
	|
	AGG_COUNT NUMBER
	|
	PORT_RANGE NUMBER
	|
	PORT_RANGE NUMBER ':' NUMBER 
	|
	MAX_PORTS NUMBER
	|
	STATES_CHUNKS NUMBER
	|
	JMAXLEN NUMBER
	|
	NH_DEL_AGE NUMBER
	|
	PG_DEL_AGE NUMBER
	|
	TCP_SYN_AGE NUMBER
	|
	TCP_EST_AGE NUMBER
	|
	TCP_CLOSE_AGE NUMBER
	|
	UDP_AGE NUMBER
	|
	ICMP_AGE NUMBER
	|
	LOG
	|
	ALLOW_PRIVATE
	|
	SWAP_CONF
	;
nptv6config:
	nptv6token
	|
	nptv6config nptv6token
	;
dump_tag:
	TOKEN
	{
	cfg.set_dump_action_arg($1);
	}
	|
	NUMBER
	{
	cfg.set_dump_action_arg($1);
	}
	;
nptv6token:
	INT_PREFIX NETWORK6
	|
	INT_PREFIX IP6
	|
	EXT_PREFIX NETWORK6
	|
	EXT_PREFIX IP6
	|
	PREFIXLEN NUMBER
	;
%%

// -- epilogue section of parser source --

namespace ipfw {
  // Mandatory error function
  void
  fw_parser_t::error(const fw_parser_t::location_type& loc,
      const std::string& msg)
  {
	std::cerr << loc << ": " << msg << '\n';
  }
}

