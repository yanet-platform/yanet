/* generate C++ lexer */
%option c++

/* rename yyFlexLexer generated class to fwFlexLexer */
%option	prefix="fw"

/* generate yylex as member function of our yyFlexLexer-derived class */
%option yyclass="ipfw::fw_lexer_t"

/* unmatched scanner input produces an error */
%option nodefault

/* do not generate functions that will not be used */
%option nomain nounput noyywrap

/* generate code to mantain current line number */
/* %option	yylineno */

/* generate debug tracing */
%option debug

/* we do implement include support, declare start condition */
%x	IFILE
%s	M4QM

/* prologue of lexer source file */
%{
  // flex-generated code uses std streams without namespace
  using std::cin;
  using std::cout;
  using std::cerr;

  // include parser header file
  #include "libfwparser/fw_parser.h"

  // include parser's state header file
  #include "libfwparser/fw_config.h"

  // include lexer header file
  #include "libfwparser/fw_lexer.h"

  // yylex function declaration
  #undef YY_DECL
  #define YY_DECL ipfw::fw_parser_t::symbol_type ipfw::fw_lexer_t::Lex(ipfw::fw_config_t& cfg)

  #define yyterminate()	return ipfw::fw_parser_t::make_YYEOF(*ploc)

  // adjust current location each time a pattern is matched
  // concatenate rule tokens and save result into m_line
  #define YY_USER_ACTION  do {			\
	  ploc->columns(YYLeng());		\
	  if (!YY_AT_BOL() && m_save)		\
		m_line.append(YYText());	\
  } while (0);
%}

digit	[0-9]
digits	{digit}+
float	{digits}\.{digits}
hexdigit [0-9a-fA-F]
octet	{digit}{1,3}
ip4	({octet}\.){3}{octet}
network	{ip4}\/{digit}+
hexadecatet {hexdigit}{1,4}
lu32	({hexadecatet}:{hexadecatet}|{ip4})
ip6	(({hexadecatet}:){6}{lu32})|(::({hexadecatet}:){5}{lu32})|(({hexadecatet}?)::({hexadecatet}:){4}{lu32})|((({hexadecatet}:){0,1}{hexadecatet})?::(({hexadecatet}:){3}{lu32}))|((({hexadecatet}:){0,2}{hexadecatet})?::(({hexadecatet}:){2}{lu32}))|((({hexadecatet}:){0,3}{hexadecatet})?::({hexadecatet}:{lu32}))|((({hexadecatet}:){0,4}{hexadecatet})?::{lu32})|((({hexadecatet}:){0,5}{hexadecatet})?::{hexadecatet})|((({hexadecatet}:){0,6}{hexadecatet})?::)
ip6scopied	{ip6}%[a-zA-Z0-9._]+
network6 {ip6}\/{digit}+
net6prjid	{hexdigit}{1,8}(\/{digit}+)?@{network6}
label	:[-\.0-9A-Za-z_]+
macro	_[0-9A-Z_]+_
tablename	[-\.0-9A-Za-z]{1,63}
host	[0-9A-Za-z][-0-9A-Za-z]*
tld	[A-Za-z]+
domain	({host}\.)+{tld}\.?
fqdn	({host}\.)?{domain}

%%
%{// this code run each time yylex is called.
  auto ploc = &cfg.m_location.top();
  ploc->step();
%}

^include[ \t]+\" 	{ BEGIN IFILE; m_save = true; m_line.clear(); }
<IFILE>[^\t\n\"]+	/* gather file name */
<IFILE>\"		{
			  const auto length = m_line.size();
			  if (length == 1)
				throw ipfw::fw_parser_t::syntax_error(*ploc, "empty file name");
			  if (!cfg.open(m_line.substr(0, length - 1)))
				  yyterminate();
			  /* update location pointer, since we open new file */
			  ploc = &cfg.m_location.top();
			  m_save = false;
			  BEGIN INITIAL;
			}
<IFILE>.|\n		{ throw ipfw::fw_parser_t::syntax_error(*ploc, "bad #include line"); }
<<EOF>>			{
			  if (!cfg.close())
				  yyterminate();
			  /* update location pointer, since we open new file */
			  ploc = &cfg.m_location.top();
			}
actual			return ipfw::fw_parser_t::make_ACTUAL(*ploc);
stale			return ipfw::fw_parser_t::make_STALE(*ploc);
^[ \t]*add[ \t]*	{ m_save = true; m_line.clear(); return ipfw::fw_parser_t::make_ADDRULE(*ploc); }
add			return ipfw::fw_parser_t::make_ADD(*ploc);
allow|accept|pass	return ipfw::fw_parser_t::make_ALLOW(*ploc);
permit			return ipfw::fw_parser_t::make_ALLOW(*ploc);
deny_in			return ipfw::fw_parser_t::make_DENY_IN(*ploc);
deny|drop		return ipfw::fw_parser_t::make_DENY(*ploc);
dump            return ipfw::fw_parser_t::make_DUMP(*ploc);
reject			return ipfw::fw_parser_t::make_T_REJECT(*ploc);
unreach			return ipfw::fw_parser_t::make_UNREACH(*ploc);
unreach6		return ipfw::fw_parser_t::make_UNREACH6(*ploc);
skipto			return ipfw::fw_parser_t::make_SKIPTO(*ploc);
divert			return ipfw::fw_parser_t::make_DIVERT(*ploc);
tee			return ipfw::fw_parser_t::make_TEE(*ploc);
count			return ipfw::fw_parser_t::make_COUNT(*ploc);
setdscp			return ipfw::fw_parser_t::make_SETDSCP(*ploc);
setfib			return ipfw::fw_parser_t::make_SETFIB(*ploc);
dscp			return ipfw::fw_parser_t::make_DSCP(*ploc);
call			return ipfw::fw_parser_t::make_CALL(*ploc);
return			return ipfw::fw_parser_t::make_RETURN(*ploc);
tag			return ipfw::fw_parser_t::make_TAG(*ploc);
untag			return ipfw::fw_parser_t::make_UNTAG(*ploc);
tagged			return ipfw::fw_parser_t::make_TAGGED(*ploc);
altq			return ipfw::fw_parser_t::make_ALTQ(*ploc);
pipe			return ipfw::fw_parser_t::make_PIPE(*ploc);
queue|flowset		return ipfw::fw_parser_t::make_QUEUE(*ploc);
reass			return ipfw::fw_parser_t::make_REASS(*ploc);
config			return ipfw::fw_parser_t::make_CONFIG(*ploc);
bw|bandwidth		return ipfw::fw_parser_t::make_BW(*ploc);
weight			return ipfw::fw_parser_t::make_WEIGHT(*ploc);
buckets			return ipfw::fw_parser_t::make_BUCKETS(*ploc);
mask			return ipfw::fw_parser_t::make_MASK(*ploc);
sched_mask		return ipfw::fw_parser_t::make_SCHEDMASK(*ploc);
noerror			return ipfw::fw_parser_t::make_NOERROR(*ploc);
plr			return ipfw::fw_parser_t::make_PLR(*ploc);
droptail		return ipfw::fw_parser_t::make_DROPTAIL(*ploc);
flow-id			return ipfw::fw_parser_t::make_FLOWID(*ploc);
delay			return ipfw::fw_parser_t::make_PDELAY(*ploc);
sched			return ipfw::fw_parser_t::make_SCHED(*ploc);
flow_mask		return ipfw::fw_parser_t::make_FLOWMASK(*ploc);
link			return ipfw::fw_parser_t::make_LINK(*ploc);
pri|priority		return ipfw::fw_parser_t::make_PRIORITY(*ploc);
type			return ipfw::fw_parser_t::make_TYPE(*ploc);
valtype			return ipfw::fw_parser_t::make_VALTYPE(*ploc);
algo			return ipfw::fw_parser_t::make_ALGO(*ploc);
fib			return ipfw::fw_parser_t::make_FIB(*ploc);
profile			return ipfw::fw_parser_t::make_PROFILE(*ploc);
burst			return ipfw::fw_parser_t::make_BURST(*ploc);
check-state		return ipfw::fw_parser_t::make_CHECKSTATE(*ploc);
fwd|forward		return ipfw::fw_parser_t::make_FWD(*ploc);
log			return ipfw::fw_parser_t::make_LOG(*ploc);
logamount		return ipfw::fw_parser_t::make_LOGAMOUNT(*ploc);
logdst			return ipfw::fw_parser_t::make_LOGDST(*ploc);
setup			return ipfw::fw_parser_t::make_SETUP(*ploc);
established		return ipfw::fw_parser_t::make_ESTABLISHED(*ploc);
frag			return ipfw::fw_parser_t::make_FRAG(*ploc);
mf			return ipfw::fw_parser_t::make_MF(*ploc);
rf			return ipfw::fw_parser_t::make_RF(*ploc);
df			return ipfw::fw_parser_t::make_DF(*ploc);
offset			return ipfw::fw_parser_t::make_OFFSET(*ploc);
keep-state		return ipfw::fw_parser_t::make_KEEPSTATE(*ploc);
icmptype|icmptypes	return ipfw::fw_parser_t::make_ICMPTYPES(*ploc);
icmp6type|icmp6types	return ipfw::fw_parser_t::make_ICMP6TYPES(*ploc);
from			return ipfw::fw_parser_t::make_FROM(*ploc);
to			return ipfw::fw_parser_t::make_TO(*ploc);
me			return ipfw::fw_parser_t::make_ME(*ploc);
me6			return ipfw::fw_parser_t::make_ME6(*ploc);
any			return ipfw::fw_parser_t::make_ANY(*ploc);
in			return ipfw::fw_parser_t::make_IN(*ploc);
out			return ipfw::fw_parser_t::make_OUT(*ploc);
via			return ipfw::fw_parser_t::make_VIA(*ploc);
xmit			return ipfw::fw_parser_t::make_XMIT(*ploc);
recv			return ipfw::fw_parser_t::make_RECV(*ploc);
or			return ipfw::fw_parser_t::make_OR(*ploc);
not			return ipfw::fw_parser_t::make_NOT(*ploc);
limit			return ipfw::fw_parser_t::make_LIMIT(*ploc);
table			return ipfw::fw_parser_t::make_TABLE(*ploc);
tcpflags		return ipfw::fw_parser_t::make_TCPFLAGS(*ploc);
tcpoptions		return ipfw::fw_parser_t::make_TCPOPTIONS(*ploc);
ip			return ipfw::fw_parser_t::make_T_IP(*ploc);
ip4			return ipfw::fw_parser_t::make_T_IP4(*ploc);
ip6			return ipfw::fw_parser_t::make_T_IP6(*ploc);
iplen			return ipfw::fw_parser_t::make_IPLEN(*ploc);
ipid			return ipfw::fw_parser_t::make_IPID(*ploc);
ipoptions		return ipfw::fw_parser_t::make_IPOPTIONS(*ploc);
iptos			return ipfw::fw_parser_t::make_IPTOS(*ploc);
ipttl			return ipfw::fw_parser_t::make_IPTTL(*ploc);
tcpdatalen		return ipfw::fw_parser_t::make_TCPDATALEN(*ploc);
tcpseq			return ipfw::fw_parser_t::make_TCPSEQ(*ploc);
tcpwin			return ipfw::fw_parser_t::make_TCPWIN(*ploc);
fin			return ipfw::fw_parser_t::make_FIN(*ploc);
syn			return ipfw::fw_parser_t::make_SYN(*ploc);
rst			return ipfw::fw_parser_t::make_RST(*ploc);
psh			return ipfw::fw_parser_t::make_PSH(*ploc);
ack			return ipfw::fw_parser_t::make_ACK(*ploc);
urg			return ipfw::fw_parser_t::make_URG(*ploc);
mss			return ipfw::fw_parser_t::make_MSS(*ploc);
tcpmss			return ipfw::fw_parser_t::make_TCPMSS(*ploc);
window			return ipfw::fw_parser_t::make_WINDOW(*ploc);
sack			return ipfw::fw_parser_t::make_SACK(*ploc);
ts			return ipfw::fw_parser_t::make_TS(*ploc);
cc			return ipfw::fw_parser_t::make_CC(*ploc);
ssrr			return ipfw::fw_parser_t::make_SSRR(*ploc);
lsrr			return ipfw::fw_parser_t::make_LSRR(*ploc);
rr			return ipfw::fw_parser_t::make_RR(*ploc);
lowdelay		return ipfw::fw_parser_t::make_LOWDELAY(*ploc);
throughput		return ipfw::fw_parser_t::make_THROUGHPUT(*ploc);
reliability		return ipfw::fw_parser_t::make_RELIABILITY(*ploc);
mincost			return ipfw::fw_parser_t::make_MINCOST(*ploc);
congestion		return ipfw::fw_parser_t::make_CONGESTION(*ploc);
net			return ipfw::fw_parser_t::make_NET(*ploc);
host			return ipfw::fw_parser_t::make_HOST(*ploc);
proto			return ipfw::fw_parser_t::make_PROTO(*ploc);
port			return ipfw::fw_parser_t::make_PORT(*ploc);
needfrag		return ipfw::fw_parser_t::make_NEEDFRAG(*ploc);
srcfail			return ipfw::fw_parser_t::make_SRCFAIL(*ploc);
net-unknown		return ipfw::fw_parser_t::make_NETUNKNOWN(*ploc);
host-unknown		return ipfw::fw_parser_t::make_HOSTUNKNOWN(*ploc);
isolated		return ipfw::fw_parser_t::make_ISOLATED(*ploc);
net-prohib		return ipfw::fw_parser_t::make_NETPROHIB(*ploc);
host-prohib		return ipfw::fw_parser_t::make_HOSTPROHIB(*ploc);
tosnet			return ipfw::fw_parser_t::make_TOSNET(*ploc);
toshost			return ipfw::fw_parser_t::make_TOSHOST(*ploc);
filter-prohib		return ipfw::fw_parser_t::make_FILTERPROHIB(*ploc);
host-precedence		return ipfw::fw_parser_t::make_HOSTPRECEDENCE(*ploc);
precedence-cutoff	return ipfw::fw_parser_t::make_PRECEDENCECUTOFF(*ploc);
diverted-loopback	return ipfw::fw_parser_t::make_DIVERTEDLOOPBACK(*ploc);
diverted-output		return ipfw::fw_parser_t::make_DIVERTEDOUTPUT(*ploc);
diverted		return ipfw::fw_parser_t::make_DIVERTED(*ploc);
nat			return ipfw::fw_parser_t::make_NAT(*ploc);
nh4			return ipfw::fw_parser_t::make_NH4(*ploc);
netgraph		return ipfw::fw_parser_t::make_NETGRAPH(*ploc);
same_ports		return ipfw::fw_parser_t::make_SAME_PORTS(*ploc);
if			return ipfw::fw_parser_t::make_IF(*ploc);
unreg_only		return ipfw::fw_parser_t::make_UNREG_ONLY(*ploc);
verrevpath		return ipfw::fw_parser_t::make_VERREVPATH(*ploc);
versrcreach		return ipfw::fw_parser_t::make_VERSRCREACH(*ploc);
antispoof		return ipfw::fw_parser_t::make_ANTISPOOF(*ploc);
reset			return ipfw::fw_parser_t::make_RESET(*ploc);
reset6			return ipfw::fw_parser_t::make_RESET6(*ploc);
reverse			return ipfw::fw_parser_t::make_REVERSE(*ploc);
proxy_only		return ipfw::fw_parser_t::make_PROXY_ONLY(*ploc);
redirect_addr		return ipfw::fw_parser_t::make_REDIRECT_ADDR(*ploc);
redirect_port		return ipfw::fw_parser_t::make_REDIRECT_PORT(*ploc);
redirect_proto		return ipfw::fw_parser_t::make_REDIRECT_PROTO(*ploc);
skip_global		return ipfw::fw_parser_t::make_SKIP_GLOBAL(*ploc);
global			return ipfw::fw_parser_t::make_GLOBAL(*ploc);
ext6hdr			return ipfw::fw_parser_t::make_EXT6HDR(*ploc);
hopopt			return ipfw::fw_parser_t::make_HOPOPT(*ploc);
route			return ipfw::fw_parser_t::make_ROUTE(*ploc);
dstopt			return ipfw::fw_parser_t::make_DSTOPT(*ploc);
rthdr0			return ipfw::fw_parser_t::make_RTHDR0(*ploc);
rthdr2			return ipfw::fw_parser_t::make_RTHDR2(*ploc);
ipsec			return ipfw::fw_parser_t::make_IPSEC(*ploc);
ipversion		return ipfw::fw_parser_t::make_IPVER(*ploc);
create			return ipfw::fw_parser_t::make_CREATE(*ploc);
addr			return ipfw::fw_parser_t::make_ADDR(*ploc);
iface			return ipfw::fw_parser_t::make_IFACE(*ploc);
number			return ipfw::fw_parser_t::make_T_NUMBER(*ploc);
flow			return ipfw::fw_parser_t::make_FLOW(*ploc);
tablearg		return ipfw::fw_parser_t::make_TABLEARG(*ploc);
plat_prefix		return ipfw::fw_parser_t::make_PLAT_PREFIX(*ploc);
clat_prefix		return ipfw::fw_parser_t::make_CLAT_PREFIX(*ploc);
allow_private		return ipfw::fw_parser_t::make_ALLOW_PRIVATE(*ploc);
int_prefix		return ipfw::fw_parser_t::make_INT_PREFIX(*ploc);
ext_prefix		return ipfw::fw_parser_t::make_EXT_PREFIX(*ploc);
prefixlen		return ipfw::fw_parser_t::make_PREFIXLEN(*ploc);
prefix4			return ipfw::fw_parser_t::make_PREFIX4(*ploc);
prefix6			return ipfw::fw_parser_t::make_PREFIX6(*ploc);
agg_len			return ipfw::fw_parser_t::make_AGG_LEN(*ploc);
agg_count		return ipfw::fw_parser_t::make_AGG_COUNT(*ploc);
max_ports		return ipfw::fw_parser_t::make_MAX_PORTS(*ploc);
states_chunks		return ipfw::fw_parser_t::make_STATES_CHUNKS(*ploc);
jail			return ipfw::fw_parser_t::make_JAIL(*ploc);
jmaxlen			return ipfw::fw_parser_t::make_JMAXLEN(*ploc);
port_range		return ipfw::fw_parser_t::make_PORT_RANGE(*ploc);
nh_del_age		return ipfw::fw_parser_t::make_NH_DEL_AGE(*ploc);
host_del_age		return ipfw::fw_parser_t::make_NH_DEL_AGE(*ploc);
pg_del_age		return ipfw::fw_parser_t::make_PG_DEL_AGE(*ploc);
tcp_syn_age		return ipfw::fw_parser_t::make_TCP_SYN_AGE(*ploc);
tcp_est_age		return ipfw::fw_parser_t::make_TCP_EST_AGE(*ploc);
tcp_close_age		return ipfw::fw_parser_t::make_TCP_CLOSE_AGE(*ploc);
udp_age			return ipfw::fw_parser_t::make_UDP_AGE(*ploc);
icmp_age		return ipfw::fw_parser_t::make_ICMP_AGE(*ploc);
table4			return ipfw::fw_parser_t::make_TABLE4(*ploc);
table6			return ipfw::fw_parser_t::make_TABLE6(*ploc);
swap_conf		return ipfw::fw_parser_t::make_SWAP_CONF(*ploc);
layer2			return ipfw::fw_parser_t::make_LAYER2(*ploc);
mac			return ipfw::fw_parser_t::make_MAC(*ploc);
src-mac			return ipfw::fw_parser_t::make_SRCMAC(*ploc);
dst-mac			return ipfw::fw_parser_t::make_DSTMAC(*ploc);
!			return ipfw::fw_parser_t::make_NOTCHAR(*ploc);
lookup			return ipfw::fw_parser_t::make_LOOKUP(*ploc);
uid			return ipfw::fw_parser_t::make_UID(*ploc);
rulenum			return ipfw::fw_parser_t::make_RULENUM(*ploc);
srcprjid		return ipfw::fw_parser_t::make_SRCPRJID(*ploc);
dstprjid		return ipfw::fw_parser_t::make_DSTPRJID(*ploc);
gred|red		return ipfw::fw_parser_t::make_RED(*ploc);
lmax|maxlen		return ipfw::fw_parser_t::make_LMAX(*ploc);
dst-ip6|dst-ipv6	return ipfw::fw_parser_t::make_DSTIP6(*ploc);
src-ip6|src-ipv6	return ipfw::fw_parser_t::make_SRCIP6(*ploc);
tcp-setmss		return ipfw::fw_parser_t::make_TCPSETMSS(*ploc);
nat64clat		return ipfw::fw_parser_t::make_NAT64CLAT(*ploc);
nat64lsn		return ipfw::fw_parser_t::make_NAT64LSN(*ploc);
nat64stl		return ipfw::fw_parser_t::make_NAT64STL(*ploc);
nptv6			return ipfw::fw_parser_t::make_NPTV6(*ploc);
src-addr		return ipfw::fw_parser_t::make_SRCADDR(*ploc);
dst-addr		return ipfw::fw_parser_t::make_DSTADDR(*ploc);
src-port		return ipfw::fw_parser_t::make_SRCPORT(*ploc);
dst-port		return ipfw::fw_parser_t::make_DSTPORT(*ploc);
dst-ip			return ipfw::fw_parser_t::make_DSTIP(*ploc);
src-ip			return ipfw::fw_parser_t::make_SRCIP(*ploc);
all			return ipfw::fw_parser_t::make_ALL(*ploc);
\{			return ipfw::fw_parser_t::make_OBRACE(*ploc);
\}			return ipfw::fw_parser_t::make_EBRACE(*ploc);
\(			return ipfw::fw_parser_t::make_LBRACE(*ploc);
\)			return ipfw::fw_parser_t::make_RBRACE(*ploc);
=			return ipfw::fw_parser_t::make_EQUAL(*ploc);
,			return ipfw::fw_parser_t::make_COMMA(*ploc);
-			return ipfw::fw_parser_t::make_MINUS(*ploc);
\"			return ipfw::fw_parser_t::make_QM(*ploc);
`			{ BEGIN M4QM; return ipfw::fw_parser_t::make_M4LQ(*ploc); }
<M4QM>'			{ BEGIN INITIAL; return ipfw::fw_parser_t::make_M4RQ(*ploc); }
{float}			return ipfw::fw_parser_t::make_FLOAT(::strtof(yytext, NULL), *ploc);
0x{hexdigit}+		return ipfw::fw_parser_t::make_HEXMASK(::strtol(yytext+2, NULL, 16), *ploc);
\/{digits}		return ipfw::fw_parser_t::make_MASKLEN(::strtol(yytext+1, NULL, 10), *ploc);
{digits}[Bb]it\/s	return ipfw::fw_parser_t::make_BWBS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Bb]yte\/s	return ipfw::fw_parser_t::make_BWBTS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Kk][Bb]it\/s	return ipfw::fw_parser_t::make_BWKBS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Kk][Bb]yte\/s	return ipfw::fw_parser_t::make_BWKBTS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Mm][Bb]it\/s	return ipfw::fw_parser_t::make_BWMBS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Mm][Bb]yte\/s	return ipfw::fw_parser_t::make_BWMBTS(::strtol(yytext, NULL, 10), *ploc);
{digits}[Bb]ytes	return ipfw::fw_parser_t::make_SIZEK(::strtol(yytext, NULL, 10), *ploc);
{digits}[Kk][Bb]ytes	return ipfw::fw_parser_t::make_SIZEK(::strtol(yytext, NULL, 10) * 1024, *ploc);
{digits}		return ipfw::fw_parser_t::make_NUMBER(::strtol(yytext, NULL, 10), *ploc);
cs[0-7]|af[1-4][1-3]|ef|be|va	return make_DSCPSPEC(yytext, *ploc);
[a-z]+:[a-z]+		return ipfw::fw_parser_t::make_ALGO_NAME(yytext, *ploc);
{ip4}			return ipfw::fw_parser_t::make_IP(common::ipv4_address_t(yytext), *ploc);
{ip4}:{ip4}		return make_IPMASK(yytext, *ploc);
{ip4}\/{ip4}		return make_IPMASK(yytext, *ploc);
{ip4}:{digits}		return ipfw::fw_parser_t::make_SOCKADDR4(yytext, *ploc);
{ip6}			return ipfw::fw_parser_t::make_IP6(common::ipv6_address_t(yytext), *ploc);
{ip6}\/{ip6}		return make_IP6MASK(std::string(yytext), *ploc);
{ip6scopied}		return ipfw::fw_parser_t::make_IP6SCOPIED(yytext, *ploc);
{network}		return make_NETWORK(yytext, *ploc);
{network6}		return make_NETWORK6(yytext, *ploc);
{net6prjid}		return make_IP6PRJID(yytext, *ploc);
{digits}-{digits}	return ipfw::fw_parser_t::make_RANGE(std::string(yytext), *ploc);
{float}\/{digits}[Kk]\/{digits}[Kk]\/{float}	return ipfw::fw_parser_t::make_REDPARAM(yytext, *ploc);
{label}			return ipfw::fw_parser_t::make_LABEL(yytext, *ploc);
{macro}			return ipfw::fw_parser_t::make_MACRO(yytext, *ploc);
^{macro}:		return ipfw::fw_parser_t::make_MACRODEF(yytext, *ploc);
{fqdn}			return ipfw::fw_parser_t::make_FQDN(yytext, *ploc);
[a-zA-Z0-9][-\\a-zA-Z0-9\?\*\[\]_\.]+	return ipfw::fw_parser_t::make_TOKEN(yytext, *ploc);
{tablename}		return ipfw::fw_parser_t::make_TABLENAME(yytext, *ploc);
\/\/[ ][^\n]*		return ipfw::fw_parser_t::make_COMMENT(yytext+3, *ploc);
[ \t]+			/* ignore spaces */
#.*\n			{ ploc->lines(); /* ignore comments */ }
^[ \t]*\n		{ ploc->lines(); /* ignore empty lines */ }
\n			{ ploc->lines(); m_save = false; return ipfw::fw_parser_t::make_EOL(*ploc); }
.			throw ipfw::fw_parser_t::syntax_error(*ploc, "invalid character: " + std::string(yytext));
%%
