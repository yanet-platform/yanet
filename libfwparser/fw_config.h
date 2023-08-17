#pragma once

#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <stack>
#include <string>
#include <vector>

#include "common/type.h"
#include "libfwparser/fw_lexer.h"

#define FW_CONFIG_MAX_NESTED 5

namespace acl {
    struct rule_t;
    struct firewall_rules_t;
};

namespace ipfw {

    using string_ptr_t = std::unique_ptr<std::string>;

    // we keep list of config files that were opened and nesting level
    typedef struct fw_config_history {
        string_ptr_t name;
        size_t level;
    } fw_config_history_t;

    // we keep track for various definitions
    typedef struct location_history {
        size_t lineno; // line number in the config file
        size_t fileno; // file number in the history
    } location_history_t;

    using label_info_t = std::tuple<unsigned int, // ruleno
                                    location_history_t>;
    // single DNS name may have many IPv4 and IPv6 addresses
    using dns_addresses_t = std::tuple<location_history_t,
                                       std::set<common::ip_address_t>,
                                       bool>;

    // IPv4 addresses in form 1.2.3.4/255.0.255.0
    using ipv4_prefix_mask_t = std::tuple<common::ipv4_address_t,
                                          common::ipv4_address_t>;

    // IPv6 addresses in form 2a02:6b8:c00::4440:0:0/ffff:ffff:ff00:0:ffff:ffff::
    using ipv6_prefix_mask_t = std::tuple<common::ipv6_address_t,
                                          common::ipv6_address_t>;

    using ip_prefix_mask_t = std::variant<common::ip_address_t,
                                          common::ip_prefix_t,
                                          ipv4_prefix_mask_t,
                                          ipv6_prefix_mask_t>;

    inline std::ostream& operator<<(std::ostream& stream, const ip_prefix_mask_t& prefix)
    {
        switch (prefix.index()) {
            case 0:
                return stream << std::get<common::ip_address_t>(prefix).toString();
            case 1:
                return stream << std::get<common::ip_prefix_t>(prefix).toString();
            case 2: {
                const auto& [addr, mask] = std::get<ipv4_prefix_mask_t>(prefix);
                return stream << addr.toString() << "/" << mask.toString();
            } break;
            case 3: {
                const auto& [addr, mask] = std::get<ipv6_prefix_mask_t>(prefix);
                return stream << addr.toString() << "/" << mask.toString();
            } break;
        }
        return stream << "UNKNOWN_PREFIX";
    }

    // macro can keep IPv4 and IPv6 addresses, IPv4 and IPv6 prefixes
    // and hostnames. All thes objects can be stored as ip_prefix_mask_t.
    using macro_t = std::tuple<location_history_t,
                               std::set<ip_prefix_mask_t>,
                               bool>;

    // ipfw tables
    namespace tables {
        // table NAME add IFNAME
        // table NAME add IFNAME LABEL
        using ifname_entry_t = std::pair<std::string,
                                         std::string>;
        using ifname_t = std::map<std::string,
                                  std::string>;

        // table NAME add 1.2.3.4/24 LABEL
        using prefix_skipto_entry_t = std::pair<common::ip_prefix_t,
                                                std::string>;
        using prefix_skipto_t = std::map<common::ip_prefix_t,
                                         std::string,
                                         std::greater<common::ip_prefix_t>>;

        // the following variants should have matching order
        using table_type_t = std::variant<prefix_skipto_t,
                                          ifname_t>;
        using entry_type_t = std::variant<prefix_skipto_entry_t,
                                          ifname_entry_t>;
        // table entry context
        using curr_entry_t = std::variant<common::ip_prefix_t,   // IP[6], NETWORK[6]
                                          std::string>;          // FQDN
        using entry_value_t = std::variant<common::ip_address_t, // IP, IP6
                                           std::string,          // LABEL
                                           int64_t>;             // NUMBER
        enum class valtype_t {
            LEGACY,
            SKIPTO,
            PIPE,
            FIB,
            NAT,
            DSCP,
            TAG,
            DIVERT,
            NETGRAPH,
            LIMIT,
            NH4,
            NH6
        };
    }

    using table_t = std::tuple<location_history_t,
                               tables::table_type_t>;

    enum class rule_action_t {
        ALLOW,
        CALL,
        CHECKSTATE,
        COUNT,
        DENY,
        DIVERT,
        FORWARD,
        NAT,
        NAT64CLAT,
        NAT64LSN,
        NAT64STL,
        NETGRAPH,
        NGTEE,
        NPTV6,
        PIPE,
        QUEUE,
        REASS,
        RETURN,
        SETDSCP,
        SETFIB,
        SKIPTO,
        TCPSETMSS,
        TEE,
        UNREACH,
        UNREACH6,
        SRCPRJID,
        DSTPRJID,
    };

    enum class rule_action_modifier_t {
        ALTQ,
        LOG,
        TAG,
        UNTAG,
    };

    enum class iface_direction_t {
        RECV,
        XMIT,
        VIA,
    };

    // rule filters
    struct rule_t {
        enum rule_state_t {
            UNKNOWN = 0,
            RULENUMBER,
            ACTION,
            ACTIONMOD,
            PROTO,
            SOURCE,
            DESTINATION,
            OPTIONS,
        };
        enum ip_version_t {
            ANY = 0,
            IPv4 = 4,
            IPv6 = 6,
        };
        enum direction_t {
            IN = 0x01,
            OUT = 0x02,
            BOTH = 0x03,
        };

        enum class opcode_t {
            DIRECTION,
            KEEPSTATE,
            IPID,
            IPLEN,
            IPTTL,
            TCPACK,
            TCPDATALEN,
            TCPMSS,
            TCPSEQ,
            TCPWIN,
            TCPESTABLISHED,
            ICMPTYPE,
            ICMP6TYPE,
        };
        enum class flags_options_t {
            IPOPTIONS,
            IPOFFSETFLAGS,
            IPTOS,
            TCPOPTIONS,
            TCPFLAGS,
        };
        enum class validation_status_t {
            UNKNOWN,
            UNKNOWN_LABEL,
            EMPTY_SRC_MACRO,
            EMPTY_SRC_FQDN,
            EMPTY_SRC_TABLE,
            EMPTY_DST_MACRO,
            EMPTY_DST_FQDN,
            EMPTY_DST_TABLE,
        };

        std::string validation_status_to_string(validation_status_t status)
        {
            switch (status)
            {
                case validation_status_t::UNKNOWN_LABEL:
                    return "rule uses unknown label";
                case validation_status_t::EMPTY_SRC_MACRO:
                    return "rule has macro, but source addresses list is empty";
                case validation_status_t::EMPTY_SRC_FQDN:
                    return "rule has fqdn, but source addresses list is empty";
                case validation_status_t::EMPTY_SRC_TABLE:
                    return "rule has table, but source addresses list is empty";
                case validation_status_t::EMPTY_DST_MACRO:
                    return "rule has macro, but destination addresses list is empty";
                case validation_status_t::EMPTY_DST_FQDN:
                    return "rule has fqdn, but destination addresses list is empty";
                case validation_status_t::EMPTY_DST_TABLE:
                    return "rule has table, but destination addresses list is empty";
                case validation_status_t::UNKNOWN:
                    [[fallthrough]];
                default:
                    return "unknown";
            }
        }
        std::string vstatus_to_string()
        {
            return validation_status_to_string(vstatus);
        }
        void set_vstatus(validation_status_t status)
        {
            if (vstatus == validation_status_t::UNKNOWN)
                vstatus = status;
        }
        // we do not support "not protoname" syntax, otherwise we need to keep "not" flag
        using proto_t = std::set<uint8_t>;
        using ports_t = std::set<uint16_t>;
        using ports_ranges_t = common::ranges_t;
        using ports_arg_t = std::variant<common::range_t,
                                         std::string,
                                         uint16_t>;
        using address_t = std::set<ip_prefix_mask_t>;                  // addr, addr/len, addr/mask
        using sockaddr_t = std::tuple<common::ip_address_t, uint16_t>; // addr, port
        using action_arg_t = std::variant<std::string,
                                          sockaddr_t,
                                          int64_t>;
        using opcode_arg_t = std::variant<common::range_t,
                                          uint32_t>;

        location_history_t location; // file:lineno
        rule_state_t state = rule_state_t::UNKNOWN;
        bool keepstate = false;
        bool log = false;           // has log option
        unsigned int logamount = 0; // log limit
        unsigned int setno = 0;     // set number
        unsigned int ruleno = 0;    // rule number
        unsigned int ruleid = 0;
        uint8_t direction = 0;                  // in/out/both
        ip_version_t ipver = ip_version_t::ANY; // explicit IP version

        rule_action_t action{rule_action_t::DENY}; // rule action
        action_arg_t action_arg;                   // action argument
        proto_t proto;                             // list of IP protocols
        address_t src, dst;                        // sourc/destination
        bool src_targ, dst_targ;                   // skipto tablearg src/dst
        bool src_me, src_me6, src_any;             // special source specified
        bool dst_me, dst_me6, dst_any;             // special dst specified
        bool src_macros, src_fqdn, src_tables;
        bool dst_macros, dst_fqdn, dst_tables;
        std::string targ_name;                     // skipto tablearg table name
        ports_t sports, dports;                    // src-port/dst-port opcodes
        ports_ranges_t sports_range, dports_range; // src-port/dst-port ranges

        // frag opcode
        enum ipoff_flags_t {
            OFFSET = 0x01,
            MF = 0x20,
            DF = 0x40,
            RF = 0x80,
        };
        uint8_t ipoff_setflags, ipoff_clearflags; // IP frag flags set/clear

        // TCP opcodes
        enum tcp_flags_t {
            FIN = 0x01,
            SYN = 0x02,
            RST = 0x04,
            PUSH = 0x08,
            ACK = 0x10,
            URG = 0x20,
            ECE = 0x40,
            CWR = 0x80,
        };
        enum tcp_options_t {
            MSS = 0x01,
            WIN = 0x02,
            SACK = 0x04,
            TIMESTAMP = 0x08,
            CC = 0x10,
        };
        uint8_t tcp_setflags, tcp_clearflags; // TCP flags set/clear
        uint8_t tcp_setopts, tcp_clearopts;   // TCP options set/clear
        uint32_t tcp_ack, tcp_seq;            // TCP ACK/SEQ
        ports_t tcp_datalen;                  // TCP datalen
        ports_ranges_t tcp_datalen_range;
        ports_t tcp_mss; // TCP MSS
        ports_ranges_t tcp_mss_range;
        ports_t tcp_win; // TCP window
        ports_ranges_t tcp_win_range;
        bool tcp_established;

        // ICMPv4, ICMPv6
        ports_t icmp_types;
        ports_t icmp6_types;

        validation_status_t vstatus = validation_status_t::UNKNOWN;
        std::map<std::string, iface_direction_t> ifaces;                 // recv/xmit/via ifname
        std::map<iface_direction_t, std::set<std::string>> iface_tables; // via table(NAME)
        std::string comment;                                             // rule comment
        std::string text;                                                // original rule text
    };

    using rule_ptr_t = std::shared_ptr<rule_t>;
    using istream_ptr_t = std::shared_ptr<std::istream>;
    using fw_config_ptr_t = std::shared_ptr<fw_config_t>;
    using fw_config_ref_t = std::weak_ptr<fw_config_t>;

    // forward declaration

    class fw_config_t {
        friend class fw_parser_t;
        friend class fw_lexer_t;
        friend class fw_dump_t;

        friend struct acl::rule_t;
        friend struct acl::firewall_rules_t;

    public:
        fw_config_t(int step = 100);
        ~fw_config_t() = default;

        bool parse();
        bool validate();
        bool validate_rule(rule_ptr_t rulep);
        bool resolve_labels();

        int getservbyname(const std::string& service);
        int getprotobyname(const std::string& proto);

        bool schedule_stdin();
        bool schedule_file(const std::string& file);
        bool schedule_string(const std::string& str);

        // to handle lexer scanner coordination
        void set_debug(int level)
        {
            m_debug = level;
        }

        fw_parser_t::symbol_type Lex()
        {
            return m_lexer.Lex(*this);
        }

    public:
        void add_label(const std::string&);

        void set_macro(const std::string&);
        void fill_macro(const ip_prefix_mask_t&);
        void fill_macro_fqdn(const std::string& fqdn);

        void set_fqdn(const std::string&);
        void fill_fqdn(const common::ip_address_t&);
        const auto& resolve_fqdn(const std::string& s) const {
            return std::get<1>(m_dns_cache.at(s));
        }
        const auto& resolve_macro(const std::string& s) const {
            return std::get<1>(m_macros.at(s));
        }
        void set_table(const std::string&);
        void create_skipto_table();
        void create_iface_table();
        void fill_table_entry(const tables::curr_entry_t&);
        void fill_table_entry_value(const tables::entry_value_t&);

        void fill_rule_number(unsigned int);
        void set_rule_action(rule_action_t);
        void set_rule_action_arg(const rule_t::action_arg_t&);
        void set_rule_log()
        {
            m_curr_rule->log = true;
        }
        void fill_rule_proto(uint8_t);
        void fill_rule_proto(const std::string&);
        void fill_rule_ipver(rule_t::ip_version_t ver);
        void fill_rule_text();
        void add_rule_addr(const ip_prefix_mask_t&);
        void add_rule_addr_any();
        void add_rule_addr_me();
        void add_rule_addr_me6();
        void add_rule_macro(const std::string& macro);
        void add_rule_table(const std::string& name);
        void add_rule_fqdn(const std::string& fqdn);
        void set_rule_src(bool value)
        {
            m_curr_src = value;
        }
        void add_rule_ports(const rule_t::ports_arg_t&);
        void set_rule_opcode(const rule_t::opcode_t op)
        {
            m_curr_opcode = op;
        }
        void add_rule_opcode(const rule_t::opcode_arg_t&);
        void set_rule_options(const rule_t::flags_options_t op)
        {
            m_curr_options = op;
        }
        void set_rule_tablename(const std::string name)
        {
            m_curr_name = name;
            m_curr_valtype = tables::valtype_t::LEGACY;
            m_curr_value = 0;
        }
        void set_rule_valuetype(const tables::valtype_t t)
        {
            m_curr_valtype = t;
        }
        void set_rule_tablevalue(uint32_t v)
        {
            m_curr_value = v;
        }
        void add_table_addresses();
        void set_iface_direction(iface_direction_t dir)
        {
            m_curr_dir = dir;
        }
        void add_rule_iface(const std::string& iface);
        void add_via_table();
        void set_rule_flag(uint32_t);
        void clear_rule_flag(uint32_t);

        std::string format_location(const location_history_t& loc);
        const auto& labels() const {
            return m_labels;
        }

    private:
        void setup_lexer(const std::string& name, istream_ptr_t isrm, bool nested);
        // parser's context
        enum class entity_type {
            NONE,
            MACRODEF,
            DNSCACHE,
            TABLE,
            RULE,
        };
        rule_ptr_t m_curr_rule;
        rule_ptr_t m_prev_rule;
        std::string m_last_label;

        entity_type m_curr_entity;
        std::string m_curr_name;
        tables::valtype_t m_curr_valtype;
        uint32_t m_curr_value;

        // table entry context
        tables::curr_entry_t m_curr_table_entry;

        // addr/ports src or dst
        bool m_curr_src;
        rule_t::opcode_t m_curr_opcode;
        rule_t::flags_options_t m_curr_options;

        // recv/xmit/via
        iface_direction_t m_curr_dir;

        // proto cache
        std::map<std::string, uint8_t> m_protocols;
        // services cache
        std::map<std::string, uint16_t> m_services;

        // internal methods
        void check_table();
        void check_table_entry(const tables::entry_type_t&);
        void fill_skipto_table(const tables::prefix_skipto_entry_t&);
        void fill_iface_table(const tables::ifname_entry_t&);

    protected:
        bool open(const std::string& file, bool nested = true);
        bool close();

        fw_lexer_t m_lexer;
        int m_debug; // debug level
        unsigned int m_ruleid_last;
        unsigned int m_ruleno_last;
        unsigned int m_ruleno_step;
        std::vector<fw_config_history_t> m_history; // history of opened files
        // lexer cursor location, current filename and its number in m_history
        std::stack<location> m_location;
        std::stack<istream_ptr_t> m_filestrm;
        std::stack<unsigned int> m_fileno;

        std::map<std::string, dns_addresses_t> m_dns_cache;
        std::map<std::string, label_info_t> m_labels;

        // keep track of used skipto labels
        std::map<std::string,
                 std::vector<rule_ptr_t>>
            m_skipto_labels;

        std::map<std::string, macro_t> m_macros;
        std::map<std::string, table_t> m_tables;
        // ruleno -> vector<rule_t *>
        std::map<unsigned int, // rulenum
                 std::vector<rule_ptr_t>>
            m_rules;
    };

} // namespace ipfw
