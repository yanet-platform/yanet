#include <cstdint>
#include <cstring>
#include <iostream>
#include <fstream>
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include "common.h"
#include "common/type.h"
#include "dataplane.h"
#include "globalbase.h"
#include "hashtable.h"
#include "type.h"

// struct balancer_state_key_t
// {
// 	uint8_t balancer_id;
// 	uint8_t protocol;
// 	uint16_t addr_type; // 4=ip4, 6=ip6.

// 	ipv6_address_t ip_source;
// 	ipv6_address_t ip_destination;

// 	uint16_t port_source;
// 	uint16_t port_destination;
// };

/*
module(0)     virtual_ip(1)      proto(2)  virtual_port(3)  
---------    ------------------  --------  ---------------  
real_ip(4)      real_port(5)  client_ip(6)     client_port(7)  created(8)  last_seen(9)
--------------  ------------  ---------------  --------------  ----------  ------------
*/

struct Collison {
    std::vector<std::string> values;
    std::vector<std::string> key_strs;
    std::vector<uint32_t> hashs;
};

std::map<uint32_t, Collison> collision_map;

inline std::string get_str_from_vec(const std::vector<std::string>& vals) {
    std::string res;
    for (auto& e:  vals) {
        res += e + "\t";
    }
    return res;
}

inline std::string get_str_from_key(const dataplane::globalBase::balancer_state_key_t& key) {
    char buf[sizeof(key) + 1];
    memcpy(buf, &key, sizeof(key));
    buf[sizeof(key)] = '\0';
    return std::string(buf);
}

inline int test_hash_table(tDataPlaneConfig config, dataplane::globalBase::balancer::state_ht* balancer_state, uint32_t table_size) {
    std::ifstream file(config.session_name);
    (void)table_size;
    if (!file.is_open()) {
        YADECAP_LOG_ERROR("Unable to open file\n");
        return 1;
    }

    std::string line;
    int cnt = 0;
    std::vector<uint32_t> stats;
    uint32_t max_has_value = 0;
    uint32_t module = config.hash_module;
    if (module > table_size / config.chunk_size) {
        module = table_size / config.chunk_size;
        YADECAP_LOG_WARNING("HASH MODULE CHANGED!!!!\n");
    }
    stats.resize(table_size / config.chunk_size + 1);


    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::vector<std::string> values;
        std::string word;

        while (iss >> word) {
            values.push_back(word);
        }
        if (cnt++ < 2 || values.size() != 10) {
            YADECAP_LOG_DEBUG("Skip line: %d\n", cnt);
            continue;
        }
        dataplane::globalBase::balancer_state_key_t key;
        key.balancer_id = 0;
        common::ip_address_t source_ip(values[6]);
        common::ip_address_t dest_ip(values[1]);
        common::ip_address_t real_ip(values[4]);
        if (source_ip.is_ipv4()) {
            key.addr_type = 4;
            memset(key.ip_source.nap, 0, sizeof(key.ip_source.nap));
            key.ip_source.mapped_ipv4_address.address = source_ip.get_ipv4();
            memset(key.ip_destination.nap, 0, sizeof(key.ip_destination.nap));
            key.ip_destination.mapped_ipv4_address.address = dest_ip.get_ipv4();
        } else {
            key.addr_type = 6;
            key.ip_source.convert(source_ip.get_ipv6());
            key.ip_destination.convert(dest_ip.get_ipv6());
        }
		
		key.port_source = std::stoi(values[7]); 
		key.port_destination = std::stoi(values[3]);

        if (values[2] == "tcp") {
            key.protocol = IPPROTO_TCP;
        } else {
            key.protocol = IPPROTO_UDP;
        }

        /*
        Work with real hash table
        dataplane::globalBase::balancer_state_value_t* value;
		dataplane::spinlock_nonrecursive_t* locker;
		const uint32_t hash = balancer_state->fake_lookup(key, value);
        
        if (!value) {
            / counter_id:
            /   0 - insert failed
            /   1 - insert done
        dataplane::globalBase::balancer_state_value_t new_value;
        new_value.timestamp_create = std::stoi(values[8]);
        new_value.timestamp_last_packet = std::stoi(values[9]);
        new_value.real_unordered_id = real_ip.get_ipv6().get_mapped_ipv4_address();
        chunk_id = balancer_state->fake_insert(hash, key, new_value);
        */

        uint32_t hash = balancer_state->calc_hash(key);
        max_has_value = std::max(max_has_value, hash);
        uint32_t chunk_id = (hash % module);
        assert (chunk_id < stats.size());
        ++stats[chunk_id];
        if (stats[chunk_id] > config.chunk_size) {
            collision_map[chunk_id].values.push_back(get_str_from_vec(values));
            collision_map[chunk_id].hashs.push_back(hash);
            collision_map[chunk_id].key_strs.push_back(get_str_from_key(key));
        }
    }

    file.close();
    std::string chunk_size_str, table_size_str, hash_module_str;
    nlohmann::detail::int_to_string(chunk_size_str, config.chunk_size);
    nlohmann::detail::int_to_string(table_size_str, table_size / (1024 * 1024));
    nlohmann::detail::int_to_string(hash_module_str, module + 1);

    std::string path = config.session_name + "_dir/";
    std::string stats_path = path + chunk_size_str + "_" + table_size_str  + "m_" + config.hash_func_name + "_" + hash_module_str + "_stats";
    std::string collis_path = path + chunk_size_str + "_" + table_size_str  + "m_" + config.hash_func_name + "_" + hash_module_str + "_collisions";
   
    std::ofstream output_file(stats_path);
    std::ofstream output_collsion_file(collis_path);

    YADECAP_LOG_DEBUG("STATS PATH: %s\n", stats_path.data());
    YADECAP_LOG_DEBUG("COLLIS PATH: %s\n", collis_path.data());

    if (!output_file.is_open()) {
        YADECAP_LOG_ERROR("Unable to open file for writing\n");
        return 1;
    }

    for (auto& chunk_size: stats) {
        output_file << chunk_size << ' ';
    }

    for (auto& [k, col]: collision_map) {
        output_collsion_file << "Chunk_id: " << k << "\n";
        for (size_t i = 0; i < col.values.size(); ++i) {
            output_collsion_file << col.values[i] << "\n";
            output_collsion_file << col.key_strs[i] << "\t" << col.hashs[i] << "\n"; 
        }
        output_collsion_file << "\n";
        
    }

    output_file.close();
    output_collsion_file.close();

    return 0;
}
