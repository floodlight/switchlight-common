/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

#include <sflowa/sflowa_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>
#include "sflowa_int.h"

static const indigo_core_gentable_ops_t *ops_collector;
static const indigo_core_gentable_ops_t *ops_sampler;
static void *table_priv_collector;
static void *table_priv_sampler;

static const slow_collector_entry_t collector_entry_1 = {
    .key.collector_ip = 0xc0a80101, //192.168.1.1
    .value.vlan_id = 7,
    .value.agent_mac = { .addr = {0x55, 0x16, 0xc7, 0x01, 0x02, 0x03} },
    .value.agent_ip = 0xc0a86401, //192.168.100.1
    .value.agent_udp_sport = 50000,
    .value.collector_mac = { .addr = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f} },
    .value.collector_udp_dport = 6343,
    .value.sub_agent_id = 1,
};
static slow_collector_entry_t collector_entry_2 = {
    .key.collector_ip = 0x0a0a0505, //10.10.5.5
    .value.vlan_id = 2,
    .value.agent_mac = { .addr = {0x55, 0x16, 0xc7, 0x01, 0x02, 0x03} },
    .value.agent_ip = 0x0a0a6401, //10.10.100.1
    .value.agent_udp_sport = 45000,
    .value.collector_mac = { .addr = {0xca, 0xfe, 0xc0, 0xff, 0xee, 0x00} },
    .value.collector_udp_dport = 6343,
    .value.sub_agent_id = 2,
};

void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *_ops,
    void *_table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    if (!strcmp(name, "sflow_collector")) {
        ops_collector = _ops;
        table_priv_collector = _table_priv; //NULL
    } else if (!strcmp(name, "sflow_sampler")) {
        ops_sampler = _ops;
        table_priv_sampler = _table_priv; //NULL
    }

    *gentable = (void *)1;
}

static void
verify_cache(slow_collector_entry_t entry)
{
    sflow_collector_cache_entry_t *cache_entry = sflow_collector_cache_find(entry.key);

    AIM_ASSERT(cache_entry != NULL, "Collector entry with key: 0x%x missing from cache",
               entry.key.collector_ip);
    AIM_ASSERT(!memcmp(&cache_entry->entry, &entry, sizeof(slow_collector_entry_t)),
               "Mismatch in Collector entry with key: 0x%x", entry.key.collector_ip);
}

static void
verify_no_cache(slow_collector_entry_t entry)
{
    sflow_collector_cache_entry_t *cache_entry = sflow_collector_cache_find(entry.key);

    AIM_ASSERT(cache_entry == NULL);
}

static of_list_bsn_tlv_t *
make_key_collector(uint32_t dst_ip)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    of_bsn_tlv_ipv4_dst_t *tlv = of_bsn_tlv_ipv4_dst_new(OF_VERSION_1_3);
    of_bsn_tlv_ipv4_dst_value_set(tlv, dst_ip);
    of_list_append(list, tlv);
    of_object_delete(tlv);
    return list;
}

static of_list_bsn_tlv_t *
make_value(uint16_t vlan, of_mac_addr_t src_mac, uint32_t src_ip, uint16_t sport,
           of_mac_addr_t dst_mac, uint16_t dport, uint32_t sub_agent_id)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    {
        of_bsn_tlv_vlan_vid_t *tlv = of_bsn_tlv_vlan_vid_new(OF_VERSION_1_3);
        of_bsn_tlv_vlan_vid_value_set(tlv, vlan);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_eth_src_t *tlv = of_bsn_tlv_eth_src_new(OF_VERSION_1_3);
        of_bsn_tlv_eth_src_value_set(tlv, src_mac);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_ipv4_src_t *tlv = of_bsn_tlv_ipv4_src_new(OF_VERSION_1_3);
        of_bsn_tlv_ipv4_src_value_set(tlv, src_ip);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_udp_src_t *tlv = of_bsn_tlv_udp_src_new(OF_VERSION_1_3);
        of_bsn_tlv_udp_src_value_set(tlv, sport);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_eth_dst_t *tlv = of_bsn_tlv_eth_dst_new(OF_VERSION_1_3);
        of_bsn_tlv_eth_dst_value_set(tlv, dst_mac);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_udp_dst_t *tlv = of_bsn_tlv_udp_dst_new(OF_VERSION_1_3);
        of_bsn_tlv_udp_dst_value_set(tlv, dport);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_sub_agent_id_t *tlv = of_bsn_tlv_sub_agent_id_new(OF_VERSION_1_3);
        of_bsn_tlv_sub_agent_id_value_set(tlv, sub_agent_id);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    return list;
}

static void
test_sflow_collector_table()
{
    indigo_error_t rv;
    of_list_bsn_tlv_t *key, *value;
    void *entry_priv_1, *entry_priv_2;

    /*
     * Test add
     */
    key = make_key_collector(collector_entry_1.key.collector_ip);
    value = make_value(collector_entry_1.value.vlan_id,
                       collector_entry_1.value.agent_mac,
                       collector_entry_1.value.agent_ip,
                       collector_entry_1.value.agent_udp_sport,
                       collector_entry_1.value.collector_mac,
                       collector_entry_1.value.collector_udp_dport,
                       collector_entry_1.value.sub_agent_id);

    AIM_ASSERT((rv = ops_collector->add(table_priv_collector, key, value,
               &entry_priv_1)) == INDIGO_ERROR_NONE,
               "Error in collector table add: %s\n", indigo_strerror(rv));

    of_object_delete(key);
    of_object_delete(value);

    /*
     * Verify entry got added to collector cache
     */
    verify_cache(collector_entry_1);
    verify_no_cache(collector_entry_2);

    key = make_key_collector(collector_entry_2.key.collector_ip);
    value = make_value(collector_entry_2.value.vlan_id,
                       collector_entry_2.value.agent_mac,
                       collector_entry_2.value.agent_ip,
                       collector_entry_2.value.agent_udp_sport,
                       collector_entry_2.value.collector_mac,
                       collector_entry_2.value.collector_udp_dport,
                       collector_entry_2.value.sub_agent_id);

    AIM_ASSERT((rv = ops_collector->add(table_priv_collector, key, value,
               &entry_priv_2)) == INDIGO_ERROR_NONE,
               "Error in collector table add: %s\n", indigo_strerror(rv));

    of_object_delete(value);

    verify_cache(collector_entry_1);
    verify_cache(collector_entry_2);

    /*
     * Test modify
     */
    collector_entry_2.value.vlan_id = 15;
    collector_entry_2.value.agent_ip = 0x0a0a6464; //10.10.100.100
    value = make_value(collector_entry_2.value.vlan_id,
                       collector_entry_2.value.agent_mac,
                       collector_entry_2.value.agent_ip,
                       collector_entry_2.value.agent_udp_sport,
                       collector_entry_2.value.collector_mac,
                       collector_entry_2.value.collector_udp_dport,
                       collector_entry_2.value.sub_agent_id);
    AIM_ASSERT((rv = ops_collector->modify(table_priv_sampler, entry_priv_2, key,
               value)) == INDIGO_ERROR_NONE,
               "Error in collector table modify: %s\n", indigo_strerror(rv));

    verify_cache(collector_entry_1);
    verify_cache(collector_entry_2);

    of_object_delete(value);

    /*
     * Test delete
     */
    AIM_ASSERT((rv = ops_collector->del(table_priv_collector, entry_priv_2, key))
               == INDIGO_ERROR_NONE,
               "Error in collector table delete: %s\n", indigo_strerror(rv));

    of_object_delete(key);

    verify_cache(collector_entry_1);
    verify_no_cache(collector_entry_2);

    key = make_key_collector(collector_entry_1.key.collector_ip);
    AIM_ASSERT((rv = ops_collector->del(table_priv_collector, entry_priv_1, key))
               == INDIGO_ERROR_NONE,
               "Error in collector table delete: %s\n", indigo_strerror(rv));

    of_object_delete(key);

    verify_no_cache(collector_entry_1);
    verify_no_cache(collector_entry_2);
}

static of_list_bsn_tlv_t *
make_key_sampler(of_port_no_t port_no)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    of_bsn_tlv_port_t *tlv = of_bsn_tlv_port_new(OF_VERSION_1_3);
    of_bsn_tlv_port_value_set(tlv, port_no);
    of_list_append(list, tlv);
    of_object_delete(tlv);
    return list;
}

static of_list_bsn_tlv_t *
make_value_sampler(uint32_t sampling_rate, uint32_t header_size)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    {
        of_bsn_tlv_sampling_rate_t *tlv = of_bsn_tlv_sampling_rate_new(OF_VERSION_1_3);
        of_bsn_tlv_sampling_rate_value_set(tlv, sampling_rate);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_header_size_t *tlv = of_bsn_tlv_header_size_new(OF_VERSION_1_3);
        of_bsn_tlv_header_size_value_set(tlv, header_size);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    return list;
}

static void
test_sflow_sampler_table()
{
    indigo_error_t rv;
    of_list_bsn_tlv_t *key, *value;
    void *entry_priv_1, *entry_priv_2;

    /*
     * Test add
     */
    key = make_key_sampler(57);
    value = make_value_sampler(512, 128);

    AIM_ASSERT((rv = ops_sampler->add(table_priv_sampler, key, value,
               &entry_priv_1)) == INDIGO_ERROR_NONE,
               "Error in sampler table add: %s\n", indigo_strerror(rv));

    of_object_delete(key);
    of_object_delete(value);

    key = make_key_sampler(92);
    value = make_value_sampler(1024, 64);

    AIM_ASSERT((rv = ops_sampler->add(table_priv_sampler, key, value,
               &entry_priv_2)) == INDIGO_ERROR_NONE,
               "Error in sampler table add: %s\n", indigo_strerror(rv));

    of_object_delete(value);

    /*
     * Test modify
     */
    value = make_value_sampler(2048, 64);
    AIM_ASSERT((rv = ops_sampler->modify(table_priv_sampler, entry_priv_1, key,
               value)) == INDIGO_ERROR_NONE,
               "Error in sampler table modify: %s\n", indigo_strerror(rv));

    of_object_delete(key);
    of_object_delete(value);

    /*
     * Test delete
     */
    AIM_ASSERT((rv = ops_sampler->del(table_priv_sampler, entry_priv_1, NULL))
               == INDIGO_ERROR_NONE,
               "Error in sampler table delete: %s\n", indigo_strerror(rv));

    AIM_ASSERT((rv = ops_sampler->del(table_priv_sampler, entry_priv_2, NULL))
               == INDIGO_ERROR_NONE,
               "Error in sampler table delete: %s\n", indigo_strerror(rv));
}

int aim_main(int argc, char* argv[])
{
    sflowa_init();

    test_sflow_collector_table();
    test_sflow_sampler_table();

    return 0;
}

