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
 * either express or implied. See the License for the shard
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

/*
 * Implementation of Sflow Agent.
 *
 * This file contains code for initalizing sflow agent and
 * sflow gentable (sflow_collector, sflow_sampler) operations.
 */

#include <AIM/aim.h>
#include <debug_counter/debug_counter.h>
#include <OS/os_time.h>
#include "sflowa_int.h"
#include "sflowa_log.h"

static indigo_core_gentable_t *sflow_collector_table;
static indigo_core_gentable_t *sflow_sampler_table;

static const indigo_core_gentable_ops_t sflow_collector_ops;
static const indigo_core_gentable_ops_t sflow_sampler_ops;

static bool sflowa_initialized = false;
static uint64_t start_time;

static sflow_sampler_entry_t sampler_entries[MAX_PORTS+1];
static LIST_DEFINE(sflow_collector_cache);

/*
 * sflowa_init
 *
 * API to init the Sflow Agent
 * This should only be done once at the beginning.
 */
indigo_error_t
sflowa_init(void)
{
    if (sflowa_initialized) return INDIGO_ERROR_NONE;

    /*
     * Record current time as the system boot time. This time will be used
     * to calculate switch uptime needed in sflow datagrams.
     */
    start_time = os_time_monotonic();

    AIM_LOG_INFO("init");

    indigo_core_gentable_register("sflow_collector", &sflow_collector_ops, NULL, 4, 4,
                                  &sflow_collector_table);
    indigo_core_gentable_register("sflow_sampler", &sflow_sampler_ops, NULL, 1, 1,
                                  &sflow_sampler_table);

    sflowa_initialized = true;

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_cache_list
 *
 * Return a list of sflow collector entries
 *
 * The list is through the 'links' field of sflow_collector_cache_entry_t.
 */
list_head_t *
sflow_collector_cache_list(void)
{
    return &sflow_collector_cache;
}

/*
 * sflow_collector_cache_find
 *
 * API to find if an slow_collector_entry_t exists in the collector cache
 */
sflow_collector_cache_entry_t*
sflow_collector_cache_find(sflow_collector_entry_key_t key)
{
    list_head_t *cache = sflow_collector_cache_list();
    list_links_t *cur;
    LIST_FOREACH(cache, cur) {
        sflow_collector_cache_entry_t *cache_entry = container_of(cur, links,
                                                     sflow_collector_cache_entry_t);
        if (cache_entry->entry.key.collector_ip == key.collector_ip) {
            return cache_entry;
        }
    }

    return NULL;
}

/*
 * sflow_collector_cache_add
 *
 * API to add an slow_collector_entry_t in the collector cache
 */
static slow_collector_entry_t *
sflow_collector_cache_add(sflow_collector_entry_key_t key,
                          sflow_collector_entry_value_t value)
{
    sflow_collector_cache_entry_t *cache_entry = aim_zmalloc(sizeof(*cache_entry));
    cache_entry->entry.key = key;
    cache_entry->entry.value = value;
    list_push(&sflow_collector_cache, &cache_entry->links);

    AIM_LOG_TRACE("Added collector cache entry with key: %{ipv4a}",
                  cache_entry->entry.key.collector_ip);

    return &cache_entry->entry;
}

/*
 * sflow_collector_cache_delete
 *
 * API to delete an slow_collector_entry_t from the collector cache
 */
static void
sflow_collector_cache_delete(sflow_collector_entry_key_t key)
{
    sflow_collector_cache_entry_t *cache_entry = sflow_collector_cache_find(key);
    AIM_ASSERT(cache_entry, "collector entry with key: %{ipv4a} missing from cache",
               key.collector_ip);

    AIM_LOG_TRACE("Deleted collector cache entry with key: %{ipv4a}",
                  cache_entry->entry.key.collector_ip);
    list_remove(&cache_entry->links);
    aim_free(cache_entry);
}

/*
 * sflow_collector_parse_key
 *
 * Parse key for slow_collector table entry from tlv list
 */
static indigo_error_t
sflow_collector_parse_key(of_list_bsn_tlv_t *tlvs,
                          sflow_collector_entry_key_t *key)
{
    of_bsn_tlv_t tlv;

    SFLOWA_MEMSET(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    /* Collector ip */
    if (tlv.header.object_id == OF_BSN_TLV_IPV4_DST) {
        of_bsn_tlv_ipv4_dst_value_get(&tlv.ipv4_dst, &key->collector_ip);
    } else {
        AIM_LOG_ERROR("expected ipv4_dst key TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_parse_value
 *
 * Parse values for slow_collector table entry from tlv list
 */
static indigo_error_t
sflow_collector_parse_value(of_list_bsn_tlv_t *tlvs,
                            sflow_collector_entry_value_t *value)
{
    of_bsn_tlv_t tlv;

    SFLOWA_MEMSET(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Vlan id */
    if (tlv.header.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv.vlan_vid, &value->vlan_id);
    } else {
        AIM_LOG_ERROR("expected vlan value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }


    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Agent mac */
    if (tlv.header.object_id == OF_BSN_TLV_ETH_SRC) {
        of_bsn_tlv_eth_src_value_get(&tlv.eth_src, &value->agent_mac);
    } else {
        AIM_LOG_ERROR("expected eth_src value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Agent ip */
    if (tlv.header.object_id == OF_BSN_TLV_IPV4_SRC) {
        of_bsn_tlv_ipv4_src_value_get(&tlv.ipv4_src, &value->agent_ip);
    } else {
        AIM_LOG_ERROR("expected ipv4_src value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Agent udp src port */
    if (tlv.header.object_id == OF_BSN_TLV_UDP_SRC) {
        of_bsn_tlv_udp_src_value_get(&tlv.udp_src, &value->agent_udp_sport);
    } else {
        AIM_LOG_ERROR("expected udp_src value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Collector mac */
    if (tlv.header.object_id == OF_BSN_TLV_ETH_DST) {
        of_bsn_tlv_eth_dst_value_get(&tlv.eth_dst, &value->collector_mac);
    } else {
        AIM_LOG_ERROR("expected eth_dst value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Collector udp dst port */
    if (tlv.header.object_id == OF_BSN_TLV_UDP_DST) {
        of_bsn_tlv_udp_dst_value_get(&tlv.udp_dst,
                                     &value->collector_udp_dport);
    } else {
        AIM_LOG_ERROR("expected udp_dst value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Sub agent id */
    if (tlv.header.object_id == OF_BSN_TLV_SUB_AGENT_ID) {
        of_bsn_tlv_sub_agent_id_value_get(&tlv.sub_agent_id,
                                          &value->sub_agent_id);
    } else {
        AIM_LOG_ERROR("expected udp_dst value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_add
 *
 * Add a new entry to slow_collector table
 */
static indigo_error_t
sflow_collector_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs,
                    of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    sflow_collector_entry_key_t key;
    sflow_collector_entry_value_t value;
    slow_collector_entry_t *entry;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    rv = sflow_collector_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = sflow_collector_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    /*
     * Add this entry to a list to be used later for sending a sflow datagram out
     */
    entry = sflow_collector_cache_add(key, value);

    AIM_LOG_TRACE("Add collector table entry, collector_ip: %{ipv4a} -> vlan_id:"
                  " %u, agent_mac: %{mac}, agent_ip: %{ipv4a}, agent_udp_sport:"
                  " %u, collector_mac: %{mac}, collector_udp_dport: %u, "
                  "sub_agent_id: %u", entry->key.collector_ip,
                  entry->value.vlan_id, entry->value.agent_mac.addr,
                  entry->value.agent_ip, entry->value.agent_udp_sport,
                  entry->value.collector_mac.addr,
                  entry->value.collector_udp_dport, entry->value.sub_agent_id);

    *entry_priv = entry;

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_modify
 *
 * Modify a existing entry in slow_collector table
 */
static indigo_error_t
sflow_collector_modify(void *table_priv, void *entry_priv,
                       of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    sflow_collector_entry_value_t value;
    slow_collector_entry_t *entry = entry_priv;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    AIM_ASSERT(entry, "Attempted to modify a NULL entry in collector table");

    rv = sflow_collector_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    AIM_LOG_TRACE("Modify collector table entry, old collector_ip: %{ipv4a} ->"
                  " vlan_id:%u, agent_mac: %{mac}, agent_ip: %{ipv4a}, "
                  "agent_udp_sport: %u, collector_mac: %{mac}, "
                  "collector_udp_dport: %u, sub_agent_id: %u",
                  entry->key.collector_ip, entry->value.vlan_id,
                  entry->value.agent_mac.addr, entry->value.agent_ip,
                  entry->value.agent_udp_sport, entry->value.collector_mac.addr,
                  entry->value.collector_udp_dport, entry->value.sub_agent_id);

    AIM_LOG_TRACE("New, collector_ip: %{ipv4a} -> vlan_id: %u, agent_mac: "
                  "%{mac}, agent_ip: %{ipv4a}, agent_udp_sport: %u, "
                  "collector_mac: %{mac}, collector_udp_dport: %u, "
                  "sub_agent_id: %u", entry->key.collector_ip, value.vlan_id,
                  value.agent_mac.addr, value.agent_ip, value.agent_udp_sport,
                  value.collector_mac.addr, value.collector_udp_dport,
                  value.sub_agent_id);

    entry->value = value;

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_delete
 *
 * Remove a entry from slow_collector table
 */
static indigo_error_t
sflow_collector_delete(void *table_priv, void *entry_priv,
                       of_list_bsn_tlv_t *key_tlvs)
{
    slow_collector_entry_t *entry = entry_priv;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    AIM_ASSERT(entry, "Attempted to delete a NULL entry from collector table");

    AIM_LOG_TRACE("Delete collector table entry, collector_ip: %{ipv4a} -> vlan_id:"
                  " %u, agent_mac: %{mac}, agent_ip: %{ipv4a}, agent_udp_sport:"
                  " %u, collector_mac: %{mac}, collector_udp_dport: %u, "
                  "sub_agent_id: %u", entry->key.collector_ip,
                  entry->value.vlan_id, entry->value.agent_mac.addr,
                  entry->value.agent_ip, entry->value.agent_udp_sport,
                  entry->value.collector_mac.addr,
                  entry->value.collector_udp_dport, entry->value.sub_agent_id);

    /*
     * Delete this entry from the list
     */
    sflow_collector_cache_delete(entry->key);

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_collector_get_stats
 *
 * Return the stats related with a entry in slow_collector table
 */
static void
sflow_collector_get_stats(void *table_priv, void *entry_priv,
                          of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    slow_collector_entry_t *entry = entry_priv;

    if (!sflowa_initialized) return;

    AIM_ASSERT(entry, "Attempted to request stats from collector table "
               "for NULL entry");

    /* tx_packets */
    {
        of_bsn_tlv_tx_packets_t tlv;
        of_bsn_tlv_tx_packets_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_tx_packets_value_set(&tlv, entry->stats.tx_packets);
    }

    /* tx_bytes */
    {
        of_bsn_tlv_tx_bytes_t tlv;
        of_bsn_tlv_tx_bytes_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_tx_bytes_value_set(&tlv, entry->stats.tx_bytes);
    }

}

static const indigo_core_gentable_ops_t sflow_collector_ops = {
    .add = sflow_collector_add,
    .modify = sflow_collector_modify,
    .del = sflow_collector_delete,
    .get_stats = sflow_collector_get_stats,
};

/*
 * sflow_sampler_parse_key
 *
 * Parse key for slow_sampler table entry from tlv list
 */
static indigo_error_t
sflow_sampler_parse_key(of_list_bsn_tlv_t *tlvs, of_port_no_t *port_no)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    /* port */
    if (tlv.header.object_id == OF_BSN_TLV_PORT) {
        of_bsn_tlv_port_value_get(&tlv.port, port_no);
    } else {
        AIM_LOG_ERROR("expected port key TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*port_no > MAX_PORTS) {
        AIM_LOG_ERROR("Port out of range (%u)", *port_no);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_sampler_parse_value
 *
 * Parse values for slow_sampler table entry from tlv list
 */
static indigo_error_t
sflow_sampler_parse_value(of_list_bsn_tlv_t *tlvs,
                          sflow_sampler_entry_value_t *value)
{
    of_bsn_tlv_t tlv;

    SFLOWA_MEMSET(value, 0, sizeof(*value));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Sampling rate */
    if (tlv.header.object_id == OF_BSN_TLV_SAMPLING_RATE) {
        of_bsn_tlv_sampling_rate_value_get(&tlv.sampling_rate,
                                           &value->sampling_rate);
    } else {
        AIM_LOG_ERROR("expected sampling_rate value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Header size */
    if (tlv.header.object_id == OF_BSN_TLV_HEADER_SIZE) {
        of_bsn_tlv_header_size_value_get(&tlv.header_size, &value->header_size);
    } else {
        AIM_LOG_ERROR("expected header_size value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_sampler_add
 *
 * Add a new entry to slow_sampler table
 */
static indigo_error_t
sflow_sampler_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs,
                  of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    of_port_no_t port_no;
    sflow_sampler_entry_value_t value;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    rv = sflow_sampler_parse_key(key_tlvs, &port_no);
    if (rv < 0) {
        return rv;
    }

    rv = sflow_sampler_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    sflow_sampler_entry_t *entry = &sampler_entries[port_no];
    entry->value = value;

    AIM_LOG_TRACE("Add sampler table entry, port: %u -> sampling_rate: %u, "
                  "header_size: %u", port_no,
                  entry->value.sampling_rate, entry->value.header_size);

    *entry_priv = entry;

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_sampler_modify
 *
 * Modify a existing entry in slow_sampler table
 */
static indigo_error_t
sflow_sampler_modify(void *table_priv, void *entry_priv,
                     of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    of_port_no_t port_no;
    sflow_sampler_entry_value_t value;
    sflow_sampler_entry_t *entry = entry_priv;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    rv = sflow_sampler_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    port_no = entry - sampler_entries;
    AIM_LOG_TRACE("Modify sampler table entry, port: %u -> from sampling_rate: "
                  "%u, header_size: %u to sampling_rate: %u, header_size: %u",
                  port_no, entry->value.sampling_rate,
                  entry->value.header_size, value.sampling_rate,
                  value.header_size);

    entry->value = value;

    /*
     * Todo: Notify about the change in sampling rate on this port
     */

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_sampler_delete
 *
 * Remove a entry from slow_sampler table
 */
static indigo_error_t
sflow_sampler_delete(void *table_priv, void *entry_priv,
                     of_list_bsn_tlv_t *key_tlvs)
{
    sflow_sampler_entry_t *entry = entry_priv;
    of_port_no_t port_no;

    if (!sflowa_initialized) return INDIGO_ERROR_INIT;

    AIM_ASSERT(entry, "Attempted to delete a NULL entry from sampler table");

    port_no = entry - sampler_entries;
    AIM_LOG_TRACE("Delete sampler table entry, port: %u -> sampling_rate: %u, "
                  "header_size: %u", port_no,
                  entry->value.sampling_rate, entry->value.header_size);

    /*
     * Set the sampling rate to 0 to disable sampling on this port
     * Todo: Send notifications to disable sampling on this port
     */
    SFLOWA_MEMSET(entry, 0, sizeof(*entry));

    return INDIGO_ERROR_NONE;
}

/*
 * sflow_sampler_get_stats
 *
 * Dummy function
 */
static void
sflow_sampler_get_stats(void *table_priv, void *entry_priv,
                        of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    /* No stats */
}

static const indigo_core_gentable_ops_t sflow_sampler_ops = {
    .add = sflow_sampler_add,
    .modify = sflow_sampler_modify,
    .del = sflow_sampler_delete,
    .get_stats = sflow_sampler_get_stats,
};
