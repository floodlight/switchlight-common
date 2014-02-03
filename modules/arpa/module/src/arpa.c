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

#include <arpa/arpa.h>
#include <indigo/of_state_manager.h>
#include <PPE/ppe.h>
#include <router_ip_table/router_ip_table.h>
#include <OS/os.h>
#include <BigHash/bighash.h>
#include <AIM/aim_list.h>
#include <indigo/time.h>
#include <SocketManager/socketmanager.h>

#include "arpa_log.h"

enum arp_timer_state {
    ARP_TIMER_STATE_NONE, /* no timeouts configured */
    ARP_TIMER_STATE_UNICAST_QUERY,
    ARP_TIMER_STATE_BROADCAST_QUERY,
    ARP_TIMER_STATE_IDLE_TIMEOUT,
};

struct arp_info {
    of_mac_addr_t eth_src;
    of_mac_addr_t eth_dst;
    uint16_t vlan_vid;
    uint8_t vlan_pcp;
    uint16_t operation;
    of_mac_addr_t sha;
    uint32_t spa;
    of_mac_addr_t tha;
    uint32_t tpa;
};

struct arp_entry_key {
    uint16_t vlan_vid;
    uint32_t ipv4;
};

struct arp_entry_value {
    of_mac_addr_t mac;
    uint32_t unicast_query_timeout;
    uint32_t broadcast_query_timeout;
    uint32_t idle_timeout;
};

struct arp_entry_stats {
    indigo_time_t active_time;
    uint64_t request_packets;
    uint64_t reply_packets;
    uint64_t miss_packets;
};

struct arp_entry {
    bighash_entry_t hash_entry;
    struct arp_entry_key key;
    struct arp_entry_value value;
    struct arp_entry_stats stats;

    /*
     * Which timer will fire next?
     *
     * initial state: unicast if timeouts configured, else none
     *
     * On current timer expiring:
     *   unicast -> broadcast
     *   broadcast -> idle_timeout
     *   idle_timeout -> idle_timeout
     *
     * On ARP packet hitting this entry:
     *   none -> none
     *   * -> unicast
     */
    enum arp_timer_state timer_state;

    /*
     * When will the next timer expire?
     *
     * Updated along with stats.active_time when an ARP packet
     * hits this entry and timeouts are configured.
     */
    indigo_time_t deadline;
};

#define TEMPLATE_NAME arp_entries_hashtable
#define TEMPLATE_OBJ_TYPE struct arp_entry
#define TEMPLATE_KEY_FIELD key
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_listener_result_t arpa_handle_pkt(of_packet_in_t *packet_in);
static indigo_error_t arpa_parse_packet(of_octets_t *data, struct arp_info *info);
static void arpa_send_packet(struct arp_info *info);
static bool arpa_check_source(struct arp_info *info);
static void arpa_set_timer_state(struct arp_entry *entry, enum arp_timer_state state);
static void arpa_timer(void *cookie);
static void arpa_send_idle_notification(struct arp_entry *entry);
static void arpa_send_query(struct arp_entry *entry, bool broadcast);

static indigo_core_gentable_t *arp_table;

static const indigo_core_gentable_ops_t arp_ops;

static aim_ratelimiter_t arpa_pktin_log_limiter;

static bighash_table_t *arp_entries;


/* Public interface */

indigo_error_t
arpa_init()
{
    indigo_error_t rv;

    arp_entries = bighash_table_create(1024);

    indigo_core_gentable_register("arp", &arp_ops, NULL, 16384, 1024,
                                  &arp_table);

    indigo_core_packet_in_listener_register(arpa_handle_pkt);

    aim_ratelimiter_init(&arpa_pktin_log_limiter, 1000*1000, 5, NULL);

    if ((rv = ind_soc_timer_event_register(arpa_timer, NULL, 1000)) < 0) {
        AIM_DIE("Failed to register ARP agent timer: %s", indigo_strerror(rv));
    }

    return INDIGO_ERROR_NONE;
}

void
arpa_finish()
{
    ind_soc_timer_event_unregister(arpa_timer, NULL);
    indigo_core_gentable_unregister(arp_table);
    indigo_core_packet_in_listener_unregister(arpa_handle_pkt);
    bighash_table_destroy(arp_entries, NULL);
}


/* arp table operations */

static indigo_error_t
arp_parse_key(of_list_bsn_tlv_t *tlvs, struct arp_entry_key *key)
{
    of_bsn_tlv_t tlv;

    memset(key, 0, sizeof(*key));

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv.vlan_vid, &key->vlan_vid);
    } else {
        AIM_LOG_ERROR("expected vlan key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv.ipv4, &key->ipv4);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_parse_value(of_list_bsn_tlv_t *tlvs, struct arp_entry_value *value)
{
    of_bsn_tlv_t tlv;

    value->unicast_query_timeout = 0;
    value->broadcast_query_timeout = 0;
    value->idle_timeout = 0;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_MAC) {
        of_bsn_tlv_mac_value_get(&tlv.mac, &value->mac);
    } else {
        AIM_LOG_ERROR("expected mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    /* Parse optional TLVs */
    while (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        switch (tlv.header.object_id) {
        case OF_BSN_TLV_UNICAST_QUERY_TIMEOUT:
            of_bsn_tlv_unicast_query_timeout_value_get(&tlv.unicast_query_timeout,
                                                       &value->unicast_query_timeout);
            break;
        case OF_BSN_TLV_BROADCAST_QUERY_TIMEOUT:
            of_bsn_tlv_broadcast_query_timeout_value_get(&tlv.broadcast_query_timeout,
                                                         &value->broadcast_query_timeout);
            break;
        case OF_BSN_TLV_IDLE_TIMEOUT:
            of_bsn_tlv_idle_timeout_value_get(&tlv.idle_timeout,
                                              &value->idle_timeout);
            break;
        default:
            AIM_LOG_ERROR("unexpected value TLV %s", of_object_id_str[tlv.header.object_id]);
            return INDIGO_ERROR_PARAM;
        }
    }

    if (value->unicast_query_timeout != 0 ||
            value->broadcast_query_timeout != 0 ||
            value->idle_timeout != 0) {
        if (value->unicast_query_timeout == 0 ||
                value->broadcast_query_timeout == 0 ||
                value->idle_timeout == 0) {
            AIM_LOG_ERROR("all timeouts must be specified if any are");
            return INDIGO_ERROR_PARAM;
        }

        if (value->broadcast_query_timeout <= value->unicast_query_timeout ||
                value->idle_timeout <= value->broadcast_query_timeout) {
            AIM_LOG_ERROR("timeouts must be monotonically increasing");
            return INDIGO_ERROR_PARAM;
        }
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_add(void *table_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    struct arp_entry_key key;
    struct arp_entry_value value;
    struct arp_entry *entry;

    rv = arp_parse_key(key_tlvs, &key);
    if (rv < 0) {
        return rv;
    }

    rv = arp_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry = aim_zmalloc(sizeof(*entry));
    entry->key = key;
    entry->value = value;
    entry->stats.active_time = INDIGO_CURRENT_TIME;

    if (entry->value.unicast_query_timeout > 0) {
        arpa_set_timer_state(entry, ARP_TIMER_STATE_UNICAST_QUERY);
    } else {
        arpa_set_timer_state(entry, ARP_TIMER_STATE_NONE);
    }

    arp_entries_hashtable_insert(arp_entries, entry);

    *entry_priv = entry;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    struct arp_entry_value value;
    struct arp_entry *entry = entry_priv;

    rv = arp_parse_value(value_tlvs, &value);
    if (rv < 0) {
        return rv;
    }

    entry->value = value;
    entry->stats.active_time = INDIGO_CURRENT_TIME;

    if (entry->value.unicast_query_timeout > 0) {
        arpa_set_timer_state(entry, ARP_TIMER_STATE_UNICAST_QUERY);
    } else {
        arpa_set_timer_state(entry, ARP_TIMER_STATE_NONE);
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    struct arp_entry *entry = entry_priv;
    bighash_remove(arp_entries, &entry->hash_entry);
    aim_free(entry);
    return INDIGO_ERROR_NONE;
}

static void
arp_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
    struct arp_entry *entry = entry_priv;

    /* idle_time */
    {
        uint64_t idle_time = INDIGO_CURRENT_TIME - entry->stats.active_time;
        of_bsn_tlv_idle_time_t tlv;
        of_bsn_tlv_idle_time_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_idle_time_value_set(&tlv, idle_time);
    }

    /* request_packets */
    {
        of_bsn_tlv_request_packets_t tlv;
        of_bsn_tlv_request_packets_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_request_packets_value_set(&tlv, entry->stats.request_packets);
    }

    /* reply_packets */
    {
        of_bsn_tlv_reply_packets_t tlv;
        of_bsn_tlv_reply_packets_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_reply_packets_value_set(&tlv, entry->stats.reply_packets);
    }

    /* miss_packets */
    {
        of_bsn_tlv_miss_packets_t tlv;
        of_bsn_tlv_miss_packets_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_miss_packets_value_set(&tlv, entry->stats.miss_packets);
    }
}

static const indigo_core_gentable_ops_t arp_ops = {
    .add = arp_add,
    .modify = arp_modify,
    .del = arp_delete,
    .get_stats = arp_get_stats,
};


/* Hashtable lookup */

static struct arp_entry *
arpa_lookup(uint16_t vlan_vid, uint32_t ipv4)
{
    struct arp_entry_key key;
    memset(&key, 0, sizeof(key));
    key.vlan_vid = vlan_vid;
    key.ipv4 = ipv4;
    return arp_entries_hashtable_first(arp_entries, &key);
}


/* packet-in listener */

static indigo_core_listener_result_t
arpa_handle_pkt(of_packet_in_t *packet_in)
{
    uint8_t reason;
    of_octets_t octets;
    struct arp_info info;
    indigo_error_t rv;

    of_packet_in_reason_get(packet_in, &reason);
    of_packet_in_data_get(packet_in, &octets);

    if (reason != OF_PACKET_IN_REASON_BSN_ARP) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    rv = arpa_parse_packet(&octets, &info);
    if (rv < 0) {
        AIM_LOG_RL_ERROR(&arpa_pktin_log_limiter, os_time_monotonic(),
                         "not a valid ARP packet: %s", indigo_strerror(rv));
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    AIM_LOG_TRACE("received ARP packet: op=%d spa=%#x tpa=%#x", info.operation, info.spa, info.tpa);

    if (!arpa_check_source(&info)) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (info.operation != 1) {
        AIM_LOG_TRACE("Ignoring ARP reply");
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    uint32_t router_ip;
    of_mac_addr_t router_mac;
    if (router_ip_table_lookup(info.vlan_vid, &router_ip, &router_mac) < 0) {
        AIM_LOG_TRACE("no router configured on vlan %u", info.vlan_vid);
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    if (router_ip != info.tpa) {
        AIM_LOG_TRACE("not destined for our router IP");
        return INDIGO_CORE_LISTENER_RESULT_DROP;
    }

    AIM_LOG_TRACE("handling ARP request for router IP");

    /* Send an ARP reply to the SHA of the request, from the router */
    struct arp_info reply_info = info;
    memcpy(reply_info.eth_dst.addr, info.sha.addr, sizeof(reply_info.eth_dst));
    memcpy(reply_info.eth_src.addr, router_mac.addr, sizeof(reply_info.eth_src));
    reply_info.tpa = info.spa;
    memcpy(reply_info.tha.addr, info.sha.addr, sizeof(reply_info.tha));
    reply_info.spa = router_ip;
    memcpy(reply_info.sha.addr, router_mac.addr, sizeof(reply_info.tha));
    reply_info.operation = 2;

    arpa_send_packet(&reply_info);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

static indigo_error_t
arpa_parse_packet(of_octets_t *octets, struct arp_info *info)
{
    ppe_packet_t ppep;
    uint32_t tmp;

    ppe_packet_init(&ppep, octets->data, octets->bytes);
    if (ppe_parse(&ppep) < 0) {
        return INDIGO_ERROR_PARSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_8021Q)) {
        return INDIGO_ERROR_PARSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_ARP)) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_wide_field_get(&ppep, PPE_FIELD_ETHERNET_DST_MAC, info->eth_dst.addr);

    ppe_wide_field_get(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, info->eth_src.addr);

    ppe_field_get(&ppep, PPE_FIELD_8021Q_VLAN, &tmp);
    info->vlan_vid = tmp;

    ppe_field_get(&ppep, PPE_FIELD_8021Q_PRI, &tmp);
    info->vlan_pcp = tmp;

    ppe_field_get(&ppep, PPE_FIELD_ARP_HTYPE, &tmp);
    if (tmp != 1) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_PTYPE, &tmp);
    if (tmp != 0x0800) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_HLEN, &tmp);
    if (tmp != 6) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_PLEN, &tmp);
    if (tmp != 4) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_OPERATION, &tmp);
    info->operation = tmp;

    ppe_wide_field_get(&ppep, PPE_FIELD_ARP_SHA, info->sha.addr);

    ppe_field_get(&ppep, PPE_FIELD_ARP_SPA, &tmp);
    info->spa = tmp;

    ppe_wide_field_get(&ppep, PPE_FIELD_ARP_THA, info->tha.addr);

    ppe_field_get(&ppep, PPE_FIELD_ARP_TPA, &tmp);
    info->tpa = tmp;

    return INDIGO_ERROR_NONE;
}

static void
arpa_send_packet(struct arp_info *info)
{
    ppe_packet_t ppep;
    uint8_t data[60];
    memset(data, 0, sizeof(data));
    ppe_packet_init(&ppep, data, sizeof(data));

    /* Set ethertypes before parsing */
    data[12] = 0x81;
    data[13] = 0x00;
    data[16] = 0x08;
    data[17] = 0x06;

    if (ppe_parse(&ppep) < 0) {
        AIM_DIE("arpa_send_packet parsing failed");
    }

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_DST_MAC,
                           info->eth_dst.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ETHERNET_DST_MAC");
    }

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_SRC_MAC,
                           info->eth_src.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ETHERNET_SRC_MAC");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_8021Q_VLAN, info->vlan_vid) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_8021Q_VLAN");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_8021Q_PRI, info->vlan_pcp) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_8021Q_PRI");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_OPERATION, info->operation) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_OPERATION");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_HTYPE, 1) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_HTYPE");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_PTYPE, 0x0800) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_PTYPE");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_HLEN, 6) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_HLEN");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_PLEN, 4) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_PLEN");
    }

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ARP_SHA, info->sha.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_SHA");
    }

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ARP_THA, info->tha.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_THA");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_SPA, info->spa) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_SPA");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_TPA, info->tpa) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_TPA");
    }

    of_packet_out_t *obj = of_packet_out_new(OF_VERSION_1_3);
    of_packet_out_buffer_id_set(obj, -1);
    of_packet_out_in_port_set(obj, OF_PORT_DEST_LOCAL);

    of_list_action_t *list = of_list_action_new(obj->version);
    of_action_output_t *action = of_action_output_new(list->version);
    of_action_output_port_set(action, OF_PORT_DEST_USE_TABLE);
    of_list_append(list, action);
    of_object_delete(action);
    AIM_TRUE_OR_DIE(of_packet_out_actions_set(obj, list) == 0);
    of_object_delete(list);

    of_octets_t octets = { data, sizeof(data) };
    if (of_packet_out_data_set(obj, &octets) < 0) {
        AIM_DIE("Failed to set data on ARP reply");
    }

    indigo_error_t rv = indigo_fwd_packet_out(obj);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to inject ARP reply: %s", indigo_strerror(rv));
    }

    of_packet_out_delete(obj);
}

static bool
arpa_check_source(struct arp_info *info)
{
    struct arp_entry *entry = arpa_lookup(info->vlan_vid, info->spa);
    if (entry == NULL) {
        AIM_LOG_TRACE("Source not found in ARP table");
        return false;
    }

    if (memcmp(info->sha.addr, entry->value.mac.addr, OF_MAC_ADDR_BYTES)) {
        AIM_LOG_TRACE("Source MAC does not match");
        entry->stats.miss_packets++;
        return false;
    }

    entry->stats.active_time = INDIGO_CURRENT_TIME;

    if (entry->timer_state != ARP_TIMER_STATE_NONE) {
        arpa_set_timer_state(entry, ARP_TIMER_STATE_UNICAST_QUERY);
    }

    if (info->operation == 1) {
        entry->stats.request_packets++;
    } else if (info->operation == 2) {
        entry->stats.reply_packets++;
    }

    return true;
}

static const char *
arpa_timer_state_to_string(enum arp_timer_state state)
{
    switch (state) {
    case ARP_TIMER_STATE_NONE: return "none";
    case ARP_TIMER_STATE_UNICAST_QUERY: return "unicast_query";
    case ARP_TIMER_STATE_BROADCAST_QUERY: return "broadcast_query";
    case ARP_TIMER_STATE_IDLE_TIMEOUT: return "idle_timeout";
    default: AIM_DIE("unexpected timer state %u", state);
    }
}

static void
arpa_set_timer_state(struct arp_entry *entry, enum arp_timer_state state)
{
    AIM_LOG_TRACE("VLAN=%u IP=%x timer state %s -> %s",
                  entry->key.vlan_vid, entry->key.ipv4,
                  arpa_timer_state_to_string(entry->timer_state),
                  arpa_timer_state_to_string(state));

    entry->timer_state = state;

    switch (state) {
    case ARP_TIMER_STATE_NONE:
        entry->deadline = 0;
        break;
    case ARP_TIMER_STATE_UNICAST_QUERY:
        entry->deadline = entry->stats.active_time + entry->value.unicast_query_timeout;
        break;
    case ARP_TIMER_STATE_BROADCAST_QUERY:
        entry->deadline = entry->stats.active_time + entry->value.broadcast_query_timeout;
        break;
    case ARP_TIMER_STATE_IDLE_TIMEOUT:
        entry->deadline = entry->stats.active_time + entry->value.idle_timeout;
        break;
    }
}

static void
arpa_timer(void *cookie)
{
    bighash_iter_t iter;
    bighash_entry_t *cur;
    indigo_time_t now = INDIGO_CURRENT_TIME;

    for (cur = bighash_iter_start(arp_entries, &iter);
         cur != NULL;
         cur = bighash_iter_next(&iter)) {
        struct arp_entry *entry = container_of(cur, hash_entry, struct arp_entry);

        if (entry->timer_state != ARP_TIMER_STATE_NONE && now >= entry->deadline) {
            if (entry->timer_state == ARP_TIMER_STATE_UNICAST_QUERY) {
                arpa_send_query(entry, false);
                arpa_set_timer_state(entry, ARP_TIMER_STATE_BROADCAST_QUERY);
            } else if (entry->timer_state == ARP_TIMER_STATE_BROADCAST_QUERY) {
                arpa_send_query(entry, true);
                arpa_set_timer_state(entry, ARP_TIMER_STATE_IDLE_TIMEOUT);
            } else if (entry->timer_state == ARP_TIMER_STATE_IDLE_TIMEOUT) {
                arpa_send_idle_notification(entry);
                entry->deadline = now + entry->value.idle_timeout;
            }
        }
    }
}

static void
arpa_send_query(struct arp_entry *entry, bool broadcast)
{
    AIM_LOG_VERBOSE("Sending %s query for VLAN %u IP %08x", broadcast ? "broadcast" : "unicast", entry->key.vlan_vid, entry->key.ipv4);

    /* Lookup the router for this VLAN */
    uint32_t router_ip;
    of_mac_addr_t router_mac;
    if (router_ip_table_lookup(entry->key.vlan_vid, &router_ip, &router_mac) < 0) {
        AIM_LOG_TRACE("no router configured on vlan %u", entry->key.vlan_vid);
        return;
    }

    /* Send an ARP request to the host, from the router */
    struct arp_info info;
    if (broadcast) {
        memcpy(info.eth_dst.addr, of_mac_addr_all_ones.addr, sizeof(info.eth_dst));
    } else {
        memcpy(info.eth_dst.addr, entry->value.mac.addr, sizeof(info.eth_dst));
    }
    memcpy(info.eth_src.addr, router_mac.addr, sizeof(info.eth_src));
    info.vlan_vid = entry->key.vlan_vid;
    info.vlan_pcp = 0;
    info.operation = 1;
    memcpy(info.sha.addr, router_mac.addr, sizeof(info.tha));
    info.spa = router_ip;
    memset(info.tha.addr, 0, sizeof(info.tha));
    info.tpa = entry->key.ipv4;

    arpa_send_packet(&info);
}

static void
arpa_send_idle_notification(struct arp_entry *entry)
{
    AIM_LOG_VERBOSE("Sending idle notification for VLAN %u IP %08x", entry->key.vlan_vid, entry->key.ipv4);

    of_version_t version;
    if (indigo_cxn_get_async_version(&version) < 0) {
        /* No controller connected */
        return;
    } else if (version < OF_VERSION_1_3) {
        /* ARP idle notification requires OF 1.3+ */
        return;
    }

    of_object_t *msg = of_bsn_arp_idle_new(version);
    of_bsn_arp_idle_vlan_vid_set(msg, entry->key.vlan_vid);
    of_bsn_arp_idle_ipv4_addr_set(msg, entry->key.ipv4);
    indigo_cxn_send_async_message(msg);
}
