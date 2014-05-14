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

/*
 * Implementation of BigTap ARP Agent.
 * (Not to be confused with arpa module which is t5/t6 ARP agent)  
 *
 * This file contains the api's for initializing and handling incoming/outgoing
 * messages to/from the agent.
 *
 * ARP Agent maintains a cache for IP --> MAC mapping and 
 * responds to ARP requests for target IP's present in the cache.
 * ARP requests for IP addresses not present in the cache are passed
 * to the controller.
 *
 * ARP Cache enteries are added/deleted by 
 * broadcom/Modules/Indigo/BRCMDriver/module/src/brcm_l2gre_port.c
 */

#include "arpra_int.h"

bool arpra_initialized = false;
aim_ratelimiter_t arpra_pktin_log_limiter;
static LIST_DEFINE(arp_cache);
arpra_packet_counter_t pkt_counters;

/*
 * arpra_is_initialized
 *
 * true = ARPRA Initialized
 * false = ARPRA Uninitialized
 */
bool
arpra_is_initialized (void)
{
    return arpra_initialized;
}

/*
 * arp_cache_list
 *  
 * Return a list of arp cache entries 
 *
 * The list is through the 'links' field of arp_cache_t.
 */
list_head_t *
arp_cache_list(void)
{
    return &arp_cache;
}

/*
 * arpra_parse_packet
 * 
 * Parse ARP packet and extract info 
 */
static indigo_error_t
arpra_parse_packet (ppe_packet_t *ppep, arp_info_t *info)
{
    uint32_t tmp;    

    if (!ppep || !info) return INDIGO_ERROR_PARAM;

    ppe_wide_field_get(ppep, PPE_FIELD_ETHERNET_DST_MAC, info->eth_dst.addr);

    ppe_wide_field_get(ppep, PPE_FIELD_ETHERNET_SRC_MAC, info->eth_src.addr);

    ppe_field_get(ppep, PPE_FIELD_8021Q_VLAN, &tmp);
    info->vlan_vid = tmp;

    ppe_field_get(ppep, PPE_FIELD_8021Q_PRI, &tmp);
    info->vlan_pcp = tmp;

    ppe_field_get(ppep, PPE_FIELD_ARP_HTYPE, &tmp);
    if (tmp != 1) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(ppep, PPE_FIELD_ARP_PTYPE, &tmp);
    if (tmp != 0x0800) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(ppep, PPE_FIELD_ARP_HLEN, &tmp);
    if (tmp != 6) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(ppep, PPE_FIELD_ARP_PLEN, &tmp);
    if (tmp != 4) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(ppep, PPE_FIELD_ARP_OPERATION, &tmp);
    info->operation = tmp;

    ppe_wide_field_get(ppep, PPE_FIELD_ARP_SHA, info->sender.mac.addr);

    ppe_field_get(ppep, PPE_FIELD_ARP_SPA, &tmp);
    info->sender.ipv4 = tmp;

    ppe_wide_field_get(ppep, PPE_FIELD_ARP_THA, info->target.mac.addr);

    ppe_field_get(ppep, PPE_FIELD_ARP_TPA, &tmp);
    info->target.ipv4 = tmp;

    return INDIGO_ERROR_NONE;
}

/* 
 * arpra_lookup
 *
 * return true if target ip is one of the tunnel interface; 
 * fill mac with addr associated with that interface
 *
 * else; returns false
 */ 
bool
arpra_lookup (uint32_t ipv4, of_mac_addr_t *mac)
{
    list_head_t *cache = arp_cache_list();
    list_links_t *cur;
    LIST_FOREACH(cache, cur) {
        arp_cache_entry_t *cache_entry = container_of(cur, links,
                                                      arp_cache_entry_t);
        if (cache_entry->entry.ipv4 == ipv4) {
            ARPRA_MEMCPY(mac->addr, cache_entry->entry.mac.addr,
                         OF_MAC_ADDR_BYTES); 
            AIM_LOG_TRACE("Target mac: %{mac} found", 
                          cache_entry->entry.mac.addr);
            return true; 
        }
    }

    AIM_LOG_TRACE("Target ip: %{ipv4a} not found in ARP cache", ipv4); 
    return false;
}

/*
 * arpra_send_packet
 *
 * Construct the arp response and send it out on specified port 
 */
static void
arpra_send_packet (arp_info_t *info, of_port_no_t port_no)
{
    ppe_packet_t ppep;
    uint8_t data[60];

    if (!info) return;

    memset(data, 0, sizeof(data));
    ppe_packet_init(&ppep, data, sizeof(data));

    /* 
     * Set ethertypes before parsing 
     */
    data[12] = 0x81;
    data[13] = 0x00;
    data[16] = 0x08;
    data[17] = 0x06;

    if (ppe_parse(&ppep) < 0) {
        AIM_DIE("arpra_send_packet parsing failed");
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

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ARP_SHA, info->sender.mac.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_SHA");
    }

    if (ppe_wide_field_set(&ppep, PPE_FIELD_ARP_THA, info->target.mac.addr) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_THA");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_SPA, info->sender.ipv4) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_SPA");
    }

    if (ppe_field_set(&ppep, PPE_FIELD_ARP_TPA, info->target.ipv4) < 0) {
        AIM_DIE("Failed to set PPE_FIELD_ARP_TPA");
    }

    of_packet_out_t    *obj;
    of_list_action_t   *list;
    of_action_output_t *action;
    indigo_error_t     rv;

    obj = of_packet_out_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(obj != NULL);

    list = of_list_action_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(list != NULL);

    action = of_action_output_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(action != NULL);

    of_action_output_port_set(action, port_no);
    of_list_append(list, action);
    of_object_delete(action);
    rv = of_packet_out_actions_set(obj, list);
    AIM_ASSERT(rv == 0);
    of_object_delete(list);
    
    of_octets_t octets = { data, sizeof(data) };
    if (of_packet_out_data_set(obj, &octets) < 0) {
        AIM_DIE("Failed to set data on ARP reply");
    }

    rv = indigo_fwd_packet_out(obj);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to send packet out the port: %d, reason: %s",
                      port_no, indigo_strerror(rv));
        debug_counter_inc(&pkt_counters.internal_errors);
    } else {
        AIM_LOG_TRACE("Succesfully sent a packet out the port: %d", port_no);
        debug_counter_inc(&pkt_counters.total_out_packets);
    }

    of_packet_out_delete(obj); 
}

/*
 * icmp_packet_in_handler 
 *
 * API for handling incoming packets
 */
indigo_core_listener_result_t
arpra_packet_in_handler (of_packet_in_t *packet_in)
{
    of_octets_t                   octets;
    of_port_no_t                  port_no;
    of_match_t                    match;
    ppe_packet_t                  ppep;
    arp_info_t                    info;
    indigo_error_t                rv;

    debug_counter_inc(&pkt_counters.total_in_packets);
    if (!packet_in) return INDIGO_CORE_LISTENER_RESULT_PASS;

    of_packet_in_data_get(packet_in, &octets);

    /*
     * Identify the recv port
     */
    if (packet_in->version <= OF_VERSION_1_1) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_ERROR("ARPRA: match get failed");
            debug_counter_inc(&pkt_counters.internal_errors);    
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        port_no = match.fields.in_port;
    }

    ppe_packet_init(&ppep, octets.data, octets.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&arpra_pktin_log_limiter, os_time_monotonic(),
                         "ARPRA: Packet_in parsing failed.");
        debug_counter_inc(&pkt_counters.internal_errors);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /*
     * Identify if this is an ARP Packet
     */
    if (!ppe_header_get(&ppep, PPE_HEADER_8021Q)) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_ARP)) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    rv = arpra_parse_packet(&ppep, &info);
    if (rv < 0) {
        AIM_LOG_RL_ERROR(&arpra_pktin_log_limiter, os_time_monotonic(),
                         "ARPRA: not a valid ARP packet: %s", 
                         indigo_strerror(rv));
        debug_counter_inc(&pkt_counters.internal_errors);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    AIM_LOG_TRACE("Received ARP packet: op: %d spa: %{ipv4a}, tpa: %{ipv4a}", 
                  info.operation, info.sender.ipv4, info.target.ipv4);

    /*
     * Only interested in arp requests, arp replies will be passed to 
     * the controller
     */
    if (info.operation != 1) {
        AIM_LOG_TRACE("Ignoring ARP reply");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (!arpra_lookup(info.target.ipv4, &info.target.mac)) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }
   
    AIM_LOG_TRACE("Sending ARP Reply for ip: %{ipv4a}, mac: %{mac}", 
                  info.target.ipv4, info.target.mac.addr);

    /* 
     * Send an ARP reply to the SHA of the request
     */
    arp_info_t reply_info = info;
    memcpy(reply_info.eth_dst.addr, info.sender.mac.addr, 
           sizeof(reply_info.eth_dst));
    memcpy(reply_info.eth_src.addr, info.target.mac.addr, 
           sizeof(reply_info.eth_src));
    reply_info.target.ipv4 = info.sender.ipv4;
    memcpy(reply_info.target.mac.addr, info.sender.mac.addr, 
           sizeof(reply_info.target.mac));
    reply_info.sender.ipv4 = info.target.ipv4;
    memcpy(reply_info.sender.mac.addr, info.target.mac.addr, 
           sizeof(reply_info.sender.mac));
    reply_info.operation = 2;

    arpra_send_packet(&reply_info, port_no);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

/*
 * arpra_find_cache_entry
 *
 * API to find if an ip --> mac mapping exists in the arp cache
 */
static arp_cache_entry_t *
arpra_find_cache_entry (uint32_t ipv4, of_mac_addr_t mac)
{
    list_head_t *cache = arp_cache_list();
    list_links_t *cur;
    LIST_FOREACH(cache, cur) {
        arp_cache_entry_t *cache_entry = container_of(cur, links, 
                                                      arp_cache_entry_t);
        if (cache_entry->entry.ipv4 == ipv4 && 
            !ARPRA_MEMCMP(cache_entry->entry.mac.addr, mac.addr, 
                          OF_MAC_ADDR_BYTES)) {
            return cache_entry;
        }
    }
    
    return NULL;
}

/*
 * arpra_add_cache_entry
 *
 * API to add an ip --> mac mapping in the arp cache
 */
indigo_error_t
arpra_add_cache_entry (uint32_t ipv4, of_mac_addr_t mac)
{
    arp_cache_entry_t *cache_entry;

    if (!arpra_is_initialized()) return INDIGO_ERROR_INIT;

    AIM_LOG_TRACE("Received Arp cache entry add request for ip: %{ipv4a}, "
                  "mac: %{mac}", ipv4, mac.addr);

    cache_entry = arpra_find_cache_entry(ipv4, mac);
    if (cache_entry) {
        AIM_LOG_TRACE("Entry already exist in the arp cache");
        ++cache_entry->refcount;
        AIM_LOG_TRACE("Incermented refcount for Arp cache entry with ip: "
                      "%{ipv4a}, mac: %{mac} to refcount: %d",
                      cache_entry->entry.ipv4, cache_entry->entry.mac.addr,
                      cache_entry->refcount);            
        return INDIGO_ERROR_NONE;
    }

    cache_entry = (arp_cache_entry_t *) ARPRA_MALLOC(sizeof(arp_cache_entry_t)); 
    AIM_TRUE_OR_DIE(cache_entry != NULL);
    ARPRA_MEMSET(cache_entry, 0, sizeof(arp_cache_entry_t));
    cache_entry->entry.ipv4 = ipv4;
    ARPRA_MEMCPY(cache_entry->entry.mac.addr, mac.addr, OF_MAC_ADDR_BYTES);  
    ++cache_entry->refcount;
    list_push(&arp_cache, &cache_entry->links);    

    AIM_LOG_TRACE("Added Arp cache entry with ip: %{ipv4a}, mac: %{mac}, "
                  "refcount: %d", cache_entry->entry.ipv4, cache_entry->entry.mac.addr,
                  cache_entry->refcount);

    return INDIGO_ERROR_NONE;
}

/*
 * arpra_delete_cache_entry
 *
 * API to delete an ip --> mac mapping from the arp cache
 */
indigo_error_t
arpra_delete_cache_entry (uint32_t ipv4, of_mac_addr_t mac)
{
    arp_cache_entry_t *cache_entry;

    if (!arpra_is_initialized()) return INDIGO_ERROR_INIT;
    
    AIM_LOG_TRACE("Received Arp cache entry delete request for ip: %{ipv4a}, "
                  "mac: %{mac}", ipv4, mac.addr);
   
    cache_entry = arpra_find_cache_entry(ipv4, mac);
    if (!cache_entry) {
        AIM_LOG_TRACE("No such entry exist in the arp cache");  
        return INDIGO_ERROR_NONE;
    }

    --cache_entry->refcount;
    if (cache_entry->refcount) {
        AIM_LOG_TRACE("Decremented refcount for Arp cache entry with ip: "
                      "%{ipv4a}, mac: %{mac} to refcount: %d",
                      cache_entry->entry.ipv4, cache_entry->entry.mac.addr,
                      cache_entry->refcount);
    } else {
        AIM_LOG_TRACE("Deleted Arp cache entry with ip: %{ipv4a}, mac: %{mac}",
                      cache_entry->entry.ipv4, cache_entry->entry.mac.addr);
        list_remove(&cache_entry->links);
        ARPRA_FREE(cache_entry);
    }

    return INDIGO_ERROR_NONE;
}

/*
 * arpra_delete_cache
 *
 * Delete all the entries from the arp cache
 */
static void
arpra_delete_cache (void)
{
    list_head_t *cache = arp_cache_list();
    list_links_t *cur, *next;
    LIST_FOREACH_SAFE(cache, cur, next) {
        arp_cache_entry_t *cache_entry = container_of(cur, links,
                                                      arp_cache_entry_t);
        list_remove(&cache_entry->links);
        ARPRA_FREE(cache_entry);
    }
}

/*
 * arpra_init
 *
 * API to init the ARPRA Agent
 * This should only be done once at the beginning.
 */
indigo_error_t
arpra_init (void)
{
    if (arpra_is_initialized()) return INDIGO_ERROR_NONE;

    AIM_LOG_INFO("init");

    aim_ratelimiter_init(&arpra_pktin_log_limiter, 1000*1000, 5, NULL);

    /*
     * Register debug counters
     */
    debug_counter_register(&pkt_counters.total_in_packets,
                           "arpra.total_in_packets",
                           "Packet-ins recv'd by arpra");
    debug_counter_register(&pkt_counters.total_out_packets,
                           "arpra.total_out_packets",
                           "ARP replies sent by arpra");
    debug_counter_register(&pkt_counters.internal_errors,
                           "arpra.internal_errors",
                           "Internal errors in arpra");    

    /*
     * Register listerner for packet_in
     */
    if (indigo_core_packet_in_listener_register(
        (indigo_core_packet_in_listener_f) arpra_packet_in_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for packet_in in ARPRA module");
        return INDIGO_ERROR_INIT;
    }

    arpra_initialized = true;
    return INDIGO_ERROR_NONE;
}

/*
 * arpra_finish
 *
 * API to deinit the ARPRA Agent
 * This will result in ARPRA Agent being diabled in the system.
 */
void
arpra_finish (void)
{
    if (!arpra_is_initialized()) return;

    /*
     * Unregister debug counters
     */
    debug_counter_unregister(&pkt_counters.total_in_packets);
    debug_counter_unregister(&pkt_counters.total_out_packets);
    debug_counter_unregister(&pkt_counters.internal_errors); 

    /*
     * Unregister listerner for packet_in
     */
    indigo_core_packet_in_listener_unregister(arpra_packet_in_handler);

    arpra_delete_cache();

    arpra_initialized = false;
}
