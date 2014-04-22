/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
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
 * Implementation of ICMP Agent Handlers.
 *
 * This file contains the api's for initializing and handling incoming/outgoing
 * messages to/from icmp agent.
 */

#include "icmpa_int.h"

bool icmp_initialized = false;
aim_ratelimiter_t icmp_pktin_log_limiter;

icmpa_packet_counter_t pkt_counters;
icmpa_typecode_packet_counter_t port_pkt_counters[MAX_PORTS+1];

/*
 * icmp_send_packet_out
 * 
 * Send the ICMP message out
 */
indigo_error_t
icmpa_send_packet_out (of_octets_t *octets)
{
    of_packet_out_t    *obj;
    of_list_action_t   *list;
    of_action_output_t *action;
    indigo_error_t     rv;

    if (!octets) return INDIGO_ERROR_PARAM;

    obj = of_packet_out_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(obj != NULL);

    list = of_list_action_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(list != NULL);

    action = of_action_output_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(action != NULL);

    of_packet_out_buffer_id_set(obj, -1);
    of_packet_out_in_port_set(obj, OF_PORT_DEST_LOCAL);
    of_action_output_port_set(action, OF_PORT_DEST_USE_TABLE);
    of_list_append(list, action);
    of_object_delete(action);
    rv = of_packet_out_actions_set(obj, list);
    AIM_ASSERT(rv == 0);
    of_object_delete(list);

    rv = of_packet_out_data_set(obj, octets);
    if (rv < 0) {
        AIM_LOG_ERROR("ICMPA: Failed to set data on packet out");
        of_packet_out_delete(obj);
        return rv;
    }

    rv = indigo_fwd_packet_out(obj);
    of_packet_out_delete(obj);
    return rv;
}

/*
 * icmp_packet_in_handler 
 *
 * API for handling incoming packets
 */
indigo_core_listener_result_t
icmpa_packet_in_handler (of_packet_in_t *packet_in)
{
    of_octets_t                octets;
    of_port_no_t               port_no;
    of_match_t                 match;
    ppe_packet_t               ppep;
    indigo_core_listener_result_t result = INDIGO_CORE_LISTENER_RESULT_PASS;
    uint32_t                   type, code;

    debug_counter_inc(&pkt_counters.icmp_total_in_packets);
    if (!packet_in) return INDIGO_CORE_LISTENER_RESULT_PASS;

    of_packet_in_data_get(packet_in, &octets);

    /*
     * Identify the recv port
     */
    if (packet_in->version <= OF_VERSION_1_1) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_ERROR("ICMPA: match get failed");
            debug_counter_inc(&pkt_counters.icmp_internal_errors);
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        port_no = match.fields.in_port;
    }

    if (port_no > MAX_PORTS) {
        AIM_LOG_ERROR("ICMPA: Port No: %d Out of Range %d", port_no, MAX_PORTS);
        debug_counter_inc(&pkt_counters.icmp_internal_errors);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /*
     * Check the packet-in reasons in metadata 
     * FIXME: Temporary fix, need to think of long term solution
     */
    if ((match.fields.metadata & OFP_BSN_PKTIN_FLAG_STATION_MOVE) ||
        (match.fields.metadata & OFP_BSN_PKTIN_FLAG_NEW_HOST)) {
        debug_counter_inc(&pkt_counters.icmp_total_passed_packets);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    ppe_packet_init(&ppep, octets.data, octets.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&icmp_pktin_log_limiter, os_time_monotonic(),
                         "ICMPA: Packet_in parsing failed.");
        debug_counter_inc(&pkt_counters.icmp_internal_errors);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /*
     * Identify if this is an Echo Request, destined to one of VRouter
     */
    if (ppe_header_get(&ppep, PPE_HEADER_ICMP)) {
        if (icmpa_reply(&ppep, port_no)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_echo_packets;
            return result;
        } 
    }  
  
    /*
     * Identify if the reason is valid for ICMP Agent to consume the packet
     */
    if (match.fields.metadata & OFP_BSN_PKTIN_FLAG_L3_MISS) {
        AIM_LOG_TRACE("ICMP Dest Host Unreachable received on port: %d", 
                      port_no);
        type = ICMP_DEST_UNREACHABLE;
        code = 1;
        if (icmpa_send(&ppep, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_host_unreachable_packets;
        }
    } else if (match.fields.metadata & OFP_BSN_PKTIN_FLAG_TTL_EXPIRED) {
        AIM_LOG_TRACE("ICMP TTL Expired received on port: %d", port_no);
        type = ICMP_TIME_EXCEEDED;
        code = 0;
        if (icmpa_send(&ppep, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_time_exceeded_packets;    
        }
    }

    return result;
}

/*
 * icmpa_is_initialized
 *
 * true = ICMP Initialized
 * false = ICMP Uninitialized
 */
bool
icmpa_is_initialized (void)
{
    return icmp_initialized;
}

/*
 * icmpa_init
 *
 * API to init the ICMP Agent
 * This should only be done once at the beginning.
 */
indigo_error_t
icmpa_init (void)
{
    if (icmpa_is_initialized()) return INDIGO_ERROR_NONE;

    AIM_LOG_INFO("init");

    /*
     * Register system debug counters
     */
    debug_counter_register(&pkt_counters.icmp_total_in_packets,
                           "icmpa.icmp_total_in_packets",
                           "Packet-ins recv'd by icmpa");
    debug_counter_register(&pkt_counters.icmp_total_out_packets,
                           "icmpa.icmp_total_out_packets",
                           "Icmp packets sent by lacpa");
    debug_counter_register(&pkt_counters.icmp_total_passed_packets,
                           "icmpa.icmp_total_passed_packets",
                            "Packet-ins passed by icmpa");
    debug_counter_register(&pkt_counters.icmp_internal_errors,
                           "icmpa.icmp_internal_errors",
                           "Internal errors in icmpa");

    ICMPA_MEMSET(&port_pkt_counters[0], 0, 
                 sizeof(icmpa_typecode_packet_counter_t) * (MAX_PORTS+1));
    aim_ratelimiter_init(&icmp_pktin_log_limiter, 1000*1000, 5, NULL);

    /*
     * Register listerner for packet_in
     */
    if (indigo_core_packet_in_listener_register(
        (indigo_core_packet_in_listener_f) icmpa_packet_in_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for packet_in in ICMPA module");
        return INDIGO_ERROR_INIT;
    }

    icmp_initialized = true;
    return INDIGO_ERROR_NONE;
}

/*
 * icmpa_finish
 *
 * API to deinit the ICMP Agent
 * This will result in ICMP Agent being diabled in the system.
 */
void
icmpa_finish (void)
{
    if (!icmpa_is_initialized()) return;

    /*
     * Unregister system debug counters
     */
    debug_counter_unregister(&pkt_counters.icmp_total_in_packets);
    debug_counter_unregister(&pkt_counters.icmp_total_out_packets);
    debug_counter_unregister(&pkt_counters.icmp_total_passed_packets);
    debug_counter_unregister(&pkt_counters.icmp_internal_errors);

    ICMPA_MEMSET(&port_pkt_counters[0], 0,
                 sizeof(icmpa_typecode_packet_counter_t) * (MAX_PORTS+1));

    /*
     * Unregister listerner for packet_in
     */
    indigo_core_packet_in_listener_unregister(icmpa_packet_in_handler);

    icmp_initialized = false;
}
