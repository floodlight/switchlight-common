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
icmpa_send_packet_out (of_octets_t *octets, of_port_no_t port_no)
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

    of_action_output_port_set(action, port_no);
    of_list_append(list, action);
    of_object_delete(action);
    rv = of_packet_out_actions_set(obj, list);
    of_object_delete(list);

    rv = of_packet_out_data_set(obj, octets);
    if (rv < 0) {
        AIM_LOG_ERROR("ICMPA: Failed to set data on packet out");
        of_packet_out_delete(obj);
        return rv;
    }

    rv = indigo_fwd_packet_out(obj);
    if (rv < 0) {
        AIM_LOG_ERROR("ICMPA: Failed to send packet out the port: %d, "
                      "reason: %s", port_no, indigo_strerror(rv));
    } else {
        ++pkt_counters.icmp_total_out_packets; 
        AIM_LOG_TRACE("Successfully sent packet out the port: %d", port_no);
    }

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
    uint8_t                    reason;
    indigo_core_listener_result_t result = INDIGO_CORE_LISTENER_RESULT_PASS;
    uint32_t                   type, code;

    ++pkt_counters.icmp_total_in_packets;
    if (!packet_in) return INDIGO_CORE_LISTENER_RESULT_PASS;

    of_packet_in_data_get(packet_in, &octets);
    of_packet_in_reason_get(packet_in, &reason); 

    /*
     * Identify the recv port
     */
    if (packet_in->version <= OF_VERSION_1_1) {
        of_packet_in_in_port_get(packet_in, &port_no);
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_ERROR("ICMPA: match get failed");
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        port_no = match.fields.in_port;
    }

    if (port_no > MAX_PORTS) {
        AIM_LOG_ERROR("ICMPA: Port No: %d Out of Range %d", port_no, MAX_PORTS);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /*
     * Identify if the reason is valid for ICMP Agent to parse the packet
     */
    switch (reason) {
    case OF_PACKET_IN_REASON_BSN_ICMP_ECHO_REQUEST:
        AIM_LOG_TRACE("ICMP ECHO Request received on port: %d", port_no);
        if (icmpa_reply(&octets, port_no)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP; 
            ++port_pkt_counters[port_no].icmp_echo_packets;
        }   
        break;
    case OF_PACKET_IN_REASON_BSN_DEST_NETWORK_UNREACHABLE:
        AIM_LOG_TRACE("ICMP Dest Network Unreachable received on port: %d",
                      port_no);
        type = ICMP_DEST_UNREACHABLE;
        code = 0;
        if (icmpa_send(&octets, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_network_unreachable_packets;
        }
        break;
    case OF_PACKET_IN_REASON_BSN_DEST_HOST_UNREACHABLE:
        AIM_LOG_TRACE("ICMP Dest Host Unreachable received on port: %d", 
                      port_no);
        type = ICMP_DEST_UNREACHABLE;
        code = 1;
        if (icmpa_send(&octets, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_host_unreachable_packets;
        }
        break;
    case OF_PACKET_IN_REASON_BSN_DEST_PORT_UNREACHABLE:
        AIM_LOG_TRACE("ICMP Dest Port Unreachable received on port: %d", 
                      port_no);
        type = ICMP_DEST_UNREACHABLE;
        code = 3;
        if (icmpa_send(&octets, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_port_unreachable_packets;
        }
        break;
    case OF_PACKET_IN_REASON_BSN_FRAGMENTATION_REQUIRED:
        AIM_LOG_TRACE("ICMP Fragmentation Reqd received on port: %d", port_no);
        type = ICMP_DEST_UNREACHABLE;
        code = 4; 
        if (icmpa_send(&octets, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_fragmentation_reqd_packets;
        }
        break;
    case OF_PACKET_IN_REASON_INVALID_TTL:
        AIM_LOG_TRACE("ICMP TTL Expired received on port: %d", port_no);
        type = ICMP_TIME_EXCEEDED;
        code = 0;
        if (icmpa_send(&octets, port_no, type, code)) {
            result = INDIGO_CORE_LISTENER_RESULT_DROP;
            ++port_pkt_counters[port_no].icmp_time_exceeded_packets;    
        }
        break;
    default:
        break;    
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

    AIM_LOG_TRACE("Initing the ICMP Agent...");

    pkt_counters.icmp_total_in_packets = 0;
    pkt_counters.icmp_total_out_packets = 0;
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

    AIM_LOG_TRACE("Deiniting the ICMP Agent...");

    pkt_counters.icmp_total_in_packets = 0;
    pkt_counters.icmp_total_out_packets = 0;
    ICMPA_MEMSET(&port_pkt_counters[0], 0,
                 sizeof(icmpa_typecode_packet_counter_t) * (MAX_PORTS+1));

    /*
     * Unregister listerner for packet_in
     */
    indigo_core_packet_in_listener_unregister(icmpa_packet_in_handler);

    icmp_initialized = false;
}
