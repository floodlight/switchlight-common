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
 * Implementation of Lacp Agent Handlers.
 *
 * This file contains the handlers for listening to port packets and
 * controllers messages. 
 *
 * Api support for sending Async msg's to the controller is also included. 
 */

#include "lacpa_int.h"
#include "lacpa_utils.h"

/*
 * lacpa_update_controller
 *
 * This API communicates Protocol Converged/Unconverged to the Controller
 */
void
lacpa_update_controller (lacpa_port_t *port)
{
    of_version_t                    version;
    of_bsn_lacp_convergence_notif_t *obj;
    
    if (!port) return;

    AIM_LOG_TRACE("Send %s msg to Controller for port: %d", port->is_converged?
                  "Converged" : "Unconverged", port->actor.port_no);

    if (indigo_cxn_get_async_version(&version) < 0) {

        /* 
         * No controllers connected 
         */
        AIM_LOG_TRACE("Error sending convergence status. No controller "
                      "connected");
        return;
    }
        
    obj = of_bsn_lacp_convergence_notif_new(version);
    AIM_TRUE_OR_DIE(obj != NULL);
    
    of_bsn_lacp_convergence_notif_convergence_status_set(obj, 
                                                         !port->is_converged); 

    /*
     * Set Actor params in the msg
     */
    of_bsn_lacp_convergence_notif_port_no_set(obj, port->actor.port_no);
    of_bsn_lacp_convergence_notif_actor_sys_priority_set(obj, 
                                                  port->actor.sys_priority);    
    of_bsn_lacp_convergence_notif_actor_sys_mac_set(obj, port->actor.sys_mac);
    of_bsn_lacp_convergence_notif_actor_port_priority_set(obj, 
                                                  port->actor.port_priority);
    of_bsn_lacp_convergence_notif_actor_port_num_set(obj, port->actor.port_num);
    of_bsn_lacp_convergence_notif_actor_key_set(obj, port->actor.key);

    /*
     * Set Partner params in the msg
     */
    of_bsn_lacp_convergence_notif_partner_sys_priority_set(obj,
                                                  port->partner.sys_priority);
    of_bsn_lacp_convergence_notif_partner_sys_mac_set(obj, 
                                                  port->partner.sys_mac);
    of_bsn_lacp_convergence_notif_partner_port_priority_set(obj,
                                                  port->partner.port_priority);         
    of_bsn_lacp_convergence_notif_partner_port_num_set(obj, 
                                                  port->partner.port_num);
    of_bsn_lacp_convergence_notif_partner_key_set(obj, port->partner.key);
        
    /*
     * Send convergence status to the controller 
     */
    indigo_cxn_send_async_message(obj);
    debug_counter_inc(&port->debug_info.lacp_convergence_notif);     
}

/*
 * lacpa_send_packet_out
 *
 * Send the LACPDU out the port
 */
void
lacpa_send_packet_out (lacpa_port_t *port, of_octets_t *octets)
{
    of_packet_out_t    *obj;
    of_list_action_t   *list;
    of_action_output_t *action;
    indigo_error_t     rv;
    
    if (!port || !octets) return;
    
    obj = of_packet_out_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(obj != NULL);

    list = of_list_action_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(list != NULL);

    action = of_action_output_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(action != NULL);
    
    of_action_output_port_set(action, port->actor.port_no);
    of_list_append(list, action);
    of_object_delete(action);
    rv = of_packet_out_actions_set(obj, list);
    AIM_ASSERT(rv == 0);
    of_object_delete(list);

    if (of_packet_out_data_set(obj, octets) < 0) {
        AIM_LOG_ERROR("Failed to set data on packet out");
        of_packet_out_delete(obj);
        return;
    }

    rv = indigo_fwd_packet_out(obj);
    if (rv < 0) {
        AIM_LOG_ERROR("Failed to send packet out the port: %d, reason: %s", 
                      port->actor.port_no, indigo_strerror(rv));
    } else {
        AIM_LOG_TRACE("Successfully sent packet out the port: %d", 
                      port->actor.port_no);
        debug_counter_inc(&port->debug_info.lacp_port_out_packets);
        debug_counter_inc(&lacpa_system.debug_info.lacp_system_out_packets);
    }

    of_packet_out_delete(obj);
}

/*
 * lacpa_packet_in_handler 
 *
 * API for handling incoming port packets
 */
indigo_core_listener_result_t
lacpa_packet_in_handler (of_packet_in_t *packet_in)
{
    of_octets_t                octets;
    of_port_no_t               port_no;
    of_match_t                 match;
    lacpa_port_t               *port;
    lacpa_pdu_t                pdu;
    ppe_packet_t               ppep;

    debug_counter_inc(&lacpa_system.debug_info.lacp_total_in_packets);
    if (!packet_in) return INDIGO_CORE_LISTENER_RESULT_PASS;

    LACPA_MEMSET(&pdu, 0, sizeof(lacpa_pdu_t));

    of_packet_in_data_get(packet_in, &octets);  

    /*
     * Identify if this is an LACP Packet
     */
    ppe_packet_init(&ppep, octets.data, octets.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&lacpa_pktin_log_limiter, os_time_monotonic(),
                         "Packet_in parsing failed."); 
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_LACP)) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    debug_counter_inc(&lacpa_system.debug_info.lacp_system_in_packets); 

    /*
     * Identify the recv port and see if it has LACP agent running
     */ 
    if (packet_in->version <= OF_VERSION_1_1) {
        of_packet_in_in_port_get(packet_in, &port_no);
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_ERROR("match get failed");          
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        port_no = match.fields.in_port; 
    }

    AIM_LOG_TRACE("LACPDU Received on port: %d", port_no);
    port = lacpa_find_port(port_no);
    if (!port) return INDIGO_CORE_LISTENER_RESULT_PASS;
 
    if (!port->lacp_enabled) {
        AIM_LOG_TRACE("LACPDU-Rx-FAILED - Agent is Disabled on port: %d",
                      port_no);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (AIM_LOG_CUSTOM_ENABLED(LACPA_LOG_FLAG_PORTSTATS)) {
        ppe_packet_dump(&ppep, aim_log_pvs_get(&AIM_LOG_STRUCT));
    }

    /*
     * Retrieve the information from the LACP packet
     */
    if (!lacpa_parse_pdu(&ppep, &pdu)) {
        AIM_LOG_ERROR("Packet parsing failed on port: %d", port_no);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    lacpa_machine(port, &pdu, LACPA_EVENT_PDU_RECEIVED);

    return INDIGO_CORE_LISTENER_RESULT_DROP;
}

/*
 * lacpa_set_port_param_handle
 *
 * Handle the Controller msg for setting the port parameters
 */
static void
lacpa_set_port_param_handle (indigo_cxn_id_t cxn,
                             of_bsn_set_lacp_request_t *obj)
{
    uint32_t                xid = 0;
    uint8_t                 enabled = 0;
    uint32_t                status = 0;
    lacpa_info_t            info;
    of_bsn_set_lacp_reply_t *reply;

    if (!obj) return;

    LACPA_MEMSET(&info, 0, sizeof(lacpa_info_t));

    of_bsn_set_lacp_request_xid_get(obj, &xid);
    of_bsn_set_lacp_request_enabled_get(obj, &enabled);

    AIM_LOG_TRACE("Handle %s Controller msg with xid: %d, lacp enabled: %d",
                  of_object_id_str[obj->object_id], xid, enabled);

    /*
     * Get the port parameters
     */
    of_bsn_set_lacp_request_port_no_get(obj, &info.port_no);
    of_bsn_set_lacp_request_actor_sys_priority_get(obj, &info.sys_priority);
    of_bsn_set_lacp_request_actor_sys_mac_get(obj, &info.sys_mac);
    of_bsn_set_lacp_request_actor_port_priority_get(obj, &info.port_priority);
    of_bsn_set_lacp_request_actor_port_num_get(obj, &info.port_num);
    of_bsn_set_lacp_request_actor_key_get(obj, &info.key);

    AIM_LOG_TRACE("Init Actor Port: %d, sys_priority: %d, sys_mac: %{mac}, "
                  "port_priority: %d, port_num: %d, key: %d", info.port_no,
                  info.sys_priority, info.sys_mac.addr, info.port_priority,
                  info.port_num, info.key);
    lacpa_init_port(&info, enabled);

    /*
     * Set up reply 
     */
    reply = of_bsn_set_lacp_reply_new(obj->version);
    AIM_TRUE_OR_DIE(reply != NULL);

    of_bsn_set_lacp_reply_xid_set(reply, xid);

    of_bsn_set_lacp_reply_status_set(reply, status);
    of_bsn_set_lacp_reply_port_no_set(reply, info.port_no);

    /* 
     * Send reply back to the Controller
     */
    indigo_cxn_send_controller_message(cxn, reply);
}

/*
 * lacpa_get_port_stats_handle
 *
 * Handle the Controller msg for getting port stats
 */
static void
lacpa_get_port_stats_handle (indigo_cxn_id_t cxn,
                             of_bsn_lacp_stats_request_t *obj)
{
    uint32_t                       xid = 0;
    uint32_t                       i = 0;
    lacpa_port_t                   *port;
    of_bsn_lacp_stats_reply_t      *reply;
    of_bsn_lacp_stats_entry_t      *entry;
    of_list_bsn_lacp_stats_entry_t entries;


    if (!obj) return;

    of_bsn_lacp_stats_request_xid_get(obj, &xid);

    AIM_LOG_TRACE("Handle %s Controller msg with xid: %d",
                  of_object_id_str[obj->object_id], xid);

    /*
     * Set up reply 
     */
    reply = of_bsn_lacp_stats_reply_new(obj->version);
    AIM_TRUE_OR_DIE(reply != NULL);

    of_bsn_lacp_stats_reply_xid_set(reply, xid);

    of_bsn_lacp_stats_reply_entries_bind(reply, &entries);
    entry = of_bsn_lacp_stats_entry_new(entries.version);
    AIM_TRUE_OR_DIE(entry != NULL);

    /*
     * Loop over all the port's in the system with lacp enabled and 
     * send their stats info to the controller in a packed msg
     */
    for (i = 0; i <= PHY_PORT_COUNT; i++) {
        port = lacpa_find_port(i);

        if (port && port->lacp_enabled) {
            AIM_LOG_TRACE("Filling Stats request for Port: %d",
                          port->actor.port_no);

            /*
             * Set Actor stats in the reply
             */
            of_bsn_lacp_stats_entry_port_no_set(entry, port->actor.port_no);
            of_bsn_lacp_stats_entry_actor_sys_priority_set(entry,
                                                   port->actor.sys_priority);
            of_bsn_lacp_stats_entry_actor_sys_mac_set(entry,
                                                   port->actor.sys_mac);
            of_bsn_lacp_stats_entry_actor_port_priority_set(entry,
                                                   port->actor.port_priority);
            of_bsn_lacp_stats_entry_actor_port_num_set(entry,
                                                   port->actor.port_num);
            of_bsn_lacp_stats_entry_actor_key_set(entry, port->actor.key);
            of_bsn_lacp_stats_entry_convergence_status_set(entry,
                                                   !port->is_converged);

            /*
             * Set Partner stats in the reply
             */
            of_bsn_lacp_stats_entry_partner_sys_priority_set(entry,
                                                   port->partner.sys_priority);
            of_bsn_lacp_stats_entry_partner_sys_mac_set(entry,
                                                   port->partner.sys_mac);
            of_bsn_lacp_stats_entry_partner_port_priority_set(entry,
                                                   port->partner.port_priority);
            of_bsn_lacp_stats_entry_partner_port_num_set(entry,
                                                   port->partner.port_num);
            of_bsn_lacp_stats_entry_partner_key_set(entry, port->partner.key);

            /*
             * Append the entry obj created in the list of enteries
             */
            if (of_list_append(&entries, entry) < 0) {
                
                /* 
                 * This entry didn't fit, send out the current message and
                 * allocate a new one. 
                 */
                of_bsn_lacp_stats_reply_flags_set(reply, 
                                             OF_STATS_REPLY_FLAG_REPLY_MORE);
                indigo_cxn_send_controller_message(cxn, reply);

                reply = of_bsn_lacp_stats_reply_new(obj->version);
                AIM_TRUE_OR_DIE(reply != NULL);

                of_bsn_lacp_stats_reply_xid_set(reply, xid);
                of_bsn_lacp_stats_reply_entries_bind(reply, &entries);

                if (of_list_append(&entries, entry) < 0) {    
                    AIM_DIE("Unexpected failure appending single bsn_lacp"
                            "stats entry");
                }
            }
        }
    }

    of_object_delete(entry);

    /* 
     * Send reply back to the Controller
     */
    indigo_cxn_send_controller_message(cxn, reply);
}

/*
 * lacpa_controller_msg_handler
 *
 * API for handling incoming Controller msg's
 */
indigo_core_listener_result_t
lacpa_controller_msg_handler (indigo_cxn_id_t cxn, of_object_t *obj)
{
    indigo_core_listener_result_t result = INDIGO_CORE_LISTENER_RESULT_PASS;

    if (!lacpa_is_initialized()) {
        AIM_LOG_ERROR("LACPA module uninitalized");
        return result;
    }

    AIM_LOG_TRACE("Received %s Controller msg with cxn: %d",
                  of_object_id_str[obj->object_id], cxn);

    /*
     * Check if the msg is intended for lacpa module
     */
    switch (obj->object_id) {
    case OF_BSN_SET_LACP_REQUEST:
        debug_counter_inc(&lacpa_system.debug_info.lacp_controller_set_requests);
        lacpa_set_port_param_handle(cxn, (of_bsn_set_lacp_request_t *)obj);
        result = INDIGO_CORE_LISTENER_RESULT_DROP;
        break;

    case OF_BSN_LACP_STATS_REQUEST:
        debug_counter_inc(&lacpa_system.debug_info.lacp_controller_stats_requests);
        lacpa_get_port_stats_handle(cxn, (of_bsn_lacp_stats_request_t *)obj);
        result = INDIGO_CORE_LISTENER_RESULT_DROP;
        break;

    default:
        break;
    }

    return result;
}
