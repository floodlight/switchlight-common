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
 * Implementation of Lacp Agent State Machine.
 *
 * This file contains the state machhine handling and transitions between states
 * for lacp agent.
 */

#include "lacpa_int.h"
#include "lacpa_utils.h"
#include <PPE/ppe.h>

bool churn_detection_running = false;

/*
 * Slow-Protocols Dest Mac
 */
uint8_t
slow_protocols_address[OF_MAC_ADDR_BYTES] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};
uint8_t
port_src_mac_address[OF_MAC_ADDR_BYTES] = {0x55, 0x16, 0xc7, 0xff, 0xff, 0x07};

/*
 * lacpa_dump_state
 *
 * Dumps the actor/partner state flags
 */
void
lacpa_dump_state (lacpa_port_t *port)
{
    if (!port) return;

    LACPA_LOG_PORTSTATS("*************DUMPING STATE INFO*************\n");
    LACPA_LOG_PORTSTATS("\nACTOR STATE FLAGS");
    LACPA_LOG_PORTSTATS("ACTOR OF_PORT_NO        : %d", port->actor.port_no);
    LACPA_LOG_PORTSTATS("ACTOR LACP ACTIVITY     : %s", 
                        LACPA_IS_STATE_LACP_ACTIVITY(port->actor.state)? 
                        "ACTIVE" : "PASSIVE");
    LACPA_LOG_PORTSTATS("ACTOR LACP TIMEOUT      : %s", 
                        LACPA_IS_STATE_LACP_TIMEOUT(port->actor.state)? 
                        "SHORT" : "LONG");
    LACPA_LOG_PORTSTATS("ACTOR AGGREGATION       : %s", 
                        LACPA_IS_STATE_AGGREGATION(port->actor.state)?
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("ACTOR SYNCHRONIZATION   : %s", 
                        LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)?
                        "INSYNC" : "OUTofSYNC");
    LACPA_LOG_PORTSTATS("ACTOR COLLECTING        : %s", 
                        LACPA_IS_STATE_COLLECTING(port->actor.state)?
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("ACTOR DISTRIBUTING      : %s", 
                        LACPA_IS_STATE_DISTRIBUTING(port->actor.state)?
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("\nPARTNER STATE FLAGS");
    LACPA_LOG_PORTSTATS("PARTNER PORT_NUM        : %d", port->partner.port_num);
    LACPA_LOG_PORTSTATS("PARTNER LACP ACTIVITY   : %s", 
                        LACPA_IS_STATE_LACP_ACTIVITY(port->partner.state)? 
                        "ACTIVE" : "PASSIVE");
    LACPA_LOG_PORTSTATS("PARTNER LACP TIMEOUT    : %s", 
                        LACPA_IS_STATE_LACP_TIMEOUT(port->partner.state)? 
                        "SHORT" : "LONG");
    LACPA_LOG_PORTSTATS("PARTNER AGGREGATION     : %s", 
                        LACPA_IS_STATE_AGGREGATION(port->partner.state)? 
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("PARTNER SYNCHRONIZATION : %s",
                        LACPA_IS_STATE_SYNCHRONIZATION(port->partner.state)?
                        "INSYNC" : "OUTofSYNC");
    LACPA_LOG_PORTSTATS("PARTNER COLLECTING      : %s", 
                        LACPA_IS_STATE_COLLECTING(port->partner.state)?
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("PARTNER DISTRIBUTING    : %s", 
                        LACPA_IS_STATE_DISTRIBUTING(port->partner.state)?
                        "YES" : "NO");
    LACPA_LOG_PORTSTATS("*************END DUMPING INFO**************\n");
}

/*
 * lacpa_dump_port
 *
 * Dumps the current port information
 */
void
lacpa_dump_port (lacpa_port_t *port)
{
    if (!port) return;

    LACPA_LOG_PORTSTATS("*************DUMPING PORT INFO*************\n");
    LACPA_LOG_PORTSTATS("\nACTOR PORT INFO");
    LACPA_LOG_PORTSTATS("ACTOR SYS PRIORITY    : %d",
                        port->actor.sys_priority);
    LACPA_LOG_PORTSTATS("ACTOR SYS MAC         : %{mac}", 
                        port->actor.sys_mac.addr);
    LACPA_LOG_PORTSTATS("ACTOR PORT PRIORITY   : %d", 
                        port->actor.port_priority);
    LACPA_LOG_PORTSTATS("ACTOR PORT NUM        : %d", port->actor.port_num);
    LACPA_LOG_PORTSTATS("ACTOR KEY             : %d", port->actor.key);
    LACPA_LOG_PORTSTATS("ACTOR STATE           : %02x", port->actor.state);
    LACPA_LOG_PORTSTATS("ACTOR OF_PORT_NO      : %d", port->actor.port_no);
    LACPA_LOG_PORTSTATS("\nPARTNER PORT INFO");
    LACPA_LOG_PORTSTATS("PARTNER SYS PRIORITY  : %d",
                        port->partner.sys_priority);
    LACPA_LOG_PORTSTATS("PARTNER SYS MAC       : %{mac}",
                        port->partner.sys_mac.addr);
    LACPA_LOG_PORTSTATS("PARTNER PORT PRIORITY : %d", 
                        port->partner.port_priority);
    LACPA_LOG_PORTSTATS("PARTNER PORT NUM      : %d", port->partner.port_num);
    LACPA_LOG_PORTSTATS("PARTNER KEY           : %d", port->partner.key);
    LACPA_LOG_PORTSTATS("PARTNER STATE         : %02x", port->partner.state);
    LACPA_LOG_PORTSTATS("PARTNER OF_PORT_NO    : %d", port->partner.port_no);
    LACPA_LOG_PORTSTATS("\nPROTOCOL STATE INFO");
    LACPA_LOG_PORTSTATS("LACP ENABLED          : %s", 
                        port->lacp_enabled? "YES":"NO");
    LACPA_LOG_PORTSTATS("PROTOCOL CONVERGED    : %s", 
                        port->is_converged? "YES":"NO");
    LACPA_LOG_PORTSTATS("LACP STATE            : %{lacpa_machine}", 
                        port->lacp_state);
    LACPA_LOG_PORTSTATS("LACP EVENT            : %{lacpa_event}", 
                        port->lacp_event);
    LACPA_LOG_PORTSTATS("LACP ERROR            : %{lacpa_error}", port->error);
    LACPA_LOG_PORTSTATS("LACP TANSMIT REASON   : %{lacpa_transmit}",
                        port->ntt_reason);
    LACPA_LOG_PORTSTATS("*************END DUMPING INFO**************\n");
    lacpa_dump_state(port);
}

/*
 * lacpa_clear_actor_state
 *
 * Clear lacp state flags: synchronization, collecting, distributing
 *
 * These flag states ensure that the protocol is restarted
 */
static void
lacpa_clear_actor_state (lacpa_port_t *port)
{
    if (!port) return;

    AIM_LOG_TRACE("Clearing actor state flags for port: %d", 
                  port->actor.port_no);
    LACPA_CLR_STATE_SYNCHRONIZATION(port->actor.state);
    LACPA_CLR_STATE_COLLECTING(port->actor.state);
    LACPA_CLR_STATE_DISTRIBUTING(port->actor.state);
}

/*
 * lacpa_update_partner
 *
 * Match/Update the partner info and set appropraite actor state flags
 */
static void
lacpa_update_partner (lacpa_port_t *port, lacpa_pdu_t *pdu)
{
    lacpa_state_t prev_state;

    if (!port || !pdu) return;

    if (!same_partner(&pdu->actor, &port->partner)) {
        AIM_LOG_TRACE("Mis-match in Partner info for port: %d, Updating Partner"
                      " Info", port->actor.port_no);

        if (port->is_converged) {
            AIM_LOG_TRACE("Mis-match in Partner info for port: %d, Inform "
                          "Controller", port->actor.port_no);
            port->is_converged = false;
            lacpa_update_controller(port);
        }

        LACPA_CLR_STATE_SYNCHRONIZATION(port->actor.state);
        LACPA_CLR_STATE_COLLECTING(port->actor.state);
        LACPA_CLR_STATE_DISTRIBUTING(port->actor.state);
    }

    prev_state = port->partner.state;
    lacpa_copy_info(&pdu->actor, &port->partner);

    /*
     * Reset the Periodic timer if Partner's LACP Timeout value changes
     */
    if (LACPA_IS_STATE_LACP_TIMEOUT(prev_state) !=
        LACPA_IS_STATE_LACP_TIMEOUT(port->partner.state)) {
        lacpa_periodic_machine(port, true);
    }
}

/*
 * lacpa_update_ntt
 *
 * Run the logic to decide if we need to Tx a new LACPDU
 * Following the ntt parameters:
 * 1. Mismatch in Actor-Partner port parameters
 * 2. Mismatch in Actor-Partner lacp state flags
 *    lacp_activity, aggregation, lacp_activity, synchronization, 
 *    collection, distributing
 *
 * Incase of a mismatch, clear actor lacp state flags 
 */
static void
lacpa_update_ntt (lacpa_port_t *port, lacpa_pdu_t *pdu, bool *ntt)
{
    if (!port || !pdu || !ntt) return;

    if (!same_partner(&pdu->partner, &port->actor)) {
        port->ntt_reason = LACPA_TRANSMIT_INFO_MISMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_LACP_ACTIVITY(pdu->partner.state) !=
        LACPA_IS_STATE_LACP_ACTIVITY(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_LCAP_ACTIVITY_MISMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_AGGREGATION(pdu->partner.state) !=
        LACPA_IS_STATE_AGGREGATION(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_AGGREGATION_MISMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_SYNCHRONIZATION(pdu->partner.state) !=
        LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_SYNCHRONIZATION_MISMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_COLLECTING(pdu->partner.state) !=
        LACPA_IS_STATE_COLLECTING(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_COLLECTING_MISMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_DISTRIBUTING(pdu->partner.state) !=
        LACPA_IS_STATE_DISTRIBUTING(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_DISTRIBUTING_MISMATCH;
        goto transmit;
    }

    *ntt = false;
    return;

transmit:
    AIM_LOG_TRACE("Setting ntt for Port: %d, reason: %{lacpa_transmit}",
                  port->actor.port_no, port->ntt_reason);
    lacpa_clear_actor_state(port); 
    *ntt = true;
}

/*
 * lacpa_update_convergence
 *
 * Decide Protocol Converged/Unconverged based on following:
 * 1. If Partner aggregation state = false; Unconverged
 * 2. If Partner sync state = false; Unconverged
 * 3. If Partner collecting state = false; Unconverged
 * 4. If Partner distributing state = false; Unconverged
 * Else, Converged
 */
static void
lacpa_update_convergence (lacpa_port_t *port, bool *ntt)
{
    lacpa_error_t prev_error = port->error;

    if (!port || !ntt) return;

    if (!LACPA_IS_STATE_AGGREGATION(port->partner.state)) {
        if (prev_error != LACPA_ERROR_PARTNER_AGGREGATION_OFF) {
            AIM_LOG_TRACE("Setting unconverged, Mismatch in aggregation state "
                          "for port: %d", port->actor.port_no);
            port->error = LACPA_ERROR_PARTNER_AGGREGATION_OFF;
            port->lacp_event = LACPA_EVENT_PROTOCOL_UNCONVERGED;
            lacpa_machine(port, NULL);
        } else {
            AIM_LOG_TRACE("Protocol already unconverged for port: %d", 
                          port->actor.port_no);
        }
        return;
    }

    if (*ntt) {
        AIM_LOG_TRACE("Partner port has stale info, cannot procced with "
                      "convergence for port: %d", port->actor.port_no);
        return;
    }

    if (!LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)) {
        AIM_LOG_TRACE("Setting Actor sync state for Port: %d",
                      port->actor.port_no);
        LACPA_SET_STATE_SYNCHRONIZATION(port->actor.state);
        port->ntt_reason = LACPA_TRANSMIT_SYNCHRONIZATION_SET;
        *ntt = true;
    }

    if (!LACPA_IS_STATE_SYNCHRONIZATION(port->partner.state)) {
        port->error = LACPA_ERROR_PARTNER_INSYNC;
        goto unconverged;
    }

    if (!LACPA_IS_STATE_COLLECTING(port->actor.state)) {
        AIM_LOG_TRACE("Setting Actor collection state for Port: %d",
                      port->actor.port_no);
        LACPA_SET_STATE_COLLECTING(port->actor.state);
        port->ntt_reason = LACPA_TRANSMIT_COLLECTING_SET;
        *ntt = true;
    }

    if (!LACPA_IS_STATE_COLLECTING(port->partner.state)) {
        port->error = LACPA_ERROR_PARTNER_COLLECTION_OFF;
        goto unconverged;
    }

    if (!LACPA_IS_STATE_DISTRIBUTING(port->actor.state)) {
        AIM_LOG_TRACE("Setting Actor distribution state Port: %d",
                      port->actor.port_no);
        LACPA_SET_STATE_DISTRIBUTING(port->actor.state);
        port->ntt_reason = LACPA_TRANSMIT_DISTRIBUTING_SET;
        *ntt = true;
    }

    if (!LACPA_IS_STATE_DISTRIBUTING(port->partner.state)) {
        port->error = LACPA_ERROR_PARTNER_DISTRIBUTION_OFF;
        goto unconverged;
    }

    port->error = LACPA_ERROR_NONE;
    if (!port->is_converged) {
        AIM_LOG_TRACE("Setting Port: %d to Converged, ntt_reason: "
                      "%{lacpa_transmit}", port->actor.port_no, 
                      port->ntt_reason);
        port->is_converged = true;
        lacpa_update_controller(port);    
    }

    LACPA_CLR_STATE_LACP_TIMEOUT(port->actor.state);
    return;

unconverged:
    AIM_LOG_TRACE("Setting Port: %d to Unconverged, reason: %{lacpa_error}, "
                  "ntt_reason: %{lacpa_transmit}", port->actor.port_no,
                  port->error, port->ntt_reason);
    port->is_converged = false;
}

/*
 * lacpa_process_pdu
 *
 * Do the following with the incoming PDU:
 * 1. Compare Actor Info in the PDU with our Partner Info
 * 2. Compare Partner Info in the PDU with our Actor Info
 * 3. Decide if we need to Tx a new LACPDU
 * 4. Decide Protocol Converged/Unconverged
 */
static void
lacpa_process_pdu (lacpa_port_t *port, lacpa_pdu_t *pdu)
{
    bool ntt = false;

    if (!port || !pdu) return;

    lacpa_update_partner(port, pdu);

    lacpa_update_ntt(port, pdu, &ntt);

    lacpa_update_convergence(port, &ntt);

    /*
     * Identify if there is a need to transmit a new LACPDU
     */
    if (ntt) lacpa_transmit(port);
}

/*
 * lacp_init_port
 *
 * LACP Agent is being enabled/disabled.
 *
 * Start/Stop the necessay timers and enable/disable agent states.
 */
void
lacpa_init_port (lacpa_system_t *system, lacpa_info_t *info,
                 bool lacp_enabled)
{
    lacpa_port_t *port = NULL;

    if (!info || !system)  return;

    /*
     * Find any port corresponding to the info received
     */
    port = lacpa_find_port(system, info->port_no);
    if (!port) return;

    AIM_LOG_TRACE("LACP %s received for port: %d", lacp_enabled?
                  "ENABLE": "DISABLE", info->port_no);

    /*
     * Handle the case in which you get a port init msg with same params
     * and lacp has already converged on that port
     *
     * Send a Converged notification to the Controller in such a case, else
     * do not restart the protocol
     */
    if (lacp_enabled && same_partner(info, &port->actor)){
        if (port->is_converged) {
            AIM_LOG_TRACE("Init Port: %d already Converged, Inform Controller", 
                          info->port_no);
            lacpa_update_controller(port);
        }
        return;
    }
    
    lacpa_copy_info(info, &port->actor);
    lacpa_dump_port(port);

    if (lacp_enabled) {
        port->lacp_event = LACPA_EVENT_ENABLED;
    } else {
        port->lacp_event = LACPA_EVENT_DISABLED;
    }

    port->system = system;
    LACPA_MEMCPY(port->src_mac.addr, port_src_mac_address, OF_MAC_ADDR_BYTES); 

    lacpa_machine(port, NULL);
}

/*
 * lacpa_transmit
 *
 * Construct an LACPDU for the given port and transmit it out
 */
void
lacpa_transmit (lacpa_port_t *port)
{
    ppe_packet_t ppep;
    uint8_t      data[LACP_PKT_BUF_SIZE];
    of_octets_t  octets;

    if (!port) return;

    if (!port->lacp_enabled) {
        AIM_LOG_ERROR("LACPDU-Tx-FAILED - Agent is Disabled on port: %d",
                      port->actor.port_no);
        return;
    }

    LACPA_MEMSET(data, 0, LACP_PKT_BUF_SIZE);
    AIM_LOG_TRACE("Transmit Packet for port: %d, reason: %{lacpa_transmit}",
                  port->actor.port_no, port->ntt_reason);

    lacpa_dump_port(port);

    ppe_packet_init(&ppep, data, LACP_PKT_BUF_SIZE);

    /*
     * Set ethertype as slow-protocols and Set LACP subtype
     * Parse to recognize LACP packet.
     */
    data[12] = PPE_ETHERTYPE_SLOW_PROTOCOLS >> 8;
    data[13] = PPE_ETHERTYPE_SLOW_PROTOCOLS & 0xFF;
    data[14] = PPE_SLOW_PROTOCOL_LACP;

    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_ERROR("Packet_out parsing failed. packet=%{data}",
                      data, LACP_PKT_BUF_SIZE);
        return;
    }

    /*
     * Set the Src and Dest Mac.
     * Src Mac is provided to us and Dest Mac is the slow-protocols-mac-address
     */
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, port->src_mac.addr);
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_DST_MAC,
                       slow_protocols_address);

    /*
     * Build the rest of the LCAP packet
     */
    if (!lacpa_build_pdu(&ppep, port)) {
        AIM_LOG_ERROR("Packet sending failed for port: %d", 
                      port->actor.port_no);
        return;
    }

    /*
     *  Dump out the packet to verify all the fields are set properly
     */
    if (AIM_LOG_CUSTOM_ENABLED(LACPA_LOG_FLAG_PORTSTATS)) {
        ppe_packet_dump(&ppep, aim_log_pvs_get(&AIM_LOG_STRUCT));
    }

    /*
     * Send the packet out the port
     */
    octets.data = data;
    octets.bytes = LACP_PKT_BUF_SIZE;
    lacpa_send_packet_out(port, &octets);

    return;

}

/*
 * lacpa_defaulted
 *
 * Agent_Defaulted State handling
 */
static void
lacpa_defaulted (lacpa_port_t *port)
{
    if (!port) return;

    churn_detection_running = false;
    lacpa_churn_detection_machine(port, false);
    lacpa_current_while_timer(port, false);

    lacpa_clear_actor_state(port);

    AIM_LOG_TRACE("Actor State Defaulted for Port: %d,  Inform Controller",
                  port->actor.port_no);
    port->is_converged = false;
    lacpa_update_controller(port);
    lacpa_transmit(port);
}

/*
 * lacpa_machine
 *
 * LACP Agent State Machine
 *
 * Rx/Tx and Processing of LACPDU's.
 */
void
lacpa_machine (lacpa_port_t *port, lacpa_pdu_t *pdu)
{
    lacpa_error_t prev_error;

    if (!port || !port->system) return;

    lacpa_machine_t prev_state = port->lacp_state;

    switch (port->lacp_event) {
    case LACPA_EVENT_DISABLED:
        port->lacp_state = LACPA_MACHINE_AGENT_STOPPED;
        port->lacp_enabled = false;
        lacpa_periodic_machine(port, false);
        lacpa_churn_detection_machine(port, false);
        lacpa_current_while_timer(port, false);
        port->system->lacp_active_port_count--;
        LACPA_MEMSET(port, 0, sizeof(lacpa_port_t)); 
        break;

    case LACPA_EVENT_ENABLED:
        port->lacp_state = LACPA_MACHINE_AGENT_CURRENT;
        port->lacp_enabled = true;

        /*
         * Set Actor's LACP_ACTIVITY, LACP_TIMEOUT and AGGREGATION
         * to default values
         */
        LACPA_SET_STATE_LACP_ACTIVITY(port->actor.state);
        LACPA_SET_STATE_LACP_TIMEOUT(port->actor.state);
        LACPA_SET_STATE_AGGREGATION(port->actor.state);

        port->ntt_reason = LACPA_TRANSMIT_AGENT_ENABLED;
        lacpa_transmit(port);
        lacpa_periodic_machine(port, true);
        //lacpa_churn_detection_machine(port, true);
        lacpa_current_while_timer(port, true);
        port->system->lacp_active_port_count++;
        break;

    case LACPA_EVENT_PDU_RECEIVED:
        port->lacp_state = LACPA_MACHINE_AGENT_CURRENT;
        LACPA_SET_STATE_LACP_TIMEOUT(port->actor.state);
        LACPA_CLR_STATE_EXPIRED(port->actor.state);
        LACPA_CLR_STATE_DEFAULTED(port->actor.state);
        prev_error = port->error;

        /*
         * Process the received Partner LACPDU
         */
        lacpa_process_pdu(port, pdu);

        /*
         * Start the churn detection timer if:
         * Unconverged; because of the same reason and Churn Detection 
         * is not running
         *
         * Stop the churn detection timer if:
         * 1. Converged
         * 2. Unconverged; but because of a different reason
         */    
        if (!port->is_converged && (prev_error == port->error) && 
            !churn_detection_running) {
            AIM_LOG_TRACE("Starting Churn Detection timer for port: %d, "
                          "is_converged: %d, prev_error: %{lacpa_error}, "
                          "new_error: %{lacpa_error}", port->actor.port_no,
                          port->is_converged, prev_error, port->error);
            lacpa_churn_detection_machine(port, true);
            churn_detection_running = true;
        } else if (port->is_converged || (prev_error != port->error)) {
            AIM_LOG_TRACE("Stopping Churn Detection timer for port: %d, "
                          "is_converged: %d, prev_error: %{lacpa_error}, "
                          "new_error: %{lacpa_error}", port->actor.port_no,
                          port->is_converged, prev_error, port->error);
            lacpa_churn_detection_machine(port, false);
            churn_detection_running = false;
        }

        /*
         * Restart the churn detection timer if:
         * 1. Converged
         * 2. Unconverged; but because of a different reason
         *
        if (port->is_converged || (prev_error != port->error)) {
            AIM_LOG_TRACE("Restarting Churn Detection timer for port: %d, "
                          "is_converged: %d, prev_error: %{lacpa_error}, "
                          "new_error: %{lacpa_error}", port->actor.port_no,
                          port->is_converged, prev_error, port->error);
            lacpa_churn_detection_machine(port, true);
        } else if (prev_state == LACPA_MACHINE_AGENT_DEFAULTED) {
            AIM_LOG_TRACE("Prev State was AGENT_DEFAULTED due to same error: "
                          "%{lacpa_error}, Staying in Defaulted State for port:"
                          "  %d", port->error, port->actor.port_no);
            port->lacp_state = LACPA_MACHINE_AGENT_DEFAULTED;
            lacpa_clear_actor_state(port);
        }*/

        lacpa_current_while_timer(port, true);
        break;

    case LACPA_EVENT_CURRENT_TIMER_EXPIRED:
        port->lacp_state = LACPA_MACHINE_AGENT_EXPIRED;
        LACPA_SET_STATE_EXPIRED(port->actor.state);
    
        /*
         * Set the Actor/Partner LACP Timeout to Short so that we can do
         * FAST Transmits of LACPDU's
         */
        LACPA_SET_STATE_LACP_TIMEOUT(port->actor.state);
        if (!LACPA_IS_STATE_LACP_TIMEOUT(port->partner.state)) {
            LACPA_SET_STATE_LACP_TIMEOUT(port->partner.state);
            lacpa_periodic_machine(port, true);
        }

        port->ntt_reason = LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED;
        lacpa_transmit(port);
        lacpa_current_while_timer(port, true);
        break;

    case LACPA_EVENT_EXPIRY_TIMER_EXPIRED:
    case LACPA_EVENT_CHURN_DETECTION_EXPIRED:
    case LACPA_EVENT_PROTOCOL_UNCONVERGED:
        port->lacp_state = LACPA_MACHINE_AGENT_DEFAULTED;
        LACPA_SET_STATE_DEFAULTED(port->actor.state);
        LACPA_CLR_STATE_LACP_TIMEOUT(port->actor.state);
        lacpa_defaulted(port);
        break;

    default:
        break;
    }

    AIM_LOG_TRACE("State change for Port: %d, Event: %{lacpa_event}, Prev: "
                  "%{lacpa_machine}, New: %{lacpa_machine}",
                  port->actor.port_no, port->lacp_event, prev_state,
                  port->lacp_state);
}
