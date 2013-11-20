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

/*
 * Slow-Protocols Dest Mac
 */
lacpa_mac_t
slow_protocols_address = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02};

/*
 * lacpa_dump_state
 *
 * Dumps the actor/partner state flags
 */
extern void
lacpa_dump_state (lacpa_port_t *port)
{
	if (!port) return;

    AIM_LOG_TRACE("*************DUMPING STATE INFO*************\n");
    AIM_LOG_TRACE("\nACTOR STATE FLAGS");
    AIM_LOG_TRACE("ACTOR LACP ACTIVITY     : %s", LACPA_IS_STATE_LACP_ACTIVITY(
                  port->actor.state)? "ACTIVE" : "PASSIVE");
    AIM_LOG_TRACE("ACTOR LACP TIMEOUT      : %s", LACPA_IS_STATE_LACP_TIMEOUT(
                  port->actor.state)? "SHORT" : "LONG");
    AIM_LOG_TRACE("ACTOR AGGREGATION       : %s", LACPA_IS_STATE_AGGREGATION(
                  port->actor.state)? "YES" : "NO");
    AIM_LOG_TRACE("ACTOR SYNCHRONIZATION   : %s",LACPA_IS_STATE_SYNCHRONIZATION(
                  port->actor.state)? "INSYNC" : "OUTofSYNC");
    AIM_LOG_TRACE("ACTOR COLLECTING        : %s", LACPA_IS_STATE_COLLECTING(
                  port->actor.state)? "YES" : "NO");
    AIM_LOG_TRACE("ACTOR DISTRIBUTING      : %s", LACPA_IS_STATE_DISTRIBUTING(
                  port->actor.state)? "YES" : "NO");
    AIM_LOG_TRACE("\nPARTNER STATE FLAGS");
    AIM_LOG_TRACE("PARTNER LACP ACTIVITY   : %s", LACPA_IS_STATE_LACP_ACTIVITY(
                  port->partner.state)? "ACTIVE" : "PASSIVE");
    AIM_LOG_TRACE("PARTNER LACP TIMEOUT    : %s", LACPA_IS_STATE_LACP_TIMEOUT(
                  port->partner.state)? "SHORT" : "LONG");
    AIM_LOG_TRACE("PARTNER AGGREGATION     : %s", LACPA_IS_STATE_AGGREGATION(
                  port->partner.state)? "YES" : "NO");
    AIM_LOG_TRACE("PARTNER SYNCHRONIZATION : %s",LACPA_IS_STATE_SYNCHRONIZATION(
                  port->partner.state)? "INSYNC" : "OUTofSYNC");
    AIM_LOG_TRACE("PARTNER COLLECTING      : %s", LACPA_IS_STATE_COLLECTING(
                  port->partner.state)? "YES" : "NO");
    AIM_LOG_TRACE("PARTNER DISTRIBUTING    : %s", LACPA_IS_STATE_DISTRIBUTING(
                  port->partner.state)? "YES" : "NO");
    AIM_LOG_TRACE("*************END DUMPING INFO**************\n");
}

/*
 * lacpa_dump_port
 *
 * Dumps the current port information
 */
extern void
lacpa_dump_port (lacpa_port_t *port)
{
	if (!port) return;

	AIM_LOG_TRACE("*************DUMPING PORT INFO*************\n");
	AIM_LOG_TRACE("\nACTOR PORT INFO");
    AIM_LOG_TRACE("ACTOR SYS PRIORITY    : %d", port->actor.sys_priority);
    AIM_LOG_TRACE("ACTOR SYS MAC         : %{mac}", port->actor.sys_mac);
    AIM_LOG_TRACE("ACTOR PORT PRIORITY   : %d", port->actor.port_priority);
    AIM_LOG_TRACE("ACTOR PORT NUM        : %d", port->actor.port_num);
    AIM_LOG_TRACE("ACTOR KEY             : %d", port->actor.key);
    AIM_LOG_TRACE("ACTOR STATE           : %02x", port->actor.state);
    AIM_LOG_TRACE("ACTOR OF_PORT_NO      : %d", port->actor.port_no);
	AIM_LOG_TRACE("\nPARTNER PORT INFO");
    AIM_LOG_TRACE("PARTNER SYS PRIORITY  : %d", port->partner.sys_priority);
    AIM_LOG_TRACE("PARTNER SYS MAC       : %{mac}", port->partner.sys_mac);
    AIM_LOG_TRACE("PARTNER PORT PRIORITY : %d", port->partner.port_priority);
    AIM_LOG_TRACE("PARTNER PORT NUM      : %d", port->partner.port_num);
    AIM_LOG_TRACE("PARTNER KEY           : %d", port->partner.key);
    AIM_LOG_TRACE("PARTNER STATE         : %02x", port->partner.state);
    AIM_LOG_TRACE("PARTNER OF_PORT_NO    : %d", port->partner.port_no);
    AIM_LOG_TRACE("\nPROTOCOL STATE INFO");
    AIM_LOG_TRACE("LACP ENABLED          : %s", port->lacp_enabled? "YES":"NO");
    AIM_LOG_TRACE("PROTOCOL CONVERGED    : %s", port->is_converged? "YES":"NO");
    AIM_LOG_TRACE("LACP STATE            : %{lacpa_machine}", port->lacp_state);
    AIM_LOG_TRACE("LACP EVENT            : %{lacpa_event}", port->lacp_event);
    AIM_LOG_TRACE("LACP ERROR            : %{lacpa_error}", port->error);
    AIM_LOG_TRACE("LACP TANSMIT REASON   : %{lacpa_transmit}",port->ntt_reason);
	AIM_LOG_TRACE("*************END DUMPING INFO**************\n");
}

/*
 * lacpa_update_controller
 *
 * This API communicates Protocol Converged/Unconverged to the Controller
 */
extern void
lacpa_update_controller (lacpa_port_t *port)
{
    if (!port) return;

    AIM_LOG_TRACE("Send %s msg to Controller for port: %d", port->is_converged?
                  "Converged" : "Unconverged", port->actor.port_no);


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
            AIM_LOG_ERROR("Mis-match in Partner info for port: %d, Inform "
                          "Controller", port->actor.port_no);
        	port->is_converged = FALSE;
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
        lacpa_periodic_machine(port, TRUE);
    }
}

/*
 * lacpa_update_ntt
 *
 * Run the logic to decide if we need to Tx a new LACPDU
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
        port->ntt_reason = LACPA_TRANSMIT_LCAP_ACTIVITY_MISTMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_AGGREGATION(pdu->partner.state) !=
        LACPA_IS_STATE_AGGREGATION(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_AGGREGATION_MISTMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_SYNCHRONIZATION(pdu->partner.state) !=
        LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_SYNCHRONIZATION_MISTMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_COLLECTING(pdu->partner.state) !=
		LACPA_IS_STATE_COLLECTING(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_COLLECTING_MISTMATCH;
        goto transmit;
    }

    if (LACPA_IS_STATE_DISTRIBUTING(pdu->partner.state) !=
		LACPA_IS_STATE_DISTRIBUTING(port->actor.state)) {
        port->ntt_reason = LACPA_TRANSMIT_DISTRIBUTING_MISTMATCH;
        goto transmit;
    }

    *ntt = FALSE;
    return;

transmit:
    AIM_LOG_TRACE("Setting ntt for Port: %d, reason: %{lacpa_transmit}",
                  port->actor.port_no, port->ntt_reason);
	*ntt = TRUE;
}

/*
 * lacpa_update_convergence
 *
 * Decide Protocol Converged/Unconverged based on following:
 * 1. If Partner aggregation state = FALSE; Unconverged
 * 2. If Partner sync state = FALSE; Unconverged
 * 3. If Partner collecting state = FALSE; Unconverged
 * 4. If Partner distributing state = FALSE; Unconverged
 * Else, Converged
 */
static void
lacpa_update_convergence (lacpa_port_t *port, bool *ntt)
{
    lacpa_error_t prev_error = port->error;

	if (!port || !ntt) return;

    if (!LACPA_IS_STATE_AGGREGATION(port->partner.state)) {
        if (prev_error != LACPA_ERROR_PARTNER_AGGREGATION_OFF) {
        	AIM_LOG_ERROR("Setting unconverged, Mis-match in aggregation state");
        	port->error = LACPA_ERROR_PARTNER_AGGREGATION_OFF;
        	port->lacp_event = LACPA_EVENT_PROTOCOL_UNCONVERGED;
        	lacpa_machine(port, NULL);
        } else {
			AIM_LOG_ERROR("Protocol Already Unconverged..No action required");
        }
        return;
    }

    if (!LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)) {
        AIM_LOG_TRACE("Setting Actor sync state for Port: %d",
                      port->actor.port_no);
        LACPA_SET_STATE_SYNCHRONIZATION(port->actor.state);
        port->ntt_reason = LACPA_TRANSMIT_SYNCHRONIZATION_SET;
        *ntt = TRUE;
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
        *ntt = TRUE;
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
        *ntt = TRUE;
    }

    if (!LACPA_IS_STATE_DISTRIBUTING(port->partner.state)) {
        port->error = LACPA_ERROR_PARTNER_DISTRIBUTION_OFF;
        goto unconverged;
    }

    AIM_LOG_TRACE("Setting Port: %d to Converged, ntt_reason: %{lacpa_transmit}",
                  port->actor.port_no, port->ntt_reason);
    port->error = LACPA_ERROR_NONE;
    port->is_converged = TRUE;
    return;

unconverged:
    AIM_LOG_TRACE("Setting Port: %d to Unconverged, reason: %{lacpa_error}, "
                  "ntt_reason: %{lacpa_transmit}", port->actor.port_no,
                  port->error, port->ntt_reason);
	port->is_converged = FALSE;
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
	bool ntt = FALSE;

	if (!port || !pdu) return;

	lacpa_update_partner(port, pdu);

    lacpa_update_ntt(port, pdu, &ntt);

    lacpa_update_convergence(port, &ntt);

    /*
     * Identify if there is a need to inform the controller
     */
    if (port->is_converged) lacpa_update_controller(port);

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
extern void
lacpa_init_port (lacpa_system_t *system, lacpa_info_t *info,
                 uint8_t lacp_enabled)
{
    lacpa_port_t *port = NULL;

    if (!info || !system)  return;

    /*
     * Find any port corresponding to the info received
     */
    port = lacpa_find_port(system, info->port_no);
    if (!port) return;

    AIM_LOG_TRACE("LACP %s received for port: %d", lacp_enabled?
                  "ENABLE": "DISABLE", port->actor.port_no);

    lacpa_copy_info(info, &port->actor);
    lacpa_dump_port(port);

    if (lacp_enabled) {
        port->lacp_event = LACPA_EVENT_ENABLED;
    } else {
        port->lacp_event = LACPA_EVENT_DISABLED;
    }

    port->system = system;
    lacpa_machine(port, NULL);
}

/*
 * lacpa_transmit
 *
 * Construct an LACPDU for the given port and transmit it out
 */
extern bool
lacpa_transmit (lacpa_port_t *port)
{
    ppe_packet_t ppep;
    uint8_t      data[LACP_PKT_BUF_SIZE];

	if (!port) return FALSE;

    if (!port->lacp_enabled) {
        AIM_LOG_ERROR("LACPDU-Tx-FAILED - Agent is Disabled on port: %d",
                      port->actor.port_no);
        return FALSE;
    }

    LACPA_MEMSET(data, DEFAULT_ZERO, LACP_PKT_BUF_SIZE);
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
        AIM_LOG_ERROR("Packet parsing failed after ethertype. packet=%{data}",
                      data, LACP_PKT_BUF_SIZE);
        return FALSE;
    }

    /*
     * Set the Src and Dest Mac.
     * Src Mac is provided to us and Dest Mac is the slow-protocols-mac-address
     */
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, port->src_mac);
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_DST_MAC,
                       slow_protocols_address);

    /*
     * Build the rest of the LCAP packet
     */
    if (!lacpa_build_pdu(&ppep, port)) {
        AIM_LOG_ERROR("Packet sending failed.");
        return FALSE;
    }

    /*
     *  Dump out the packet to verify all the fields are set properly
     */
    ppe_packet_dump(&ppep, &aim_pvs_stdout);

    lacpa_send(port, data, LACP_PKT_BUF_SIZE);

    return TRUE;

}

/*
 * lacpa_receive
 *
 * Process incoming LACPDU and take appropriate action
 */
extern bool
lacpa_receive (lacpa_port_t *port, uint8_t *data, uint32_t bytes)
{
    lacpa_pdu_t  pdu;
    ppe_packet_t ppep;

	if (!port || !data) return FALSE;

    if (!port->lacp_enabled) {
        AIM_LOG_ERROR("LACPDU-Rx-FAILED - Agent is Disabled on port: %d",
                      port->actor.port_no);
		return FALSE;
    }

    LACPA_MEMSET(&pdu, DEFAULT_ZERO, sizeof(lacpa_pdu_t));
    AIM_LOG_TRACE("LACPDU Received on port: %d", port->actor.port_no);

    /*
     * Use ppe api's to fill info from data in our pdu
     */
    ppe_packet_init(&ppep, data, bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_ERROR("Packet parsing failed. packet=%{data}", data, bytes);
        return FALSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_LACP)) {
        AIM_LOG_ERROR("Not a Valid LCAP Packet");
        return FALSE;
    }

	/*
     * Retrieve the information from the LCAP packet
     */
    if (!lacpa_parse_pdu(&ppep, &pdu)) {
		AIM_LOG_ERROR("Packet parsing failed.");
        return FALSE;
    }

    port->lacp_event = LACPA_EVENT_PDU_RECEIVED;
    lacpa_machine(port, &pdu);

    return TRUE;
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

    lacpa_churn_detection_machine(port, FALSE);
	lacpa_current_while_timer(port, FALSE);

    /*
     * Set the Actor and Partner LACP_TIMEOUT to Long Timeout
     */
    LACPA_CLR_STATE_LACP_TIMEOUT(port->actor.state);
    //LACPA_CLR_STATE_LACP_TIMEOUT(port->partner.state);

    AIM_LOG_TRACE("Actor State Defaulted for Port: %d,  Inform Controller",
                  port->actor.port_no);
    port->is_converged = FALSE;
    lacpa_update_controller(port);
}

/*
 * lacpa_machine
 *
 * LACP Agent State Machine
 *
 * Rx/Tx and Processing of LACPDU's.
 */
extern void
lacpa_machine (lacpa_port_t *port, lacpa_pdu_t *pdu)
{
    lacpa_error_t prev_error;

    if (!port || !port->system) return;

    lacpa_machine_t prev_state = port->lacp_state;

    switch (port->lacp_event) {
    case LACPA_EVENT_DISABLED:
        port->lacp_state = LACPA_MACHINE_AGENT_STOPPED;
        port->lacp_enabled = FALSE;
        lacpa_periodic_machine(port, FALSE);
        lacpa_churn_detection_machine(port, FALSE);
        lacpa_current_while_timer(port, FALSE);
        port->system->lacp_active_port_count--;
        break;

    case LACPA_EVENT_ENABLED:
        port->lacp_state = LACPA_MACHINE_AGENT_CURRENT;
        port->lacp_enabled = TRUE;

        /*
         * Set Actor's LACP_ACTIVITY, LACP_TIMEOUT and AGGREGATION
         * to default values
         */
        LACPA_SET_STATE_LACP_ACTIVITY(port->actor.state);
        LACPA_CLR_STATE_LACP_TIMEOUT(port->actor.state);
        LACPA_SET_STATE_AGGREGATION(port->actor.state);

        port->ntt_reason = LACPA_TRANSMIT_AGENT_ENABLED;
        lacpa_transmit(port);
        lacpa_periodic_machine(port, TRUE);
        lacpa_churn_detection_machine(port, TRUE);
        lacpa_current_while_timer(port, TRUE);
        port->system->lacp_active_port_count++;
        break;

    case LACPA_EVENT_PDU_RECEIVED:
        port->lacp_state = LACPA_MACHINE_AGENT_CURRENT;
        LACPA_CLR_STATE_LACP_TIMEOUT(port->actor.state);
        prev_error = port->error;

        /*
         * Process the received Partner LACPDU
         */
        lacpa_process_pdu(port, pdu);

        /*
         * Restart the churn detection timer if:
         * 1. Converged
         * 2. Unconverged; but because of a different reason
         */
        if (port->is_converged || (prev_error != port->error)) {
            AIM_LOG_TRACE("Restarting Churn Detection timer for port: %d, "
                          "is_converged: %d, prev_error: %{lacpa_error}, "
                          "new_error: %{lacpa_error}", port->actor.port_no,
                          port->is_converged, prev_error, port->error);
	        lacpa_churn_detection_machine(port, TRUE);
        } else if (prev_state == LACPA_MACHINE_AGENT_DEFAULTED) {
        	AIM_LOG_TRACE("Prev State was AGENT_DEFAULTED due to same error: "
                          "%{lacpa_error}, Staying in Defaulted State for port:"
                          "  %d", port->error, port->actor.port_no);
            port->lacp_state = LACPA_MACHINE_AGENT_DEFAULTED;
        }

		lacpa_current_while_timer(port, TRUE);
        break;

    case LACPA_EVENT_CURRENT_TIMER_EXPIRED:
        port->lacp_state = LACPA_MACHINE_AGENT_EXPIRED;

        /*
         * Set the Actor/Partner LACP Timeout to Short so that we can do
         * FAST Transmits of LACPDU's
         */
        LACPA_SET_STATE_LACP_TIMEOUT(port->actor.state);
        if (!LACPA_IS_STATE_LACP_TIMEOUT(port->partner.state)) {
        	LACPA_SET_STATE_LACP_TIMEOUT(port->partner.state);
   			lacpa_periodic_machine(port, TRUE);
        }

        lacpa_transmit(port);
        lacpa_current_while_timer(port, TRUE);
        break;

    case LACPA_EVENT_EXPIRY_TIMER_EXPIRED:
    case LACPA_EVENT_CHURN_DETECTION_EXPIRED:
    case LACPA_EVENT_PROTOCOL_UNCONVERGED:
        port->lacp_state = LACPA_MACHINE_AGENT_DEFAULTED;
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
