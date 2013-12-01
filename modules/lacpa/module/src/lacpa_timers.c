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
 * Implementation of Lacp Agent Related Timers.
 *
 * This file contains only the timer API interfaces.
 */

#include "lacpa_int.h"
#include <SocketManager/socketmanager.h>

/*
 * lacpa_current_while_expiration_timer_cb
 *
 * Current while Expiration callback
 */
static void
lacpa_current_while_expiration_timer_cb (void *cookie)
{
    if (!cookie) return;

    lacpa_port_t *port = (lacpa_port_t *)cookie;

    AIM_LOG_TRACE("current_while timer callback for port: %d",
                  port->actor.port_no);

    port = lacpa_find_port(port->system, port->actor.port_no);
    if (!port) return;

    if (port->lacp_state == LACPA_MACHINE_AGENT_CURRENT) {
        port->lacp_event = LACPA_EVENT_CURRENT_TIMER_EXPIRED;
    } else if (port->lacp_state == LACPA_MACHINE_AGENT_EXPIRED) {
        port->lacp_event = LACPA_EVENT_EXPIRY_TIMER_EXPIRED;
    } else {

        /*
         * Sanity check, disable the timer
         */
        lacpa_current_while_timer(port, false);
        return;
    }

    lacpa_machine(port, NULL);
}

/*
 * lacpa_current_while_timer
 */
void
lacpa_current_while_timer (lacpa_port_t *port, bool timer_enabled)
{
    if (!port) return;

    AIM_LOG_TRACE("%s current_while timer for port: %d",
                  timer_enabled? "START": "STOP", port->actor.port_no);

    if (timer_enabled && port->lacp_state == LACPA_MACHINE_AGENT_DEFAULTED) {
        AIM_LOG_TRACE("Failed to Start current_while timer since Agent State: "
                      "%{lacpa_machine}", port->lacp_state);
        return;
    }

    if (timer_enabled) {
        ind_soc_timer_event_register(lacpa_current_while_expiration_timer_cb,
                                     port, LACPA_IS_STATE_LACP_TIMEOUT(
                                     port->actor.state)? LACP_SHORT_TIMEOUT_MS:
                                     LACP_LONG_TIMEOUT_MS);
    } else {
        ind_soc_timer_event_unregister(lacpa_current_while_expiration_timer_cb, 
                                       port);
    }
}

/*
 * lacpa_churn_expiration_timer_cb
 *
 * Churn Detection Timer Expiration callback
 */
static void
lacpa_churn_expiration_timer_cb (void *cookie)
{
    if (!cookie) return;

    lacpa_port_t *port = (lacpa_port_t *)cookie;

    AIM_LOG_TRACE("Churn Detection timer callback for port: %d",
                  port->actor.port_no);

    port = lacpa_find_port(port->system, port->actor.port_no);
    if (!port) return;

    port->lacp_event = LACPA_EVENT_CHURN_DETECTION_EXPIRED;
    lacpa_machine(port, NULL);
}

/*
 * lacpa_churn_detection_machine
 *
 * Churn Detection Timer
 */
void
lacpa_churn_detection_machine (lacpa_port_t *port, bool timer_enabled)
{
    if (!port) return;

    AIM_LOG_TRACE("%s Churn Detection timer for port: %d",
                  timer_enabled? "START": "STOP", port->actor.port_no);

    if (timer_enabled && port->lacp_state == LACPA_MACHINE_AGENT_DEFAULTED) {
        AIM_LOG_TRACE("Failed to Start Churn Detection timer since Agent State:"
                      " %{lacpa_machine}", port->lacp_state);
        return; 
    }
 
    if (timer_enabled) {
        ind_soc_timer_event_register(lacpa_churn_expiration_timer_cb, port,
                                     LACP_CHURN_DETECTION_TIMEOUT_MS);
    } else {
        ind_soc_timer_event_unregister(lacpa_churn_expiration_timer_cb, port);
    }
}

/*
 * lacpa_periodic_expiration_timer_cb
 *
 * Periodic Timer Expiration callback
 */
static void
lacpa_periodic_expiration_timer_cb (void *cookie)
{
    if (!cookie) return;

    lacpa_port_t *port = (lacpa_port_t *)cookie;

    AIM_LOG_TRACE("Periodic timer callback for port: %d",
                  port->actor.port_no);
    
    port = lacpa_find_port(port->system, port->actor.port_no);
    if (!port) return;

    if (port->lacp_state != LACPA_MACHINE_AGENT_STOPPED) {
        port->ntt_reason = LACPA_TRANSMIT_PERIODIC_TIMER_EXPIRED;
        lacpa_transmit(port);
    } else {
        lacpa_periodic_machine(port, false);
    }
}

/*
 * lacpa_periodic_machine
 *
 * Periodic Timer
 */
void
lacpa_periodic_machine (lacpa_port_t * port, bool timer_enabled)
{
    if (!port) return;

    AIM_LOG_TRACE("%s Periodic timer for port: %d", timer_enabled?
                  "START": "STOP", port->actor.port_no);

    if (timer_enabled) {
        ind_soc_timer_event_register(lacpa_periodic_expiration_timer_cb, port,
                                     LACPA_IS_STATE_LACP_TIMEOUT(
                                     port->partner.state)?
                                     LACP_FAST_PERIODIC_TIMEOUT_MS :
                                     LACP_SLOW_PERIODIC_TIMEOUT_MS);
    } else {
        ind_soc_timer_event_unregister(lacpa_periodic_expiration_timer_cb, port);
    }
}

