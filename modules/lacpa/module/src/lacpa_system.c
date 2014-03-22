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
 * Implementation of Lacp Agent System.
 *
 * This file contains the system wide calls for initializing/deinitializing
 * lacp system for the agent.
 */

#include "lacpa_int.h"
#include "lacpa_utils.h"

lacpa_system_t lacpa_system;
bool lacp_system_initialized = false;
aim_ratelimiter_t lacpa_pktin_log_limiter;

/*
 * lacpa_is_initialized
 *
 * true = System Initialized
 * false = System Uninitialized
 */
bool
lacpa_is_initialized (void)
{
    return lacp_system_initialized;
}

/*
 * lacpa_init
 *
 * API to init the LACP System
 * This should only be done once at the beginning.
 */
indigo_error_t
lacpa_init (void)
{
    uint32_t ports_size = 0;

    if (lacpa_is_initialized()) return INDIGO_ERROR_NONE;

    AIM_LOG_INFO("init");

    ports_size = sizeof(lacpa_port_t) * (PHY_PORT_COUNT+1);
    lacpa_system.lacp_active_port_count = 0;
    aim_ratelimiter_init(&lacpa_pktin_log_limiter, 1000*1000, 5, NULL);
    lacpa_register_system_counters();

    lacpa_system.ports = (lacpa_port_t *) LACPA_MALLOC(ports_size);
    if (lacpa_system.ports == NULL) {
        AIM_LOG_ERROR("Failed to allocate resources for ports..");
        return INDIGO_ERROR_RESOURCE;
    }

    AIM_LOG_TRACE("Succesfully inited LACP System for %d ports...",
                  PHY_PORT_COUNT);
    LACPA_MEMSET(lacpa_system.ports, 0, ports_size);
    lacp_system_initialized = true;

    /*
     * Register listerners for port packet_in and Controller msg's
     */
    if (indigo_core_packet_in_listener_register((indigo_core_packet_in_listener_f)
                                                lacpa_packet_in_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for port packet_in in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    if (indigo_core_message_listener_register((indigo_core_message_listener_f)
                                              lacpa_controller_msg_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for Controller msg in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_finish
 *
 * API to deinit the LACP System
 */
void
lacpa_finish (void)
{
    indigo_core_packet_in_listener_unregister(lacpa_packet_in_handler);
    indigo_core_message_listener_unregister(lacpa_controller_msg_handler);

    lacpa_system.lacp_active_port_count = 0;
    lacpa_unregister_system_counters();

    LACPA_FREE(lacpa_system.ports);
    lacp_system_initialized = false;
}

/*
 * lacpa_find_port
 *
 * Returns port pointer in the system for valid port_no else
 * returns NULL
 */
lacpa_port_t *
lacpa_find_port (uint32_t port_no)
{
    if (port_no > PHY_PORT_COUNT) {
        AIM_LOG_ERROR("Port No: %d Out of Range %d", port_no, PHY_PORT_COUNT);
        return NULL;
    }

    return (&lacpa_system.ports[port_no]);
}
