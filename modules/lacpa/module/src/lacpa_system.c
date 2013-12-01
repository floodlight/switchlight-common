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

lacpa_system_t lacp_system;
bool lacp_system_initialized = false;

/*
 * lacp_system_initialized
 *
 * true = System Initialized
 * false = System Uninitialized
 */
bool
lacpa_is_system_initialized (void)
{
    return lacp_system_initialized;
}

/*
 * lacp_init_system
 *
 * API to init the LACP System
 * This should only be done once at the beginning.
 */
indigo_error_t
lacpa_init_system (lacpa_system_t *system)
{
    uint32_t ports_size = 0;

    if (lacpa_is_system_initialized()) return INDIGO_ERROR_NONE;

    if (!system) return INDIGO_ERROR_PARAM;

    AIM_LOG_TRACE("Initing the LACP System...");

    ports_size = sizeof(lacpa_port_t) * (PHY_PORT_COUNT+1);
    system->lacp_active_port_count = 0;
    system->ports = (lacpa_port_t *) LACPA_MALLOC(ports_size);

    if (!system->ports) {
        AIM_LOG_ERROR("Failed to allocate resources for ports..");
        return INDIGO_ERROR_RESOURCE;
    }

    AIM_LOG_TRACE("Succesfully inited LACP System for %d ports...",
                  PHY_PORT_COUNT);
    LACPA_MEMSET(system->ports, 0, ports_size);
    lacp_system_initialized = true;

    /*
     * Register listerners for port packet_in and Controller msg's
     */
    if (ind_core_packet_in_listener_register((ind_core_packet_in_listener_f)
                                             lacpa_packet_in_listner) < 0) {
        AIM_LOG_FATAL("Failed to register for port packet_in in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    if (ind_core_message_listener_register((ind_core_message_listener_f)
                                           lacpa_controller_msg_listner) < 0) {
        AIM_LOG_FATAL("Failed to register for Controller msg in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_find_port
 *
 * Returns port pointer in the system for valid port_no else
 * returns NULL
 */
lacpa_port_t *
lacpa_find_port (lacpa_system_t *system, uint32_t port_no)
{
    if (!system) return NULL;

    if (port_no > PHY_PORT_COUNT) {
        AIM_LOG_ERROR("FATAL ERROR - Port No: %d Out of Range %d",
                      port_no, PHY_PORT_COUNT);
        return NULL;
    }

    return (&system->ports[port_no]);
}
