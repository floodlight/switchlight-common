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
bool lacp_system_initialized = FALSE;

/*
 * lacp_system_initialized
 *
 * TRUE = System Initialized
 * FASLE = System Uninitialized
 */
extern bool
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
extern void
lacpa_init_system (lacpa_system_t *system)
{
    uint32_t  num_of_ports = 0;

    if (lacpa_is_system_initialized() || !system) return;

	AIM_LOG_TRACE("Initing the LACP System...");

    num_of_ports = PHY_PORT_COUNT;
    system->lacp_active_port_count = 0;
    system->ports = (lacpa_port_t *) LACPA_MALLOC(
                    sizeof(lacpa_port_t) * (num_of_ports+1));

    if (!system->ports) {
		AIM_LOG_ERROR("Failed to allocate resources for ports..");
	    return;
    }

    AIM_LOG_TRACE("Succesfully inited LACP System for %d ports...",
                  num_of_ports);
	lacp_system_initialized = TRUE;
}

/*
 * lacpa_find_port
 *
 * Returns port pointer in the system for valid port_no else
 * returns NULL
 */
extern lacpa_port_t *
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
