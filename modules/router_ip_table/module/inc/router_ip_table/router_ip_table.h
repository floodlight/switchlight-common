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

#include <indigo/indigo.h>

#ifndef __ROUTER_IP_TABLE_H__
#define __ROUTER_IP_TABLE_H__

/*
 * This module implements the router_ip gentable and provides interfaces for
 * other modules to query it.
 */

indigo_error_t router_ip_table_init();
void router_ip_table_finish();

/**
 * @brief Lookup the router IP and MAC for a given VLAN
 * @param vlan
 * @param [out] ip
 * @param [out] mac
 * @return Error code
 */
indigo_error_t router_ip_table_lookup(uint16_t vlan, uint32_t *ip, of_mac_addr_t *mac);

/**
 * @brief Lookup if a given ip is a valid router IP 
 * @param ip 
 * @return bool 
 */
bool router_ip_check(uint32_t ip);

#endif /* __ROUTER_IP_TABLE_H__ */
