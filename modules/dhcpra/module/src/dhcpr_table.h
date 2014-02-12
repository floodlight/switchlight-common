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

#ifndef DHCPR_TABLE_H_
#define DHCPR_TABLE_H_

#include <indigo/error.h>
indigo_error_t dhcpr_table_init();
void dhcpr_table_finish();
dhc_relay_t* dhcpr_get_dhcpr_entry_from_vlan_table(uint32_t vlan);
void dhcpr_circuit_id_to_vlan(uint32_t *vlan, uint8_t *cir_id, int cir_id_len);
void dhcpr_virtual_router_ip_to_vlan(uint32_t *vlan, uint32_t vr_ip);

int dhcpr_table_get_vlan_entry_number();
int dhcpr_table_get_virtual_router_ip_entry_number();
int dhcpr_table_get_circuit_id_entry_number();

#endif /* DHCPR_TABLE_H_ */
