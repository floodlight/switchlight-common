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

#ifndef __ARPRA_H__
#define __ARPRA_H__

/*
 * BigTap ARP agent init api's
 */
indigo_error_t arpra_init();
void arpra_finish();

/*
 * Api's to add/delete ip --> mac mapping in arp cache
 */
indigo_error_t arpra_add_cache_entry(uint32_t ipv4, of_mac_addr_t mac);
indigo_error_t arpra_delete_cache_entry(uint32_t ipv4, of_mac_addr_t mac);

/*
 * Return mac --> ip mapping
 */
bool arpra_lookup(uint32_t ipv4, of_mac_addr_t *mac);

#endif /* __ARPRA_H__ */

