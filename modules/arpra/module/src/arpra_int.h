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

/**************************************************************************//**
 *
 * arpra Internal Header
 *
 *****************************************************************************/
#ifndef __ARPRA_INT_H__
#define __ARPRA_INT_H__

#include <arpra/arpra_config.h>
#include <arpra/arpra_porting.h>
#include <arpra/arpra.h>
#include "arpra_log.h"
#include <PPE/ppe.h>
#include <loci/loci.h>
#include <indigo/of_state_manager.h>
#include <OS/os_time.h>
#include <AIM/aim_list.h>

typedef struct arp_mapping_s { /* arp_mapping */
    of_mac_addr_t mac;
    uint32_t      ipv4;
} arp_mapping_t;

typedef struct arp_info_s { /* arp_info */
    of_mac_addr_t eth_src;
    of_mac_addr_t eth_dst;
    uint16_t      vlan_vid;
    uint8_t       vlan_pcp;
    uint16_t      operation;
    arp_mapping_t sender;
    arp_mapping_t target;
} arp_info_t;

typedef struct arp_cache_entry_s { /* arp_cache_entry */
    arp_mapping_t entry;
    list_links_t  links;
} arp_cache_entry_t;

bool arpra_is_initialized (void);

/*
 * 
 * Return a list of registered debug counters
 *
 * The list is through the 'links' field of debug_counter_t.
 *
 * Iterating over the list may not be done concurrently with calls to
 * debug_counter_register or debug_counter_unregister.
 */
list_head_t *arp_cache_list(void);

indigo_core_listener_result_t arpra_packet_in_handler(of_packet_in_t *packet_in);

#endif /* __ARPRA_INT_H__ */
