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

/**************************************************************************//**
 *
 * sflowa Internal Header
 *
 *****************************************************************************/
#ifndef __SFLOWA_INT_H__
#define __SFLOWA_INT_H__

#include <sflowa/sflowa_config.h>
#include <sflowa/sflowa.h>
#include <loci/loci.h>
#include <indigo/indigo.h>
#include <indigo/of_state_manager.h>
#include <AIM/aim_list.h>

#define MAX_PORTS            256

typedef struct sflow_collector_entry_key_s { /* sflow_collector_entry_key */
    uint32_t collector_ip;
} sflow_collector_entry_key_t;

typedef struct sflow_collector_entry_value_s { /* sflow_collector_entry_value */
    uint16_t vlan_id;
    of_mac_addr_t agent_mac;
    of_ipv4_t agent_ip;
    uint16_t agent_udp_sport;
    of_mac_addr_t collector_mac;
    uint16_t collector_udp_dport;
    uint32_t sub_agent_id;
} sflow_collector_entry_value_t;

typedef struct sflow_collector_entry_stats_s { /* sflow_collector_entry_stats */
    uint64_t tx_packets;
    uint64_t tx_bytes;
} sflow_collector_entry_stats_t;

typedef struct slow_collector_entry_s { /* slow_collector_entry */
    sflow_collector_entry_key_t key;
    sflow_collector_entry_value_t value;
    sflow_collector_entry_stats_t stats;
} slow_collector_entry_t;

typedef struct sflow_sampler_entry_value_s { /* sflow_sampler_entry_value */
    uint32_t sampling_rate;
    uint32_t header_size;
} sflow_sampler_entry_value_t;

typedef struct sflow_sampler_entry_s { /* sflow_sampler_entry */
    sflow_sampler_entry_value_t value;
} sflow_sampler_entry_t;

typedef struct sflow_collector_cache_entry_s { /* sflow_collector_cache_entry */
    slow_collector_entry_t entry;
    list_links_t  links;
} sflow_collector_cache_entry_t;

sflow_collector_cache_entry_t*
sflow_collector_cache_find(sflow_collector_entry_key_t key);

#endif /* __SFLOWA_INT_H__ */
