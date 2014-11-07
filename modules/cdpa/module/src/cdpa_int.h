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

#ifndef __CDPA_INT_H__
#define __CDPA_INT_H__

#include <cdpa/cdpa_config.h>
#include <cdpa/cdpa.h>
#include <debug_counter/debug_counter.h>
#include <loci/loci.h>
#include <indigo/of_state_manager.h>
#include <OFStateManager/ofstatemanager.h>
#include <SocketManager/socketmanager.h>

#define CDP_SLOT_NUM            1

typedef struct cdpa_pkt_s { /* cdpa_pkt */
    uint32_t              interval_ms;  /* interval_ms == 0: disable */
    of_octets_t           data;
} cdpa_pkt_t;

typedef struct cdpa_port_s { /* cdpa_port */
    of_port_no_t port_no;
    cdpa_pkt_t   rx_pkt;
    cdpa_pkt_t   tx_pkt;

    /* Internal Port Statistics */
    uint64_t      rx_pkt_in_cnt;
    uint64_t      rx_pkt_mismatched_no_data;
    uint64_t      rx_pkt_mismatched_len;
    uint64_t      rx_pkt_mismatched_data;
    uint64_t      rx_pkt_matched;
    uint64_t      tx_pkt_out_cnt;
    uint64_t      timeout_pkt_cnt;
    uint64_t      tx_req_cnt;
    uint64_t      rx_req_cnt;
} cdpa_port_t;

typedef struct cdpa_debug_s { /* cdpa_debug */
    debug_counter_t   cdp_total_in_packets;
    debug_counter_t   cdp_total_out_packets;
    debug_counter_t   cdp_total_rx_msgs;
    debug_counter_t   cdp_total_tx_msgs;
} cdpa_debug_t;

typedef struct cdpa_system_s { /* cdpa_system */
    cdpa_debug_t debug_info;
    cdpa_port_t  ports[CDPA_CONFIG_OF_PORTS_MAX+1];
} cdpa_system_t;

cdpa_system_t cdpa_system;

/*
 * cdpa_find_port
 *
 * Returns port pointer in the system for valid port_no else
 * returns NULL
 */
static inline cdpa_port_t*
cdpa_find_port(of_port_no_t port_no)
{
    cdpa_port_t *ret = NULL;
    if (port_no <= CDPA_CONFIG_OF_PORTS_MAX) {
        ret = &cdpa_system.ports[port_no];
    }

    return ret;
}

#endif /* __CDPA_INT_H__ */
