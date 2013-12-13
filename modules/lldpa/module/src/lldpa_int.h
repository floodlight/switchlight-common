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

/*************************************************************//**
 *
 * lldpa Internal Header
 *
 ****************************************************************/
#ifndef __LLDPA_INT_H__
#define __LLDPA_INT_H__

#include <lldpa/lldpa_config.h>

#include <loci/loci_base.h>
#include <OFStateManager/ofstatemanager.h>
#include <SocketManager/socketmanager.h>

typedef struct lldpa_pkt_s {
    /* interval_ms == 0: disable */
    uint32_t              interval_ms;
    of_octets_t           data;
} lldpa_pkt_t;

typedef struct lldpa_port_s {
    of_port_no_t  port_no;
    lldpa_pkt_t   rx_pkt;
    lldpa_pkt_t   tx_pkt;

    /* Internal Statistic */
    uint64_t      rx_pkt_in_cnt;
    uint64_t      tx_pkt_out_cnt;
    uint64_t      timeout_pkt_cnt;

} lldpa_port_t;

#define MAX_LLDPA_PORT 64
typedef struct lldpa_system_s {
    uint32_t      lldpa_total_phy_ports;

    /* Internal statistic for listener interfaces*/
    uint64_t      total_pkt_in_cnt;
    uint64_t      total_msg_in_cnt;

    lldpa_port_t  lldpa_ports[MAX_LLDPA_PORT];
} lldpa_system_t;

ind_core_listener_result_t lldpa_handle_msg (indigo_cxn_id_t cxn_id, of_object_t *msg);
ind_core_listener_result_t lldpa_handle_pkt (of_packet_in_t *packet_in);
#endif /* __LLDPA_INT_H__ */
