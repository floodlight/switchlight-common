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

    /* Slot_Num Statistics if supported */

} lldpa_port_t;

typedef struct lldpa_system_s {
    uint32_t      lldpa_total_of_ports;

    /* Internal statistic for listener interfaces*/
    uint64_t      total_pkt_in_cnt;
    uint64_t      total_msg_in_cnt;
    uint64_t      total_pkt_exp_cnt;
    lldpa_port_t  lldpa_ports[LLDPA_CONFIG_OF_PORTS_MAX+1];
} lldpa_system_t;

indigo_core_listener_result_t lldpa_handle_msg (indigo_cxn_id_t cxn_id, of_object_t *msg);
indigo_core_listener_result_t lldpa_handle_pkt (of_packet_in_t *packet_in);
lldpa_port_t *lldpa_find_port(of_port_no_t port_no);

enum {
    LLDPA_DUMP_DISABLE_ALL_PORTS = -2,
    LLDPA_DUMP_ENABLE_ALL_PORTS  = -1
};
/**
 * Dump data buffer from cxn_data_hexdump
 * Must define LLDPA_TRACE before use
 */
#define HEX_LEN 80
#define PER_LINE 16
static inline void
lldpa_data_hexdump(unsigned char *buf, int bytes, void (*display_fn)(char *))
{
    int idx;
    char display[HEX_LEN];
    int disp_offset = 0;
    int buf_offset = 0;

    display_fn("LLDPA_DATA_HEXDUMP");

    while (bytes > 0) {
        disp_offset = 0;
        for (idx = 0; (idx < PER_LINE) && (idx < bytes); idx++) {
            disp_offset += sprintf(&display[disp_offset],
                                   "%02x", buf[buf_offset + idx]);
        }

        for (idx = bytes; idx < PER_LINE; ++idx) {
            disp_offset += sprintf(&display[disp_offset], "  ");
        }
        disp_offset += sprintf(&display[disp_offset], " :");

        for (idx = 0; (idx < PER_LINE) && (idx < bytes); idx++) {
            if (buf[idx] < 32) {
                disp_offset += sprintf(&display[disp_offset], ".");
            } else {
                disp_offset += sprintf(&display[disp_offset], "%c",
                                       buf[buf_offset + idx]);
            }
        }

        display_fn(display);

        bytes -= PER_LINE;
        buf_offset += PER_LINE;
    }
}

#endif /* __LLDPA_INT_H__ */
