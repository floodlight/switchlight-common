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

#ifndef __ICMPA_INT_H__
#define __ICMPA_INT_H__

#include <icmpa/icmpa_config.h>
#include <icmpa/icmpa_porting.h>
#include <icmpa/icmpa.h>
#include "icmpa_log.h"
#include <PPE/ppe.h>
#include <loci/loci.h>
#include <OS/os_time.h>
#include <indigo/of_state_manager.h>
#include <router_ip_table/router_ip_table.h>
#include <debug_counter/debug_counter.h>

/******************************************************************************
 *
 * ICMP: INTERNET CONTROL MESSAGE PROTOCOL: DEFAULTS
 *
 *****************************************************************************/

/*
 * ICMP Packet Structure
 ---------------------------------------------------------------------------
| 6  | 6  |    4   | 2  |  20  |   8    | ECHO DATA - 32(Windows)/56(Linux) |
|DMAC|SMAC|TAG|VLAN|TYPE|IP HDR|ICMP HDR| ICMP DATA - 28                    |
 ---------------------------------------------------------------------------
*/

#define ICMP_PKT_BUF_SIZE   74 //18 + 20 + 8 + 28
#define ICMP_HEADER_SIZE    8
#define ICMP_DATA_LEN       28
#define IP_HEADER_SIZE      20
#define IP_TOTAL_LEN        56 //20 + 8 + 28

#define ETHERTYPE_DOT1Q     0x8100

/*
 * Supported ICMP TYPES
 */
#define ICMP_ECHO_REPLY         0   /* Echo Reply               */
#define ICMP_DEST_UNREACHABLE   3   /* Destination Unreachable  */
#define ICMP_ECHO_REQUEST       8   /* Echo Request             */
#define ICMP_TIME_EXCEEDED      11  /* Time Exceeded            */

#define MAX_PORTS               256

extern aim_ratelimiter_t icmp_pktin_log_limiter;

typedef struct icmpa_packet_counter_s { /* icmpa_packet_counter */
    debug_counter_t  icmp_total_in_packets;
    debug_counter_t  icmp_total_out_packets;
    debug_counter_t  icmp_total_passed_packets;
    debug_counter_t  icmp_internal_errors;
} icmpa_packet_counter_t;

typedef struct icmpa_typecode_packet_counter_s { /* icmpa_typecode_packet_counter */
    uint64_t         icmp_echo_packets;
    uint64_t         icmp_time_exceeded_packets;
    uint64_t         icmp_net_unreachable_packets;
    uint64_t         icmp_port_unreachable_packets;
} icmpa_typecode_packet_counter_t;

extern icmpa_packet_counter_t pkt_counters;
extern icmpa_typecode_packet_counter_t port_pkt_counters[MAX_PORTS+1];

/******************************************************************************
 *
 * ICMP: INTERNET CONTROL MESSAGE PROTOCOL: INTERNAL API DECLARATIONS
 *
 *****************************************************************************/

bool icmpa_reply (ppe_packet_t *ppep, of_port_no_t port_no);
bool icmpa_send (ppe_packet_t *ppep, of_port_no_t port_no,
                 uint32_t type, uint32_t code);
indigo_error_t icmpa_send_packet_out (of_octets_t *octets);

indigo_core_listener_result_t
icmpa_packet_in_handler (of_packet_in_t *packet_in);

#endif /* __ICMPA_INT_H__ */
