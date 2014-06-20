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
#ifndef __LACPA_INT_H__
#define __LACPA_INT_H__

#include <lacpa/lacpa.h>
#include "lacpa_log.h"
#include <inttypes.h>
#include <debug_counter/debug_counter.h>

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : DEFAULTS
 *
 *****************************************************************************/
#define LACP_SLOW_PERIODIC_TIMEOUT_MS   30000
#define LACP_FAST_PERIODIC_TIMEOUT_MS   1000
#define LACP_SHORT_TIMEOUT_MS           3000
#define LACP_LONG_TIMEOUT_MS            90000
#define LACP_CHURN_DETECTION_TIMEOUT_MS 60000

#define LACP_PKT_BUF_SIZE               124  //Per LACP specification
                                             //802.3ad-2000, Max LACPDU size
                                             //is 124 Bytes.

#define PHY_PORT_COUNT                  1024

#define DEFAULT_LACP_VERSION            1

#define DEFAULT_ACTOR_INFO              0x01
#define DEFAULT_PARTNER_INFO            0x02
#define DEFAULT_ACTOR_PARTNER_INFO_LEN  0x14

#define DEFAULT_COLLECTOR_INFO          0x03
#define DEFAULT_COLLECTOR_INFO_LEN      0x10
#define DEFAULT_COLLECTOR_MAX_DELAY     0x8000

/*
 * LACP Actor/Partner State bits
 */
#define LACPA_STATE_LACP_ACTIVITY       0x01
#define LACPA_STATE_LACP_TIMEOUT        0x02
#define LACPA_STATE_AGGREGATION         0x04
#define LACPA_STATE_SYNCHRONIZATION     0x08
#define LACPA_STATE_COLLECTING          0x10
#define LACPA_STATE_DISTRIBUTING        0x20
#define LACPA_STATE_DEFAULTED           0x40
#define LACPA_STATE_EXPIRED             0x80

#define LACPA_SET_STATE_LACP_ACTIVITY(_state) \
    (_state |= LACPA_STATE_LACP_ACTIVITY)
#define LACPA_CLR_STATE_LACP_ACTIVITY(_state) \
    (_state &= ~LACPA_STATE_LACP_ACTIVITY)
#define LACPA_IS_STATE_LACP_ACTIVITY(_state) \
    (_state & LACPA_STATE_LACP_ACTIVITY)

#define LACPA_SET_STATE_LACP_TIMEOUT(_state) \
    (_state |= LACPA_STATE_LACP_TIMEOUT)
#define LACPA_CLR_STATE_LACP_TIMEOUT(_state) \
    (_state &= ~LACPA_STATE_LACP_TIMEOUT)
#define LACPA_IS_STATE_LACP_TIMEOUT(_state) \
    (_state & LACPA_STATE_LACP_TIMEOUT)

#define LACPA_SET_STATE_AGGREGATION(_state) \
    (_state |= LACPA_STATE_AGGREGATION)
#define LACPA_CLR_STATE_AGGREGATION(_state) \
    (_state &= ~LACPA_STATE_AGGREGATION)
#define LACPA_IS_STATE_AGGREGATION(_state) \
    (_state & LACPA_STATE_AGGREGATION)

#define LACPA_SET_STATE_SYNCHRONIZATION(_state) \
    (_state |= LACPA_STATE_SYNCHRONIZATION)
#define LACPA_CLR_STATE_SYNCHRONIZATION(_state) \
    (_state &= ~LACPA_STATE_SYNCHRONIZATION)
#define LACPA_IS_STATE_SYNCHRONIZATION(_state) \
    (_state & LACPA_STATE_SYNCHRONIZATION)

#define LACPA_SET_STATE_COLLECTING(_state) \
    (_state |= LACPA_STATE_COLLECTING)
#define LACPA_CLR_STATE_COLLECTING(_state) \
    (_state &= ~LACPA_STATE_COLLECTING)
#define LACPA_IS_STATE_COLLECTING(_state) \
    (_state & LACPA_STATE_COLLECTING)

#define LACPA_SET_STATE_DISTRIBUTING(_state) \
    (_state |= LACPA_STATE_DISTRIBUTING)
#define LACPA_CLR_STATE_DISTRIBUTING(_state) \
    (_state &= ~LACPA_STATE_DISTRIBUTING)
#define LACPA_IS_STATE_DISTRIBUTING(_state) \
    (_state & LACPA_STATE_DISTRIBUTING)

#define LACPA_SET_STATE_DEFAULTED(_state) \
    (_state |= LACPA_STATE_DEFAULTED)
#define LACPA_CLR_STATE_DEFAULTED(_state) \
    (_state &= ~LACPA_STATE_DEFAULTED)
#define LACPA_IS_STATE_DEFAULTED(_state) \
    (_state & LACPA_STATE_DEFAULTED)

#define LACPA_SET_STATE_EXPIRED(_state) \
    (_state |= LACPA_STATE_EXPIRED)
#define LACPA_CLR_STATE_EXPIRED(_state) \
    (_state &= ~LACPA_STATE_EXPIRED)
#define LACPA_IS_STATE_EXPIRED(_state) \
    (_state & LACPA_STATE_EXPIRED)

extern aim_ratelimiter_t lacpa_pktin_log_limiter;

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : PROTOCOL DATA
 *
 *****************************************************************************/
typedef uint8_t lacpa_state_t;

typedef struct lacpa_info_s { /* lacpa_info */
    uint16_t         sys_priority;
    of_mac_addr_t    sys_mac;
    uint16_t         port_priority;
    uint16_t         port_num;
    uint16_t         key;
    lacpa_state_t    state;
    of_port_no_t     port_no;
} lacpa_info_t;

typedef struct lacp_pdu_s { /* lacpa_pdu */
    lacpa_info_t     actor;
    lacpa_info_t     partner;
} lacpa_pdu_t;

typedef struct lacpa_port_debug_s { /* lacpa_port_debug */
    lacpa_event_t    lacp_event;
    lacpa_transmit_t ntt_reason;
    debug_counter_t  lacp_port_in_packets;
    debug_counter_t  lacp_port_out_packets;
    debug_counter_t  lacp_convergence_notif;
    char             lacp_pktin_counter_name_buf[DEBUG_COUNTER_NAME_SIZE];
    char             lacp_pktout_counter_name_buf[DEBUG_COUNTER_NAME_SIZE];
    char             lacp_convergence_counter_name_buf[DEBUG_COUNTER_NAME_SIZE]; 
} lacpa_port_debug_t;

typedef struct lacpa_port_s { /* lacpa_port */
    lacpa_info_t       actor;
    lacpa_info_t       partner;
    lacpa_machine_t    lacp_state;
    bool               lacp_enabled;
    bool               is_converged;
    bool               churn_detection_running;    
    lacpa_error_t      error;
    lacpa_port_debug_t debug_info;
} lacpa_port_t;

/******************************************************************************
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : SYSTEM DATA & API DECLARATIONS
 *****************************************************************************/
typedef struct lacpa_system_debug_s { /* lacpa_system_debug */
    debug_counter_t   lacp_total_in_packets;
    debug_counter_t   lacp_system_in_packets;
    debug_counter_t   lacp_system_out_packets;
    debug_counter_t   lacp_controller_set_requests;
    debug_counter_t   lacp_controller_stats_requests;
} lacpa_system_debug_t;

typedef struct lacpa_system_s { /* lacpa_system */
    uint32_t             lacp_active_port_count;
    lacpa_system_debug_t debug_info;
    lacpa_port_t         *ports;
} lacpa_system_t;

extern lacpa_system_t lacpa_system;

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : LACPA INTERNAL API DECLARATIONS
 *
 *****************************************************************************/
void lacpa_machine (lacpa_port_t *port, lacpa_pdu_t *pdu, lacpa_event_t event);
void lacpa_transmit (lacpa_port_t *port);

void lacpa_start_periodic_timer (lacpa_port_t *port);
void lacpa_stop_periodic_timer (lacpa_port_t *port);
void lacpa_start_churn_detection_timer (lacpa_port_t *port);
void lacpa_stop_churn_detection_timer (lacpa_port_t *port);
void lacpa_start_current_while_timer (lacpa_port_t *port);
void lacpa_stop_current_while_timer (lacpa_port_t *port);

void lacpa_send_packet_out (lacpa_port_t *port, of_octets_t *octets);
void lacpa_update_controller (lacpa_port_t *port);

void lacpa_init_port (lacpa_info_t *port, bool lacp_enabled);
lacpa_port_t *lacpa_find_port (uint32_t port_no);

indigo_core_listener_result_t
lacpa_packet_in_handler (of_packet_in_t *packet_in);
indigo_core_listener_result_t
lacpa_controller_msg_handler (indigo_cxn_id_t cxn, of_object_t *obj);

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : DEBUG API DECLARATIONS
 *
 *****************************************************************************/
void lacpa_dump_port (lacpa_port_t *port);
void lacpa_dump_state (lacpa_port_t *port);

#endif /* __LACPA_INT_H__ */
