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

#ifndef __LLDPA_H__
#define __LLDPA_H__


/* <auto.start.enum(ALL).header> */
/** lldpa_contr_stype */
typedef enum lldpa_contr_stype_e {
    LLDPA_CONTR_STYPE_TX_REQ = 31,
    LLDPA_CONTR_STYPE_TX_RES = 32,
    LLDPA_CONTR_STYPE_RX_REQ = 33,
    LLDPA_CONTR_STYPE_RX_RES = 34,
    LLDPA_CONTR_STYPE_TIMEOUT = 35,
    LLDPA_CONTR_STYPE_DUMMY,
} lldpa_contr_stype_t;

/** Enum names. */
const char* lldpa_contr_stype_name(lldpa_contr_stype_t e);

/** Enum values. */
int lldpa_contr_stype_value(const char* str, lldpa_contr_stype_t* e, int substr);

/** Enum descriptions. */
const char* lldpa_contr_stype_desc(lldpa_contr_stype_t e);

/** Enum validator. */
int lldpa_contr_stype_valid(lldpa_contr_stype_t e);

/** validator */
#define LLDPA_CONTR_STYPE_VALID(_e) \
    (lldpa_contr_stype_valid((_e)))

/** lldpa_contr_stype_map table. */
extern aim_map_si_t lldpa_contr_stype_map[];
/** lldpa_contr_stype_desc_map table. */
extern aim_map_si_t lldpa_contr_stype_desc_map[];
/* <auto.end.enum(ALL).header> */


/*********************
 **** MANUALLY ADD****
 *********************/

#include <loci/loci_base.h>
#include <OFStateManager/ofstatemanager.h>
#include <SocketManager/socketmanager.h>

typedef struct lldpa_pkt_s {
    uint32_t              interval_ms;
    of_octets_t           data;
} lldpa_pkt_t;

typedef struct lldpa_port_s {
    uint32_t      version;
    of_port_no_t  port_no;
    lldpa_pkt_t   rx_pkt;
    lldpa_pkt_t   tx_pkt;

    /* Internal Statistic */
    uint64_t      rx_pkt_in_cnt;
    uint64_t      tx_pkt_out_cnt;
    uint64_t      timeout_pkt_cnt;

} lldpa_port_t;

typedef void (*SendControllerMessage) (indigo_cxn_id_t cxn_id, of_object_t *obj);
typedef void (*SendAsyncMessage)      (of_object_t *obj);
typedef indigo_error_t (*FwdPacketOut) (of_packet_out_t *pkt);
typedef indigo_error_t (*GetAsyncVersion) (of_version_t *ver);
typedef indigo_error_t (*TimerEventRegister) (ind_soc_timer_callback_f callback, void *cookie, int repeat_time_ms);
typedef indigo_error_t (*TimerEventUnregister) (ind_soc_timer_callback_f callback, void *cookie);
typedef struct lldpa_sys_fn_s {
    SendControllerMessage send_controller_message;
    FwdPacketOut          fwd_packet_out;
    GetAsyncVersion       get_async_version;
    SendAsyncMessage      send_async_message;
    TimerEventRegister    timer_event_register;
    TimerEventUnregister  timer_event_unregister;
} lldpa_sys_fn_t;

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
int lldpa_system_init(lldpa_sys_fn_t *fn);
void lldpa_system_finish();

extern int LLDPA_RX_USE_POLLING;
#endif /* __LLDPA_H__ */
