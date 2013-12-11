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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <PPE/ppe.h>
#include <PPE/ppe_types.h>

#define AIM_LOG_MODULE_NAME lldpa
#include <AIM/aim_log.h>

#include <lldpa/lldpa_config.h>
#include <lldpa/lldpa_porting.h>
#include <lldpa/lldpa.h>
#include "lldpa_int.h"

static lldpa_port_t *lldpa_find_port(of_port_no_t port_no);
static indigo_error_t  lldpa_pkt_data_set(lldpa_pkt_t *lpkt, of_octets_t *data);
static void lldpa_pkt_data_free (lldpa_pkt_t *lpkt);
static void  lldpa_free_pkts(lldpa_port_t *lldpa);
static void lldpdu_timeout_rx(void *cookie);
static void lldpdu_periodic_tx(void *cookie);
static void rx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req);
static void tx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req);

static void lldpdu_periodic_tx(void *cookie);
static void lldpdu_timeout_rx(void *cookie);

#define LLDPA_DEBUG(fmt, ...)                       \
            AIM_LOG_TRACE(fmt, ##__VA_ARGS__)

lldpa_system_t lldpa_port_sys;

static lldpa_port_t*
lldpa_find_port(of_port_no_t port_no)
{
    lldpa_port_t *ret = NULL;
    if ((port_no >= 0) && (port_no < MAX_LLDPA_PORT))
        ret = &lldpa_port_sys.lldpa_ports[port_no];

    return ret;
}

/*
 * data.data must be NULL
 * Ret 0 for success
 * */
static indigo_error_t
lldpa_pkt_data_set(lldpa_pkt_t *lpkt, of_octets_t *data)
{
    if(!lpkt || !data)
        return INDIGO_ERROR_PARAM;

    if (lpkt->data.data) {
        return INDIGO_ERROR_PARAM;
    }
    
    lpkt->data.data = LLDPA_MALLOC(data->bytes);
    if (!lpkt->data.data)
        return INDIGO_ERROR_RESOURCE;
    
    lpkt->data.bytes = data->bytes;
    LLDPA_MEMCPY(lpkt->data.data, data->data, data->bytes);
   
    return INDIGO_ERROR_NONE;
}

/* free data and reset bytes */
static void
lldpa_pkt_data_free (lldpa_pkt_t *lpkt)
{
    if (lpkt) {
        if (lpkt->data.data) {
            LLDPA_FREE(lpkt->data.data);
            lpkt->data.data  = NULL;
            lpkt->data.bytes = 0;
        }
    }
}

/* Unregister timer and free data */
static void
lldpa_free_pkts(lldpa_port_t *port)
{
    if (!port)
        return;

    if (port->tx_pkt.interval_ms) {
        ind_soc_timer_event_unregister(lldpdu_periodic_tx, port);
        port->tx_pkt.interval_ms = 0;
    }

    if (port->rx_pkt.interval_ms) {
        ind_soc_timer_event_unregister(lldpdu_timeout_rx, port);
        port->rx_pkt.interval_ms = 0;
    }

    lldpa_pkt_data_free(&port->rx_pkt);
    lldpa_pkt_data_free(&port->tx_pkt);
}

static void
lldpdu_timeout_rx(void *cookie)
{
    uint32_t version;
    lldpa_port_t *port = (lldpa_port_t*) cookie;
    of_bsn_pdu_rx_timeout_t *timeout_msg = NULL;

    if (!port)
        return;

    if (indigo_cxn_get_async_version(&version) != INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("%s: No controller connected",__FUNCTION__);
        return;
    }

    timeout_msg = of_bsn_pdu_rx_timeout_new(version);
    if(!timeout_msg){
        AIM_LOG_ERROR("%s:%d Failed to allocate timeout msg",__FILE__,__LINE__);
        return;
    }

    /* Set port number */
    of_bsn_pdu_rx_timeout_port_no_set (timeout_msg, port->port_no);

    LLDPA_DEBUG("%s:%d: send async version %u",__FUNCTION__,__LINE__,version);
    /* Send to controller, don't delete when send to controller */
    indigo_cxn_send_async_message(timeout_msg);

    port->timeout_pkt_cnt++;
}

static void
lldpdu_periodic_tx(void *cookie)
{
    lldpa_port_t *port = (lldpa_port_t*) cookie;
    of_packet_out_t *pkt_out;
    of_list_action_t   *list;
    of_action_output_t *action;
    indigo_error_t     rv;

    if(!port)
        return;

    pkt_out = of_packet_out_new (port->version);
    if(!pkt_out){
        AIM_LOG_ERROR("%s:%d Failed to allocate packet out",__FILE__,__LINE__);
        return;
    }

    action = of_action_output_new(port->version);
    if(!action){
        of_packet_out_delete(pkt_out);
        AIM_LOG_ERROR("%s:%d Failed to allocation action",
                      __FILE__,__LINE__);
        return;
    }
    of_action_output_port_set(action, port->port_no);

    list = of_list_action_new(port->version);
    if(!list){
        of_packet_out_delete(pkt_out);
        of_object_delete(action);
        AIM_LOG_ERROR("%s:%d Failed to allocate action list",
                      __FILE__,__LINE__);
        return;
    }

    of_list_append(list, action);
    of_object_delete(action);

    rv = of_packet_out_actions_set(pkt_out, list);
    of_object_delete(list);

    if ((rv = of_packet_out_data_set(pkt_out, &port->tx_pkt.data)) != INDIGO_ERROR_NONE) {
        AIM_LOG_TRACE("Packet out failed to set data %d", rv);
        of_packet_out_delete(pkt_out);
        return;
    }

    LLDPA_DEBUG("%s:%d: fwd version %u",__FUNCTION__,__LINE__,port->version);

    if ((rv = indigo_fwd_packet_out(pkt_out)) == INDIGO_ERROR_NONE)
        port->tx_pkt_out_cnt++;
    else {
        AIM_LOG_ERROR("%s:%d Fwd pkt out failed",__FILE__,__LINE__);
    }
    /* Fwding pkt out HAS to delete obj */
    of_packet_out_delete(pkt_out);
}

static void
rx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req)
{
    lldpa_port_t *port = NULL;
    int           rv;

    /* rx_req info */
    uint32_t     xid;
    of_port_no_t port_no;
    uint32_t     timeout_ms;
    of_octets_t  data;
    uint8_t      slot_num;

    of_bsn_pdu_rx_reply_t *rx_reply = NULL;
    uint32_t              status_failed = 0;

    /* Get rx req info */
    of_bsn_pdu_rx_request_xid_get       (rx_req, &xid);
    of_bsn_pdu_rx_request_timeout_ms_get(rx_req, &timeout_ms);
    of_bsn_pdu_rx_request_data_get      (rx_req, &data);
    of_bsn_pdu_rx_request_port_no_get   (rx_req, &port_no);
    of_bsn_pdu_rx_request_slot_num_get  (rx_req, &slot_num);

    /* Only support slot_num 0 at this time */
    if (slot_num) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Rx Port %u, slot_num %d not supported", port_no, slot_num);
        goto rx_reply_to_ctrl;
    }

    if (timeout_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Rx Port %u, inconsistent info", port_no);
        goto rx_reply_to_ctrl;
    }

    if (!(port = lldpa_find_port(port_no))) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
        goto rx_reply_to_ctrl;
    }

    /* 1. Unreg timer, delete the current rx_pkt */
    port->version = rx_req->version;
    if(port->rx_pkt.interval_ms) {
        if (ind_soc_timer_event_unregister(lldpdu_timeout_rx, port)
            == INDIGO_ERROR_NONE) {
            port->rx_pkt.interval_ms = 0;
            lldpa_pkt_data_free(&port->rx_pkt);
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("Port %u non-exist timer", port->port_no);
            goto rx_reply_to_ctrl;
        }
    }

    /* Additional consistent state check */
    if (port->rx_pkt.interval_ms || port->rx_pkt.data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u state inconsistent", port->port_no);
        goto rx_reply_to_ctrl;
    }

    /* 2. Set up new rx_pkt, timer */
    if(timeout_ms) {
        if ((rv = lldpa_pkt_data_set(&port->rx_pkt, &data)) == INDIGO_ERROR_NONE) {
            if (ind_soc_timer_event_register(lldpdu_timeout_rx, port, timeout_ms)
                == INDIGO_ERROR_NONE) {
                port->rx_pkt.interval_ms = timeout_ms;
                /* When it reaches here: success */
            } else {
                status_failed = 1;
                lldpa_pkt_data_free(&port->rx_pkt);
                AIM_LOG_ERROR("timer event register failed %s:%d",__FILE__,__LINE__);
            }
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("%s:%d data set failed rv %d",__FILE__,__LINE__,rv);
        }
    }

rx_reply_to_ctrl:
    /* 3. Setup reply */
    rx_reply = of_bsn_pdu_rx_reply_new(rx_req->version);
    if(!rx_reply){
        AIM_LOG_ERROR("%s:%d Failed to allocate rx_reply",__FILE__,__LINE__);
        return;
    }
    of_bsn_pdu_rx_reply_xid_set     (rx_reply, xid);
    of_bsn_pdu_rx_reply_port_no_set (rx_reply, port_no);
    of_bsn_pdu_rx_reply_status_set  (rx_reply, status_failed);

    LLDPA_DEBUG("%s:%d: send reply version %u",__FUNCTION__,__LINE__,rx_req->version);
    /* 4. Send to controller, don't delete obj */
    indigo_cxn_send_controller_message(cxn_id, rx_reply);

}


static void
tx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *tx_req)
{
    lldpa_port_t *port = NULL;

    int rv;

    /* tx_req info */
    uint32_t     xid;
    of_port_no_t port_no;
    uint32_t     tx_interval_ms;
    of_octets_t  data;
    uint8_t      slot_num;

    /* tx_reply info */
    of_bsn_pdu_tx_reply_t *tx_reply = NULL;
    uint32_t              status_failed = 0;

    /* Get tx req info */
    of_bsn_pdu_tx_request_xid_get           (tx_req, &xid);
    of_bsn_pdu_tx_request_tx_interval_ms_get(tx_req, &tx_interval_ms);
    of_bsn_pdu_tx_request_data_get          (tx_req, &data);
    of_bsn_pdu_tx_request_port_no_get       (tx_req, &port_no);
    of_bsn_pdu_tx_request_slot_num_get      (tx_req, &slot_num);

    /* Only support slot_num 0 at this time */
    if (slot_num) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Tx Port %u, Slot_num %d not supported", port_no, slot_num);
        goto tx_reply_to_ctrl;
    }

    if (tx_interval_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Tx Port %u, Inconsistent info", port_no);
        goto tx_reply_to_ctrl;
    }

    if (!(port = lldpa_find_port(port_no))) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
        goto tx_reply_to_ctrl;
    }

    /* 1. unreg old timer, delete old data */
    port->version = tx_req->version;
    if (port->tx_pkt.interval_ms) {
        if (ind_soc_timer_event_unregister(lldpdu_periodic_tx, port)
            == INDIGO_ERROR_NONE) {
            port->tx_pkt.interval_ms = 0;
            lldpa_pkt_data_free(&port->tx_pkt);
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("Port %u non-exist timer", port->port_no);
            goto tx_reply_to_ctrl;
        }
    }

    /* Additional consistent state check */
    if (port->tx_pkt.interval_ms || port->tx_pkt.data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u state inconsistent", port->port_no);
        goto tx_reply_to_ctrl;
    }

    /* 2. Set up new tx_pkt, alarm */
    if(!status_failed && tx_interval_ms) {
        if ((rv=lldpa_pkt_data_set(&port->tx_pkt, &data)) == INDIGO_ERROR_NONE) {
            /* Send one immediately */
            lldpdu_periodic_tx(port);
            if (ind_soc_timer_event_register(lldpdu_periodic_tx, port, tx_interval_ms)
                    == INDIGO_ERROR_NONE) {
                port->tx_pkt.interval_ms = tx_interval_ms;
                /* When it reaches here: success */
            } else {
                status_failed = 1;
                lldpa_pkt_data_free(&port->tx_pkt);
                AIM_LOG_ERROR("timer event register failed %s:%d",__FILE__,__LINE__);
            }
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("%s:%d data set failed rv %d",__FILE__,__LINE__,rv);
        }
    }

tx_reply_to_ctrl:
    /* 3. Setup reply  */
    tx_reply = of_bsn_pdu_tx_reply_new(tx_req->version);
    if(!tx_reply){
        AIM_LOG_ERROR("%s:%d Failed to allocate tx reply",__FILE__,__LINE__);
        return;
    }

    of_bsn_pdu_tx_reply_xid_set     (tx_reply, xid);
    of_bsn_pdu_tx_reply_port_no_set (tx_reply, port_no);
    of_bsn_pdu_tx_reply_status_set  (tx_reply, status_failed);

    LLDPA_DEBUG("%s:%d: send reply version %u",__FUNCTION__,__LINE__,tx_req->version);
    /* 4. Send to controller, don't delete obj */
    indigo_cxn_send_controller_message(cxn_id, tx_reply);

}

/* Register to listen to CTRL msg */
ind_core_listener_result_t
lldpa_handle_msg (indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    ind_core_listener_result_t ret = IND_CORE_LISTENER_RESULT_PASS;

    if(!msg)
        return ret;

    switch (msg->object_id) {
    case OF_BSN_PDU_RX_REQUEST:
        /* Count msg in */
        lldpa_port_sys.total_msg_in_cnt++;
        rx_request_handle(cxn_id, msg);
        ret = IND_CORE_LISTENER_RESULT_DROP;
        break;

    case OF_BSN_PDU_TX_REQUEST:
        /* Count msg in */
        lldpa_port_sys.total_msg_in_cnt++;
        tx_request_handle(cxn_id, msg);
        ret = IND_CORE_LISTENER_RESULT_DROP;
        break;

    default:
        break;
    }

    return ret;
}



/*****************
 * HANDLE PKT IN *
 *****************/

/*
 * Caller must ensure lldap != NULL, data != NULL
 * return 1 if pkt is expected
 * */
static inline int
lldpa_rx_pkt_is_expected(lldpa_port_t *port, of_octets_t *data)
{
    int ret = 0;

    if (port->rx_pkt.data.data &&
            (port->rx_pkt.data.bytes == data->bytes))
        if (memcmp(port->rx_pkt.data.data, data->data, data->bytes) == 0)
            ret = 1;

    return ret;
}

/*
 * Caller must ensure lldap != NULL
 * Reset timeout
 * */
static inline void
lldpa_update_rx_timeout(lldpa_port_t *port)
{
    LLDPA_DEBUG("%s:%d using reset timer",__FUNCTION__,__LINE__);
    if (ind_soc_timer_event_register(lldpdu_timeout_rx, port, port->rx_pkt.interval_ms) !=
            INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("%s:%d timer register failed",__FUNCTION__,__LINE__);
    }
}

/* Register to listen to PACKETIN msg */
ind_core_listener_result_t
lldpa_handle_pkt (of_packet_in_t *packet_in)
{
    lldpa_port_t               *port = NULL;
    of_octets_t                data;
    of_port_no_t               port_no;
    of_match_t                 match;
    ppe_packet_t               ppep;
    ind_core_listener_result_t ret = IND_CORE_LISTENER_RESULT_PASS;

    if(!packet_in)
        return ret;

    /* Data is the ether pkt */
    of_packet_in_data_get(packet_in, &data);

    if(!data.data)
        return ret;

    /* Parsing ether pkt and identify if this is a LLDP Packet */
    ppe_packet_init(&ppep, data.data, data.bytes);

    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_ERROR("Packet parsing failed. packet=%{data}", data.data, data.bytes);
        return ret;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_LLDP)) {
        /* Since we listen to all pkt_in
         * Rate is high, no need add debug msg here
         * Not LLDP packet, simply return */
        return ret;
    }

    /* Only count pkt_in with valid data */
    lldpa_port_sys.total_pkt_in_cnt++;

    if (packet_in->version <= OF_VERSION_1_1) {
        of_packet_in_in_port_get(packet_in, &port_no);
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_ERROR("match get failed");
            return ret;
        }
        port_no = match.fields.in_port;
        LLDPA_DEBUG("%s:%d: port %u",__FUNCTION__,__LINE__,port_no);
    }

    port = lldpa_find_port(port_no);
    if (!port) {
        AIM_LOG_ERROR("LLDPA port out of range %u", port_no);
        return ret;
    }

    port->rx_pkt_in_cnt++;

    /* At this step we will process the LLDP packet
     * 0. Port doesn't have data, won't expect any packet
     * 1. If expected, reset the timeout
     * 2. If not, it's automatically PASSED to the controller
     *    as a packet-in
     */
    if (lldpa_rx_pkt_is_expected(port, &data)) {
        ret = IND_CORE_LISTENER_RESULT_DROP;
        lldpa_update_rx_timeout(port);
    }

    LLDPA_DEBUG("%s:%d: port %u, rx_pkt_in_cnt %l, pkt MATCH=%s",__FUNCTION__,__LINE__,port_no,
            port->rx_pkt_in_cnt, ret == IND_CORE_LISTENER_RESULT_DROP ? "true" : "false");
    return ret;
}


/************************
 * LLDAP INIT and FINISH
 ************************/

/* Return 0: success */
int
lldpa_system_init()
{
    int i;
    lldpa_port_t *port;

    AIM_LOG_INFO("init");

    lldpa_port_sys.lldpa_total_phy_ports = MAX_LLDPA_PORT;
    for (i=0; i<MAX_LLDPA_PORT;i++) {
        port = lldpa_find_port(i);
        if (port)
            port->port_no = i;
        else
            AIM_LOG_ERROR("Port %d not existing", i);
    }

    ind_core_message_listener_register(lldpa_handle_msg);
    ind_core_packet_in_listener_register(lldpa_handle_pkt);

    return 0;
}

void
lldpa_system_finish()
{
    int i;
    lldpa_port_t *port;

    ind_core_message_listener_unregister(lldpa_handle_msg);
    ind_core_packet_in_listener_unregister(lldpa_handle_pkt);

    for (i=0; i<MAX_LLDPA_PORT;i++) {
        port = lldpa_find_port(i);
        if (port)
            lldpa_free_pkts(port);
        else
            AIM_LOG_ERROR("Port %d not existing", i);
    }
}
