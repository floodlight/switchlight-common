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

/*
 * Implementation of CDP Agent.
 *
 * This file contains code for sending and receiving cdp's from
 * partner port.
 */

#include "cdpa_int.h"
#include "cdpa_log.h"

static bool cdpa_initialized = false;

/*
 * cdpa_pkt_data_free
 *
 * free data and reset bytes
 */
static void
cdpa_pkt_data_free(cdpa_pkt_t *pkt)
{
    AIM_ASSERT(pkt->data.data, "attempted to free NULL data");

    aim_free(pkt->data.data);
    pkt->data.data = NULL;
    pkt->data.bytes = 0;
}

/*
 * cdpa_port_disable
 *
 * Disable cdp on this port
 */
static indigo_error_t
cdpa_port_disable(ind_soc_timer_callback_f cb, cdpa_pkt_t *pkt,
                  cdpa_port_t *port)
{
    indigo_error_t rv;

    if ((rv = ind_soc_timer_event_unregister(cb, port)) == INDIGO_ERROR_NONE) {
        pkt->interval_ms = 0;
        cdpa_pkt_data_free(pkt);
    }
    return rv;
}

/*
 * cdpa_port_enable
 *
 * Enable cdp on this port
 */
static indigo_error_t
cdpa_port_enable(ind_soc_timer_callback_f cb, cdpa_pkt_t *pkt, cdpa_port_t *port,
                 of_octets_t *data, uint32_t interval_ms)
{
    indigo_error_t rv;

    pkt->data.data = aim_zmalloc(data->bytes);
    pkt->data.bytes = data->bytes;
    CDPA_MEMCPY(pkt->data.data, data->data, data->bytes);

    if ((rv = ind_soc_timer_event_register_with_priority(cb, port, interval_ms,
        IND_SOC_HIGH_PRIORITY)) == INDIGO_ERROR_NONE) {
        pkt->interval_ms = interval_ms;
    } else {
        cdpa_pkt_data_free(pkt);
    }
    return rv;
}

/*
 * cdpa_timeout_rx
 *
 * Handler function for rx timeout
 */
static void
cdpa_timeout_rx(void *cookie)
{
    uint32_t version;
    cdpa_port_t *port = (cdpa_port_t*) cookie;
    of_bsn_pdu_rx_timeout_t *timeout_msg = NULL;

    AIM_ASSERT(port, "NULL cookie in rx timeout handler");

    if (indigo_cxn_get_async_version(&version) != INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("No controller connected");
        return;
    }

    timeout_msg = of_bsn_pdu_rx_timeout_new(version);
    if (!timeout_msg){
        AIM_LOG_INTERNAL("Failed to allocate timeout msg");
        return;
    }

    /* Set port number */
    of_bsn_pdu_rx_timeout_port_no_set(timeout_msg, port->port_no);

    /* Set slot number */
    of_bsn_pdu_rx_timeout_slot_num_set(timeout_msg, CDP_SLOT_NUM);

    AIM_LOG_TRACE("Send rx timeout async msg");

    /* Send to controller, don't delete when send to controller */
    indigo_cxn_send_async_message(timeout_msg);

    port->timeout_pkt_cnt++;
}

/*
 * rx_request_handle
 *
 * Handle rx request msg
 */
static void
rx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req)
{
    /* rx_req info */
    uint32_t     xid;
    of_port_no_t port_no;
    uint32_t     timeout_ms;
    of_octets_t  data;

    of_bsn_pdu_rx_reply_t *rx_reply = NULL;
    uint32_t              status_failed = 0;

    /* Get rx req info */
    of_bsn_pdu_rx_request_xid_get(rx_req, &xid);
    of_bsn_pdu_rx_request_timeout_ms_get(rx_req, &timeout_ms);
    of_bsn_pdu_rx_request_data_get(rx_req, &data);
    of_bsn_pdu_rx_request_port_no_get(rx_req, &port_no);

    AIM_LOG_TRACE("Received %s Controller msg with cxn: %u",
                  of_object_id_str[rx_req->object_id], cxn_id);

    if (timeout_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Rx Port %u, inconsistent info", port_no);
        goto rx_reply_to_ctrl;
    }

    cdpa_port_t *port = NULL;
    if (!(port = cdpa_find_port(port_no))) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
        goto rx_reply_to_ctrl;
    }

    port->rx_req_cnt++;

    /* 1. Unreg timer, delete the current rx_pkt */
    indigo_error_t rv;
    if (port->rx_pkt.interval_ms) {
        if ((rv = cdpa_port_disable(cdpa_timeout_rx, &port->rx_pkt, port))
            != INDIGO_ERROR_NONE) {
            status_failed = 1;
            AIM_LOG_ERROR("Port rx %u failed to disable %s", port_no,
                          indigo_strerror(rv));
            goto rx_reply_to_ctrl;
        }
    }

    AIM_TRUE_OR_DIE(!port->rx_pkt.interval_ms && !port->rx_pkt.data.data);

    /* 2. Set up new rx_pkt, timer */
    if (timeout_ms) {
        if ((rv = cdpa_port_enable(cdpa_timeout_rx, &port->rx_pkt, port,
                                   &data, timeout_ms)) != INDIGO_ERROR_NONE) {
            status_failed = 1;
            AIM_LOG_ERROR("Port rx %u failed to enable %s", port_no,
                          indigo_strerror(rv));
        }
    }

rx_reply_to_ctrl:
    /* 3. Setup reply */
    rx_reply = of_bsn_pdu_rx_reply_new(rx_req->version);
    if (!rx_reply){
        AIM_LOG_INTERNAL("Failed to allocate rx_reply");
        return;
    }
    of_bsn_pdu_rx_reply_xid_set(rx_reply, xid);
    of_bsn_pdu_rx_reply_port_no_set(rx_reply, port_no);
    of_bsn_pdu_rx_reply_status_set(rx_reply, status_failed);
    of_bsn_pdu_rx_reply_slot_num_set(rx_reply, CDP_SLOT_NUM);

    AIM_LOG_TRACE("Port %u: send a rx_reply to ctrl, status %s, version %u",
                  port_no, status_failed? "Failed":"Success", rx_req->version);
    /* 4. Send to controller, don't delete obj */
    indigo_cxn_send_controller_message(cxn_id, rx_reply);
}

/*
 * cdpa_periodic_tx
 *
 * Send cdp packets to the partner port
 */
static void
cdpa_periodic_tx(void *cookie)
{
    cdpa_port_t *port = (cdpa_port_t*) cookie;
    of_packet_out_t *pkt_out;
    of_list_action_t *list;
    of_action_output_t *action;
    int rv;

    /* Always use OF_VERSION_1_3 */
    uint32_t version = OF_VERSION_1_3;

    AIM_ASSERT(port, "attempted to send on a NULL port");

    pkt_out = of_packet_out_new (version);
    if (!pkt_out){
        AIM_LOG_INTERNAL("Failed to allocate packet out");
        return;
    }

    action = of_action_output_new(version);
    if (!action){
        of_packet_out_delete(pkt_out);
        AIM_LOG_INTERNAL("Failed to allocation action");
        return;
    }
    of_action_output_port_set(action, port->port_no);

    list = of_list_action_new(version);
    if (!list){
        of_packet_out_delete(pkt_out);
        of_object_delete(action);
        AIM_LOG_INTERNAL("Failed to allocate action list");
        return;
    }

    of_list_append(list, action);
    of_object_delete(action);

    rv = of_packet_out_actions_set(pkt_out, list);
    AIM_ASSERT(rv == 0);
    of_object_delete(list);

    if ((rv = of_packet_out_data_set(pkt_out, &port->tx_pkt.data))
        != OF_ERROR_NONE) {
        AIM_LOG_TRACE("Packet out failed to set data %d", rv);
        of_packet_out_delete(pkt_out);
        return;
    }

    AIM_LOG_TRACE("Port %u: fwd tx pkt out", port->port_no);

    if ((rv = indigo_fwd_packet_out(pkt_out)) == INDIGO_ERROR_NONE) {
        port->tx_pkt_out_cnt++;
        debug_counter_inc(&cdpa_system.debug_info.cdp_total_out_packets);
    } else {
        AIM_LOG_INTERNAL("Fwd pkt out failed %s", indigo_strerror(rv));
    }
    /* Fwding pkt out HAS to delete obj */
    of_packet_out_delete(pkt_out);
}

/*
 * tx_request_handle
 *
 * Handle tx request msg
 */
static void
tx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *tx_req)
{
    /* tx_req info */
    uint32_t     xid;
    of_port_no_t port_no;
    uint32_t     tx_interval_ms;
    of_octets_t  data;

    /* tx_reply info */
    of_bsn_pdu_tx_reply_t *tx_reply = NULL;
    uint32_t              status_failed = 0;

    /* Get tx req info */
    of_bsn_pdu_tx_request_xid_get           (tx_req, &xid);
    of_bsn_pdu_tx_request_tx_interval_ms_get(tx_req, &tx_interval_ms);
    of_bsn_pdu_tx_request_data_get          (tx_req, &data);
    of_bsn_pdu_tx_request_port_no_get       (tx_req, &port_no);

    AIM_LOG_TRACE("Received %s Controller msg with cxn: %u",
                  of_object_id_str[tx_req->object_id], cxn_id);

    if (tx_interval_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Req_Tx Port %u, Inconsistent info", port_no);
        goto tx_reply_to_ctrl;
    }

    cdpa_port_t *port = NULL;
    if (!(port = cdpa_find_port(port_no))) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
        goto tx_reply_to_ctrl;
    }

    port->tx_req_cnt++;

    /* 1. unreg old timer, delete old data */
    indigo_error_t rv;
    if (port->tx_pkt.interval_ms) {
        if ((rv = cdpa_port_disable(cdpa_periodic_tx, &port->tx_pkt, port))
            != INDIGO_ERROR_NONE) {
            status_failed = 1;
            AIM_LOG_ERROR("Port tx %u failed to disable %s", port->port_no,
                          indigo_strerror(rv));
            goto tx_reply_to_ctrl;
        }
    }

    AIM_TRUE_OR_DIE(!port->tx_pkt.interval_ms && !port->tx_pkt.data.data);

    /* 2. Set up new tx_pkt, alarm */
    if (tx_interval_ms) {
        if ((rv = cdpa_port_enable(cdpa_periodic_tx, &port->tx_pkt, port,
            &data, tx_interval_ms)) == INDIGO_ERROR_NONE) {
            /* Successfully enable, send one out immediately */
            cdpa_periodic_tx(port);
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("Port tx %u failed to enable %s", port->port_no,
                          indigo_strerror(rv));
        }
    }

tx_reply_to_ctrl:
    /* 3. Setup reply  */
    tx_reply = of_bsn_pdu_tx_reply_new(tx_req->version);
    if (!tx_reply){
        AIM_LOG_INTERNAL("Failed to allocate tx reply");
        return;
    }

    of_bsn_pdu_tx_reply_xid_set(tx_reply, xid);
    of_bsn_pdu_tx_reply_port_no_set(tx_reply, port_no);
    of_bsn_pdu_tx_reply_status_set(tx_reply, status_failed);
    of_bsn_pdu_tx_reply_slot_num_set(tx_reply, CDP_SLOT_NUM);

    AIM_LOG_TRACE("Port %u: send a tx_reply to ctrl, status %s version %u",
                  port_no, status_failed? "Failed":"Success", tx_req->version);
    /* 4. Send to controller, don't delete obj */
    indigo_cxn_send_controller_message(cxn_id, tx_reply);
}

/*
 * cdpa_handle_msg
 *
 * Handle incoming Controller msg's
 */
static indigo_core_listener_result_t
cdpa_handle_msg(indigo_cxn_id_t cxn_id, of_object_t *msg)
{
    indigo_core_listener_result_t ret = INDIGO_CORE_LISTENER_RESULT_PASS;
    uint8_t slot_num;

    if (!msg) {
        return ret;
    }

    if (!cdpa_initialized) {
        AIM_LOG_INTERNAL("CDPA module uninitalized");
        return ret;
    }

    switch (msg->object_id) {
    case OF_BSN_PDU_RX_REQUEST:

        /*
         * Cdp msg's will have slot_num 1
         */
        of_bsn_pdu_rx_request_slot_num_get(msg, &slot_num);
        if (slot_num != CDP_SLOT_NUM) {
            AIM_LOG_TRACE("Received rx request with slot_num: %u", slot_num);
            return ret;
        }

        debug_counter_inc(&cdpa_system.debug_info.cdp_total_rx_msgs);
        rx_request_handle(cxn_id, msg);
        ret = INDIGO_CORE_LISTENER_RESULT_DROP;
        break;

    case OF_BSN_PDU_TX_REQUEST:

        of_bsn_pdu_tx_request_slot_num_get(msg, &slot_num);
        if (slot_num != CDP_SLOT_NUM) {
            AIM_LOG_TRACE("Received tx request with slot_num: %u", slot_num);
            return ret;
        }

        debug_counter_inc(&cdpa_system.debug_info.cdp_total_tx_msgs);
        tx_request_handle(cxn_id, msg);
        ret = INDIGO_CORE_LISTENER_RESULT_DROP;
        break;

    default:
        break;
    }

    return ret;
}

/*
 * cdpa_rx_pkt_is_expected
 *
 * Match the incoming packet-in with expected data
 * return true if matched
 * else return false
 */
static inline bool
cdpa_rx_pkt_is_expected(cdpa_port_t *port, of_octets_t *data)
{
    bool ret = false;

    if (!port->rx_pkt.data.data) {
        AIM_LOG_TRACE("Port %u: MISMATCHED RX no data", port->port_no);
        port->rx_pkt_mismatched_no_data++;
        return ret;
    }

    if (port->rx_pkt.data.bytes != data->bytes) {
        AIM_LOG_TRACE("Port %u: MISMATCHED len exp=%u, rcv=%u",
                      port->port_no, port->rx_pkt.data.bytes, data->bytes);
        port->rx_pkt_mismatched_len++;
        return ret;
    }

    if (memcmp(port->rx_pkt.data.data, data->data, data->bytes) == 0) {
        AIM_LOG_TRACE("Port %u: MATCHED", port->port_no);
        ret = true;
        port->rx_pkt_matched++;
    } else {
        AIM_LOG_TRACE("Port %u: MISMATCHED data", port->port_no);
        port->rx_pkt_mismatched_data++;
    }

    return ret;
}

/*
 * cdpa_update_rx_timeout
 *
 * Reset rx timeout
 */
static inline void
cdpa_update_rx_timeout(cdpa_port_t *port)
{
    indigo_error_t rv;
    AIM_LOG_TRACE("Reset rx timer");
    if ((rv = ind_soc_timer_event_register_with_priority(cdpa_timeout_rx, port,
        port->rx_pkt.interval_ms, IND_SOC_HIGH_PRIORITY))
        != INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("Port %u failed to register %s", port->port_no,
                      indigo_strerror(rv));
    }
}

/*
 * cdpa_handle_pkt
 *
 * API for handling incoming port packets
 */
indigo_core_listener_result_t
cdpa_handle_pkt(of_packet_in_t *packet_in)
{
    cdpa_port_t                *port = NULL;
    of_octets_t                data;
    of_port_no_t               port_no;
    of_match_t                 match;
    indigo_core_listener_result_t ret = INDIGO_CORE_LISTENER_RESULT_PASS;

    if (!packet_in) {
        return ret;
    }

    /* Data is the ether pkt */
    of_packet_in_data_get(packet_in, &data);
    if (!data.data) {
        return ret;
    }

    if (packet_in->version <= OF_VERSION_1_1) {
        of_packet_in_in_port_get(packet_in, &port_no);
        AIM_LOG_TRACE("port %u pkt in version %d", port_no, packet_in->version);
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_INTERNAL("match get failed");
            return ret;
        }
        port_no = match.fields.in_port;
        AIM_LOG_TRACE("Port %u", port_no);
    }

    port = cdpa_find_port(port_no);
    if (!port) {
        return ret;
    }

    port->rx_pkt_in_cnt++;

    /* At this step we will process the packet-in
     * 1. Port doesn't have data, won't expect any packet
     * 2. If same as expected, reset the timeout
     * 3. If not, it's automatically PASSED to the controller
     *    as a packet-in
     */
    if (cdpa_rx_pkt_is_expected(port, &data)) {
        ret = INDIGO_CORE_LISTENER_RESULT_DROP;
        cdpa_update_rx_timeout(port);
        /* Only count valid cdp pkt_in's */
        debug_counter_inc(&cdpa_system.debug_info.cdp_total_in_packets);
    }

    return ret;
}

/*
 * cdpa_register_system_counters
 *
 * Register system debug counters
 */
static inline void
cdpa_register_system_counters(void)
{
    debug_counter_register(&cdpa_system.debug_info.cdp_total_in_packets,
                           "cdpa.total_in_packets",
                           "Packet-ins recv'd by cdpa");
    debug_counter_register(&cdpa_system.debug_info.cdp_total_out_packets,
                           "cdpa.total_out_packets",
                           "Cdp packets sent by cdpa");
    debug_counter_register(&cdpa_system.debug_info.cdp_total_rx_msgs,
                           "cdpa.total_rx_msgs",
                           "Rx request msgs recv'd by cdpa");
    debug_counter_register(&cdpa_system.debug_info.cdp_total_tx_msgs,
                           "cdpa.total_tx_msgs",
                           "Tx request msgs recv'd by cdpa");
}

/*
 * cdpa_unregister_system_counters
 *
 * Unregister system debug counters
 */
static inline void
cdpa_unregister_system_counters(void)
{
    debug_counter_unregister(&cdpa_system.debug_info.cdp_total_in_packets);
    debug_counter_unregister(&cdpa_system.debug_info.cdp_total_out_packets);
    debug_counter_unregister(&cdpa_system.debug_info.cdp_total_rx_msgs);
    debug_counter_unregister(&cdpa_system.debug_info.cdp_total_tx_msgs);
}

/*
 * cdpa_disable_tx_rx
 *
 * Unregister timer and free data
 */
static void
cdpa_disable_tx_rx(cdpa_port_t *port)
{
    indigo_error_t rv;

    if (port->tx_pkt.interval_ms) {
        if ((rv = cdpa_port_disable(cdpa_periodic_tx, &port->tx_pkt, port))
            != INDIGO_ERROR_NONE) {
            AIM_LOG_ERROR("Port tx %u failed to disable %s", port->port_no,
                          indigo_strerror(rv));
        }
    }

    if (port->rx_pkt.interval_ms) {
        if ((rv = cdpa_port_disable(cdpa_timeout_rx, &port->rx_pkt, port))
            != INDIGO_ERROR_NONE) {
            AIM_LOG_ERROR("Port rx %u failed to disable %s", port->port_no,
                          indigo_strerror(rv));
        }
    }
}

/*
 * cdpa_init
 *
 * API to init the CDP Agent
 * This should only be done once at the beginning.
 */
indigo_error_t
cdpa_init(void)
{
    int i;
    cdpa_port_t *port;

    if (cdpa_initialized) return INDIGO_ERROR_NONE;

    AIM_LOG_TRACE("init");

    indigo_core_message_listener_register(cdpa_handle_msg);
    indigo_core_packet_in_listener_register(cdpa_handle_pkt);

    CDPA_MEMSET(cdpa_system.ports, 0,
                sizeof(cdpa_port_t) * (CDPA_CONFIG_OF_PORTS_MAX+1));
    for (i=0; i <= CDPA_CONFIG_OF_PORTS_MAX; i++) {
        port = cdpa_find_port(i);
        port->port_no = i;
    }

    cdpa_register_system_counters();
    cdpa_initialized = true;

    return INDIGO_ERROR_NONE;
}

/*
 * cdpa_finish
 *
 * API to deinit the CDP Agent
 */
void
cdpa_finish()
{
    int i;
    cdpa_port_t *port;

    indigo_core_message_listener_unregister(cdpa_handle_msg);
    indigo_core_packet_in_listener_unregister(cdpa_handle_pkt);

    for (i=0; i < CDPA_CONFIG_OF_PORTS_MAX; i++) {
        port = cdpa_find_port(i);
        cdpa_disable_tx_rx(port);
    }

    cdpa_unregister_system_counters();
    cdpa_initialized = false;
}
