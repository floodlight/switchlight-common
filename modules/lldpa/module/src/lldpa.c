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

static lldpa_port_t* lldpa_find_port(of_port_no_t port_no);
static int  lldpa_pkt_data_set(lldpa_pkt_t *lpkt, of_octets_t *data);
static void lldpa_pkt_data_free (lldpa_pkt_t *lpkt);
static void  lldpa_free_pkts(lldpa_port_t* lldpa);
static void lldpdu_timeout_rx(void *cookie);
static void lldpdu_periodic_tx(void *cookie);
static void rx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req);
static void tx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req);

static void lldpdu_periodic_tx(void *cookie);
static void lldpdu_timeout_rx(void *cookie);

#define LLDPA_DEBUG(fmt, ...)                       \
            AIM_LOG_TRACE(fmt, ##__VA_ARGS__)

lldpa_sys_fn_t lldpa_sys;
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
static int
lldpa_pkt_data_set(lldpa_pkt_t *lpkt, of_octets_t *data)
{
    int ret = -1;

    if(!lpkt || !data)
        return ret;

    if (lpkt->data.data) {
        ret = -2;
    } else {
        lpkt->data.data = LLDPA_MALLOC(data->bytes);
        if (lpkt->data.data) {
            lpkt->data.bytes = data->bytes;
            LLDPA_MEMCPY(lpkt->data.data, data->data, data->bytes);
            ret = 0;
        }
    }
    return ret;
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
lldpa_free_pkts(lldpa_port_t* lldpa)
{
    if (!lldpa)
        return;

    if (lldpa->tx_pkt.interval_ms) {
        ind_soc_timer_event_unregister(lldpdu_periodic_tx, lldpa);
        lldpa->tx_pkt.interval_ms = 0;
    }

    if (lldpa->rx_pkt.interval_ms) {
        ind_soc_timer_event_unregister(lldpdu_timeout_rx, lldpa);
        lldpa->rx_pkt.interval_ms = 0;
    }

    lldpa_pkt_data_free(&lldpa->rx_pkt);
    lldpa_pkt_data_free(&lldpa->tx_pkt);

    return;
}

static void
lldpdu_timeout_rx(void *cookie)
{
    uint32_t version;
    lldpa_port_t* lldpa = (lldpa_port_t*) cookie;
    of_bsn_pdu_rx_timeout_t *to_pkt = NULL;

    if (!lldpa)
        return;

    if (lldpa_sys.get_async_version(&version) < 0) {
        AIM_LOG_ERROR("%s: No controller connected",__FUNCTION__);
        return;
    }

    if (version != lldpa->version) {
        AIM_LOG_INFO("Controller cxn version change %u->%u",
                    lldpa->version, version);
    }

    to_pkt = of_bsn_pdu_rx_timeout_new(lldpa->version);
    if(!to_pkt){
        AIM_LOG_ERROR("%s:%d OOM",__FILE__,__LINE__);
        return;
    }

    /* Set subtype */
    of_bsn_pdu_rx_timeout_port_no_set (to_pkt, lldpa->port_no);

    LLDPA_DEBUG("%s:%d: send async version %u",__FUNCTION__,__LINE__,lldpa->version);
    /* Send to controller, don't delete when send to controller */
    lldpa_sys.send_async_message(to_pkt);

    lldpa->timeout_pkt_cnt++;

    return;
}

static void
lldpdu_periodic_tx(void *cookie)
{
    lldpa_port_t* lldpa = (lldpa_port_t*) cookie;
    of_packet_out_t *pkt_out;
    of_list_action_t   *list;
    of_action_output_t *action;
    indigo_error_t     rv;

    if(!lldpa)
        return;

    pkt_out = of_packet_out_new (lldpa->version);
    if(!pkt_out){
        AIM_LOG_ERROR("%s:%d OOM",__FILE__,__LINE__);
        return;
    }

    list = of_list_action_new(lldpa->version);
    if(!list){
        AIM_LOG_ERROR("%s:%d OOM",__FILE__,__LINE__);
        return;
    }

    action = of_action_output_new(lldpa->version);
    if(!action){
        AIM_LOG_ERROR("%s:%d OOM",__FILE__,__LINE__);
        return;
    }

    of_action_output_port_set(action, lldpa->port_no);
    of_list_append(list, action);
    of_object_delete(action);

    rv = of_packet_out_actions_set(pkt_out, list);
    of_object_delete(list);

    if (of_packet_out_data_set(pkt_out, &lldpa->tx_pkt.data) < 0) {
        AIM_LOG_TRACE("LLDPA %d",rv);
        of_packet_out_delete(pkt_out);
        return;
    }

    LLDPA_DEBUG("%s:%d: fwd version %u",__FUNCTION__,__LINE__,lldpa->version);

    if ((rv = lldpa_sys.fwd_packet_out(pkt_out)) == INDIGO_ERROR_NONE)
        lldpa->tx_pkt_out_cnt++;
    else {
        AIM_LOG_ERROR("%s:%d Fwd pkt out failed",__FILE__,__LINE__);
    }
    /* Fwding pkt out HAS to delete obj */
    of_packet_out_delete(pkt_out);
}

static void
rx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *rx_req)
{
    lldpa_port_t* lldpa = NULL;
    int           rv;

    /* rx_req info */
    uint32_t     xid;
    uint32_t     subtype;
    of_port_no_t port_no;
    uint32_t     timeout_ms;
    of_octets_t  data;

    of_bsn_pdu_rx_reply_t *rx_reply = NULL;
    uint32_t              status_failed = 0;

    /* Get rx req info */
    of_bsn_pdu_rx_request_subtype_get(rx_req, &subtype);
    of_bsn_pdu_rx_request_xid_get       (rx_req, &xid);
    of_bsn_pdu_rx_request_timeout_ms_get(rx_req, &timeout_ms);
    of_bsn_pdu_rx_request_data_get      (rx_req, &data);
    of_bsn_pdu_rx_request_port_no_get(rx_req, &port_no);

    /* Legality check */
    if (subtype != LLDPA_CONTR_STYPE_RX_REQ ) {
        status_failed = 1;
        AIM_LOG_ERROR("Unsupported subtype %", subtype);
    }

    if (timeout_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Inconsistent info");
    }

    if (!(lldpa = lldpa_find_port(port_no))) {
        status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
    }

    /* 1. Unreg timer, delete the current rx_pkt */
    if (!status_failed) {
        lldpa->version = rx_req->version;
        if(lldpa->rx_pkt.interval_ms) {
            if (lldpa_sys.timer_event_unregister(lldpdu_timeout_rx, lldpa)
                == INDIGO_ERROR_NONE) {
                lldpa->rx_pkt.interval_ms = 0;
                lldpa_pkt_data_free(&lldpa->rx_pkt);
            } else {
                status_failed = 1;
                AIM_LOG_ERROR("Non-exist timer");
            }
        }
    }

    /* Additional consistent state check */
    if (!status_failed && (lldpa->rx_pkt.interval_ms || lldpa->rx_pkt.data.data)) {
        AIM_LOG_ERROR("Port state inconsistent");
        status_failed = 1;
    }

    /* 2. Set up new rx_pkt, timer */
    if(!status_failed && timeout_ms) {
        if (!(rv = lldpa_pkt_data_set(&lldpa->rx_pkt, &data))) {
            if (lldpa_sys.timer_event_register(lldpdu_timeout_rx, lldpa, timeout_ms)
                == INDIGO_ERROR_NONE) {
                lldpa->rx_pkt.interval_ms = timeout_ms;
                /* When it reaches here: success */
            } else {
                status_failed = 1;
                lldpa_pkt_data_free(&lldpa->rx_pkt);
                AIM_LOG_ERROR("timer event register failed %s:%d",__FILE__,__LINE__);
            }
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("%s:%d data set failed rv %d",__FILE__,__LINE__,rv);
        }
    }

    /* 3. Setup reply */
    rx_reply = of_bsn_pdu_rx_reply_new(rx_req->version);
    if(!rx_reply){
        AIM_LOG_ERROR("OOM %s:%d",__FILE__,__LINE__);
        return;
    }
    of_bsn_pdu_rx_reply_xid_set     (rx_reply, xid);
    of_bsn_pdu_rx_reply_port_no_set (rx_reply, port_no);
    of_bsn_pdu_rx_reply_status_set  (rx_reply, status_failed);

    LLDPA_DEBUG("%s:%d: send reply version %u",__FUNCTION__,__LINE__,lldpa->version);
    /* 4. Send to controller, don't delete obj */
    lldpa_sys.send_controller_message(cxn_id, rx_reply);

    return;
}


static void
tx_request_handle(indigo_cxn_id_t cxn_id, of_object_t *tx_req)
{
    lldpa_port_t* lldpa = NULL;

    int rv;

    /* tx_req info */
    uint32_t     xid;
	of_port_no_t port_no;
	uint32_t     tx_interval_ms;
	uint32_t     subtype;
	of_octets_t  data;

	/* tx_reply info */
	of_bsn_pdu_tx_reply_t *tx_reply = NULL;
	uint32_t              status_failed = 0;

	/* Get tx req info */
	of_bsn_pdu_tx_request_subtype_get       (tx_req, &subtype);
    of_bsn_pdu_tx_request_xid_get           (tx_req, &xid);
    of_bsn_pdu_tx_request_tx_interval_ms_get(tx_req, &tx_interval_ms);
    of_bsn_pdu_tx_request_data_get          (tx_req, &data);
    of_bsn_pdu_tx_request_port_no_get       (tx_req, &port_no);

    /* Legality check */
    if (subtype != LLDPA_CONTR_STYPE_TX_REQ ) {
        status_failed = 1;
        AIM_LOG_ERROR("Unsupported subtype %u", subtype);
    }

    if (tx_interval_ms && !data.data) {
        status_failed = 1;
        AIM_LOG_ERROR("Inconsistent info");
    }

	if (!(lldpa = lldpa_find_port(port_no))) {
	    status_failed = 1;
        AIM_LOG_ERROR("Port %u doesn't exist", port_no);
	}

	/* 1. unreg old timer, delete old data */
    if (!status_failed) {
        lldpa->version = tx_req->version;
        if (lldpa->tx_pkt.interval_ms) {
            if (lldpa_sys.timer_event_unregister(lldpdu_periodic_tx, lldpa)
                == INDIGO_ERROR_NONE) {
                lldpa->tx_pkt.interval_ms = 0;
                lldpa_pkt_data_free(&lldpa->tx_pkt);
            } else {
                status_failed = 1;
                AIM_LOG_ERROR("Non-exist timer");
            }
        }
    }

    /* Additional consistent state check */
    if (!status_failed && (lldpa->tx_pkt.interval_ms || lldpa->tx_pkt.data.data)) {
        AIM_LOG_ERROR("Port state inconsistent");
        status_failed = 1;
    }

	/* 2. Set up new tx_pkt, alarm */
	if(!status_failed && tx_interval_ms) {
	    if (!(rv=lldpa_pkt_data_set(&lldpa->tx_pkt, &data))) {
            /* Send one immediately */
            lldpdu_periodic_tx(lldpa);
            if (lldpa_sys.timer_event_register(lldpdu_periodic_tx, lldpa, tx_interval_ms)
                    == INDIGO_ERROR_NONE) {
                lldpa->tx_pkt.interval_ms = tx_interval_ms;
                /* When it reaches here: success */
            } else {
                status_failed = 1;
                lldpa_pkt_data_free(&lldpa->tx_pkt);
                AIM_LOG_ERROR("timer event register failed %s:%d",__FILE__,__LINE__);
            }
        } else {
            status_failed = 1;
            AIM_LOG_ERROR("%s:%d data set failed rv %d",__FILE__,__LINE__,rv);
        }
	}

	/* 3. Setup reply  */
	tx_reply = of_bsn_pdu_tx_reply_new(tx_req->version);
	if(!tx_reply){
	    AIM_LOG_ERROR("OOM %s:%d",__FILE__,__LINE__);
	    return;
	}

	of_bsn_pdu_tx_reply_xid_set     (tx_reply, xid);
	of_bsn_pdu_tx_reply_port_no_set (tx_reply, port_no);
	of_bsn_pdu_tx_reply_status_set  (tx_reply, status_failed);

	LLDPA_DEBUG("%s:%d: send reply version %u",__FUNCTION__,__LINE__,tx_req->version);
	/* 4. Send to controller, don't delete obj */
	lldpa_sys.send_controller_message(cxn_id, tx_reply);

	return;
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
lldpa_rx_pkt_is_expected(lldpa_port_t* lldpa, of_octets_t* data)
{
    int ret = 0;

    if (lldpa->rx_pkt.data.data &&
            (lldpa->rx_pkt.data.bytes == data->bytes))
        if (memcmp(lldpa->rx_pkt.data.data, data->data, data->bytes) == 0)
            ret = 1;

    return ret;
}

/*
 * Caller must ensure lldap != NULL
 * Reset timeout
 * */
static inline void
lldpa_update_rx_timeout(lldpa_port_t* lldpa)
{
    LLDPA_DEBUG("%s:%d using reset timer",__FUNCTION__,__LINE__);
    if (lldpa_sys.timer_event_register(lldpdu_timeout_rx, lldpa, lldpa->rx_pkt.interval_ms) !=
            INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("%s:%d timer register failed",__FUNCTION__,__LINE__);
    }
}

/* Register to listen to PACKETIN msg */
ind_core_listener_result_t
lldpa_handle_pkt (of_packet_in_t *packet_in)
{
    lldpa_port_t               *lldpa = NULL;
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

    lldpa = lldpa_find_port(port_no);
    if (!lldpa) {
        AIM_LOG_ERROR("LLDPA port out of range %u", port_no);
        return ret;
    }

    lldpa->rx_pkt_in_cnt++;

    /* At this step we will process the LLDP packet
     * 0. Port doesn't have data, won't expect any packet
     * 1. If expected, reset the timeout
     * 2. If not, it's automatically PASSED to the controller
     *    as a packet-in
     */
    if (lldpa_rx_pkt_is_expected(lldpa, &data)) {
        ret = IND_CORE_LISTENER_RESULT_DROP;
        lldpa_update_rx_timeout(lldpa);
    }

    LLDPA_DEBUG("%s:%d: port %u, rx_pkt_in_cnt %l, pkt MATCH=%s",__FUNCTION__,__LINE__,port_no,
            lldpa->rx_pkt_in_cnt, ret == IND_CORE_LISTENER_RESULT_DROP ? "true" : "false");
    return ret;
}


/************************
 * LLDAP INIT and FINISH
 ************************/

/* Return 0: success */
int
lldpa_system_init(lldpa_sys_fn_t *fn)
{
    int i;
    lldpa_port_t *lldpa;

    AIM_LOG_INFO("init");

    lldpa_sys.send_controller_message = fn->send_controller_message; //void indigo_cxn_send_controller_message();
    lldpa_sys.fwd_packet_out          = fn->fwd_packet_out;          //indigo_error_t indigo_fwd_packet_out();
    lldpa_sys.send_async_message      = fn->send_async_message;      //void indigo_cxn_send_async_message();
    lldpa_sys.get_async_version       = fn->get_async_version;       //indigo_error_t indigo_cxn_get_async_version();
    lldpa_sys.timer_event_register    = fn->timer_event_register;    //indigo_error_t ind_soc_timer_event_register();
    lldpa_sys.timer_event_unregister  = fn->timer_event_unregister;  //indigo_error_t ind_soc_timer_event_register();
    AIM_TRUE_OR_DIE(lldpa_sys.send_controller_message);
    AIM_TRUE_OR_DIE(lldpa_sys.fwd_packet_out);
    AIM_TRUE_OR_DIE(lldpa_sys.get_async_version);
    AIM_TRUE_OR_DIE(lldpa_sys.send_async_message);
    AIM_TRUE_OR_DIE(lldpa_sys.timer_event_register);
    AIM_TRUE_OR_DIE(lldpa_sys.timer_event_unregister);
    lldpa_port_sys.lldpa_total_phy_ports = MAX_LLDPA_PORT;
    for (i=0; i<MAX_LLDPA_PORT;i++) {
        lldpa = lldpa_find_port(i);
        if (lldpa)
            lldpa->port_no = i;
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
    lldpa_port_t *lldpa;

    ind_core_message_listener_unregister(lldpa_handle_msg);
    ind_core_packet_in_listener_unregister(lldpa_handle_pkt);

    for (i=0; i<MAX_LLDPA_PORT;i++) {
        lldpa = lldpa_find_port(i);
        if (lldpa)
            lldpa_free_pkts(lldpa);
        else
            AIM_LOG_ERROR("Port %d not existing", i);
    }

    return;
}
