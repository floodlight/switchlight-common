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

#define AIM_LOG_MODULE_NAME lldpa
#include <AIM/aim_log.h>

#include <lldpa/lldpa.h>
static void lldpa_pkt_buf_free (lldpa_pkt_t *lpkt);
static lldpa_pkt_t* lldpa_port_get_lpkt(lldpa_port_t* lldpa, lldpa_pkt_type ptype);
static int lldpa_port_set_pkt(lldpa_port_t* lldpa, lldpa_pkt_type ptype, void* buf, int len);
static int lldpa_port_alarm_register(lldpa_port_t* lldpa, lldpa_pkt_type ptype, uint32_t interval_ms);
static int lldpa_port_tx (void* args); //Callback to transmit TX packet
static int lldpa_port_rx_check (void* args); //In X sec, not rec expected message, then send pkt to ctrl
static of_bsn_header_t * lldpa_gen_msg_reply (lldpa_contr_stype stype, int status, void *bufp, uint32_t len);


static void
lldpa_pkt_buf_free (lldpa_pkt_t *lpkt)
{
    if (lpkt) {
        free(lpkt->pdata);
        lpkt->pdata = NULL;
        lpkt->len  = 0;
    }
}

/* Get rx_pkt or tx_pkt */
static lldpa_pkt_t*
lldpa_port_get_lpkt(lldpa_port_t* lldpa, lldpa_pkt_type ptype)
{
    lldpa_pkt_t* ret = NULL;
    if (ptype == RX_PACKET) {
        ret = &lldpa->rx_pkt;
    } else if (ptype == TX_PACKET)  {
        ret = &lldpa->tx_pkt;
    } else {
        AIM_LOG_FATAL("get_lpkt: Unsupported pkt type %s", ptype);
    }
    return ret;
}

/*
 * Call must free 'buf' if this return -1 (failure)
 * This function frees an current pkt if necesary
 * Return -1 if can't set
 */
static int
lldpa_port_set_pkt(lldpa_port_t* lldpa, lldpa_pkt_type ptype,
                   void* buf, int len)
{
    int error_ret = -1;

    lldpa_pkt_t *lpkt = NULL;

    lpkt = lldpa_port_get_lpkt(lldpa, ptype);

    /*
     * Can't set pkt if tx_alarm_id is on
     * Avoid possible race condition??
     * What if we delete current pkt and SIGALRM call
     * Alarm will execute the old one
     */
    if (lpkt->alarm_id)
        return error_ret;

    lldpa_pkt_buf_free(lpkt);

    /* return if len is 0 */
    if (!len)
        return 0;

    lpkt->pdata = (octets_t*) malloc(len);
    if (!lpkt->pdata)
        return error_ret;

    lpkt->len = len;
    memcpy (lpkt->pdata, buf, len);

    printf("port_set_pkt ok = %u\n", lpkt->alarm_id);
    return 0;
}

/*
 * Always unregister old one
 * Only register new one if interval > 0
 * Return -1 if new one can't be registered
 */
static int
lldpa_port_alarm_register(lldpa_port_t* lldpa, lldpa_pkt_type ptype, uint32_t interval_ms)
{
    //Always SA_REPEAT Until Unregistered
    unsigned int flags = 0x1;
    int ret = 0;
    lldpa_pkt_t *pkt;

    if(!os_alarm_register_fn || !os_alarm_unregister_fn){
        AIM_LOG_FATAL("NO_EVEN_REGISTER\n");
        return -1;
    }
    pkt = lldpa_port_get_lpkt(lldpa, ptype);

    /* Always unregister old one */
    if(pkt->alarm_id) {
        os_alarm_unregister_fn(pkt->alarm_id);
        pkt->alarm_id = 0;
        pkt->interval_ms = 0;
    }

    pkt->interval_ms = interval_ms;

    if (interval_ms > 0) {
        pkt->alarm_id = os_alarm_register_fn(interval_ms, flags, pkt->alarm_cb, lldpa);
        if (!pkt->alarm_id) {
             pkt->interval_ms = 0;
            ret = -1;
        }
    }
    return ret;
}

/*
 * Alarm Callback function: for TX_REQ
 * Transmit port info to peer
 */
static int
lldpa_port_tx (void* args)
{
    int ret = 0;
    lldpa_port_t* lldpa = (lldpa_port_t*) args;
    AIM_LOG_INFO("tx_pkt_call");
    if (lldpa->tx_fn) {
        ret = (*(lldpa->tx_fn))(lldpa->tx_pkt.pdata,
                                lldpa->tx_pkt.len,
                                lldpa->port_no);
    }
    return ret;
}

/*
 * Alarm Callback function: for RX_REQ
 * Check the lldp discovery expected - If not, generate a message
 */
static int
lldpa_port_rx_check (void* args)
{
    int ret = 0;
    of_bsn_header_t *hdr = NULL;
    int status = 0;
    lldpa_port_t* lldpa = (lldpa_port_t*) args;
    AIM_LOG_INFO("RX CHECK");
    if (lldpa->rx_pkt_matched) {
        AIM_LOG_INFO("RX CHECK: RESET");
        lldpa->rx_pkt_matched = 0;
    } else {
        AIM_LOG_INFO("RX CHECK: CTRL SEND");
        hdr = lldpa_gen_msg_reply(SW_CONTR_TIMEOUT, status, NULL, 0);
        hdr->port_no = lldpa->port_no;
        if (lldpa->tx_ctrl_fn)
            (*lldpa->tx_ctrl_fn)(hdr, hdr->length, os_ctrl_cxn_id);
        free(hdr);
    }
    return ret;
}

/*
 * Initialize port_no and alarm_cb for tx and rx_check
 * Return NULL if it failed
 */
lldpa_port_t*
lldpa_port_create(int portno)
{
    lldpa_port_t* rport;
    rport = (lldpa_port_t*) malloc(sizeof(lldpa_port_t));
    if (rport) {
        bzero(rport, sizeof(lldpa_port_t));
        rport->port_no = portno;
        rport->rx_pkt.alarm_cb = lldpa_port_rx_check;
        rport->tx_pkt.alarm_cb = lldpa_port_tx;
    }
    return rport;
}

/*
 * If alarm is registered, can't destroy it
 * Use force = 1 to force unregister alarm
 */
int
lldpa_port_free(lldpa_port_t* lldpa, int force)
{
    if (lldpa->rx_pkt.alarm_id || lldpa->tx_pkt.alarm_id ) {
        if (force) {
            lldpa_port_alarm_register(lldpa, TX_PACKET, ALARM_UNREGISTER);
            lldpa_port_alarm_register(lldpa, RX_PACKET, ALARM_UNREGISTER);
        } else
            return -1;
    }

    lldpa_pkt_buf_free(&lldpa->rx_pkt);
    lldpa_pkt_buf_free(&lldpa->tx_pkt);
    free(lldpa);
    return 0;
}

/* Set a transmit function */
void
lldpa_port_set_fwd_pkt_fn(lldpa_port_t* lldpa, tx_fn_t* tx_fn)
{
    lldpa->tx_fn = tx_fn;
}

void
lldpa_port_set_snd_ctrl_msg_fn(lldpa_port_t* lldpa, tx_fn_t* tx_fn)
{
    lldpa->tx_ctrl_fn = tx_fn;
}

/*
 * Processing receive pkt from outside world
 * If matched
 *    -- return 0
 * Else return 1: No match Caller will forward a packet to the controller
 */
int
lldpa_port_rx_matched (lldpa_port_t *lldpa, void* buf, uint32_t len)
{
    int ret = 1;
    lldpa->rx_pkt_matched = 0;

    /* Check the len for a quick comparision */
    if (lldpa->rx_pkt.len == len) {
        if (!(ret = memcmp(lldpa->rx_pkt.pdata, buf, len))) {
            lldpa->rx_pkt_matched = 1;
        }
    }
    return ret;
}


/* ENTRY POINT: handle receive packet from Controller
 * msg will be freed by caller. Do copy as necessary.
 */
void
lldpa_agent_handle_msg(lldpa_port_t* lldpa, void* msg)
{
    int status = -1;
    of_bsn_header_t *hdr = (of_bsn_header_t *)msg;
    lldpa_pkt_type ptype = INVALID_PACKET;
    lldpa_contr_stype stype = SW_CONTR_INVALID;
    lldpa_pkt_t *lpkt = NULL;

    if (hdr->subtype == SW_CONTR_TX_REQ) {
        ptype = TX_PACKET;
        stype = SW_CONTR_TX_RES;
    } else if (hdr->subtype == SW_CONTR_RX_REQ) {
        /* Got new matched request - Reset matched */
        lldpa->rx_pkt_matched = 0;
        ptype = RX_PACKET;
        stype = SW_CONTR_RX_RES;
    } else {
        AIM_LOG_FATAL("Unsupported msg type %u", ptype);
    }

    /* Processing packet
     * if interval > 0, clear old alarm, free current pkt, set new pkt & new alarm
     *    interval == 0, clear old alarm, free current pkt
     * Ret = -1: Error can't handle request
     */
    if (ptype != INVALID_PACKET ) {
        status = 0;
        lldpa_port_alarm_register(lldpa, ptype, ALARM_UNREGISTER);
        lpkt = lldpa_port_get_lpkt(lldpa, ptype);
        lldpa_pkt_buf_free(lpkt);

        if (hdr->interval_ms) {
            /*  &hdr->payload might be null */
            if ((status = lldpa_port_set_pkt(lldpa, ptype, &hdr->payload,
                                             hdr->length-sizeof(of_bsn_header_t))) == -1) {
                AIM_LOG_FATAL("Failed to set pkt type %u", ptype);
            } else {
                status = lldpa_port_alarm_register(lldpa, ptype, hdr->interval_ms);
            }
        }
    }

    /* Always generatate a new header base on old hdr to reply */
    hdr = lldpa_gen_msg_reply(stype, status, hdr, hdr->length);
    if (lldpa->tx_ctrl_fn)
        (*lldpa->tx_ctrl_fn)(hdr, hdr->length, os_ctrl_cxn_id);
    free(hdr);
}

/*
 * ENTRY POINT: handle receive packet from Open Flow Port
 * if pkt matched, reset timeout
 * else forward to lldp_port_tx_to_controller
 */
void
lldpa_agent_handle_pkt (lldpa_port_t *lldpa, void* buf, uint32_t len)
{
    int status = 0;
    of_bsn_header_t *hdr = NULL;

    if (!lldpa_port_rx_matched (lldpa, buf, len)) {
        /*
         * Every time receving new matched message:
         * Does Update timestamp mean: reset alarm???
         */
    } else {
        //Send packet-in to controller
        hdr = lldpa_gen_msg_reply(SW_CONTR_PACKET_IN, status, buf, len);
        hdr->port_no = lldpa->port_no;
        if( lldpa->tx_ctrl_fn)
            (*lldpa->tx_ctrl_fn)(hdr, hdr->length, os_ctrl_cxn_id);
        free(hdr);
    }
}

/*
 * Create hdr buffer to send to CTRL
 * Only allocate new buf if *bufp == NULL
 * Who call this, must free bufp
 * len is sizeof *bufp
 */
static of_bsn_header_t *
lldpa_gen_msg_reply (lldpa_contr_stype stype, int status, void *bufp, uint32_t len)
{
    of_bsn_header_t *hdr = NULL;
    if(stype != SW_CONTR_PACKET_IN) {
        /* TX_RES, RX_RES, TIMEOUT */
        hdr = (of_bsn_header_t*) malloc(sizeof(of_bsn_header_t));
        if (!hdr) {
            return hdr;
        }
        bzero(hdr, sizeof(of_bsn_header_t));
        if (bufp == NULL) {
            hdr->type = 4;
            hdr->experimenter = 0x5c16c7;
        }
        memcpy(hdr, bufp, len < sizeof(of_bsn_header_t) ? len : sizeof(of_bsn_header_t));
        hdr->length = sizeof(of_bsn_header_t);
    } else {
        hdr = (of_bsn_header_t*) malloc(sizeof(of_bsn_header_t)+ len);
        if (!hdr) {
            return hdr;
        }
        bzero(hdr, sizeof(of_bsn_header_t));
        memcpy(&hdr->payload, bufp, len);
        hdr->length = sizeof(of_bsn_header_t)+ len;
        hdr->type = 4;
        hdr->experimenter = 0x5c16c7;
    }

    hdr->status = status;
    hdr->subtype = stype;
    return hdr;
}
