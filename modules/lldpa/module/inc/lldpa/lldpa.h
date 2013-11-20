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
    LLDPA_CONTR_STYPE_PACKET_IN,
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

/** lldpa_pkt_type */
typedef enum lldpa_pkt_type_e {
    LLDPA_PKT_TYPE_RX_PACKET,
    LLDPA_PKT_TYPE_TX_PACKET,
    LLDPA_PKT_TYPE_LAST = LLDPA_PKT_TYPE_TX_PACKET,
    LLDPA_PKT_TYPE_COUNT,
    LLDPA_PKT_TYPE_INVALID = -1,
} lldpa_pkt_type_t;

/** Strings macro. */
#define LLDPA_PKT_TYPE_STRINGS \
{\
    "RX_PACKET", \
    "TX_PACKET", \
}
/** Enum names. */
const char* lldpa_pkt_type_name(lldpa_pkt_type_t e);

/** Enum values. */
int lldpa_pkt_type_value(const char* str, lldpa_pkt_type_t* e, int substr);

/** Enum descriptions. */
const char* lldpa_pkt_type_desc(lldpa_pkt_type_t e);

/** validator */
#define LLDPA_PKT_TYPE_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LLDPA_PKT_TYPE_TX_PACKET))

/** lldpa_pkt_type_map table. */
extern aim_map_si_t lldpa_pkt_type_map[];
/** lldpa_pkt_type_desc_map table. */
extern aim_map_si_t lldpa_pkt_type_desc_map[];
/* <auto.end.enum(ALL).header> */


/*********************
 **** MANUALLY ADD****
 *********************/

//TODO
typedef int (LLDPAAlarmCallback_t) (void* arg);

uint32_t     os_ctrl_cxn_id;

/* Return an id of alarm */
typedef uint32_t (OSAlarmRegister_t)    (unsigned int when, unsigned int flags,
                                    LLDPAAlarmCallback_t * thecallback, void *clientarg);
typedef void (OSAlarmUnregister_t)    (unsigned int alarm_id);
OSAlarmRegister_t* os_alarm_register_fn;
OSAlarmUnregister_t* os_alarm_unregister_fn;
#define ALARM_UNREGISTER 0

//TODO we need to include of_port_no_t / of_octets_t
typedef uint32_t of_port_no_t;
typedef uint8_t  octets_t;
typedef int (tx_fn_t) (void* buf, size_t count, of_port_no_t port);

typedef enum {INVALID_PACKET, RX_PACKET, TX_PACKET} lldpa_pkt_type;
typedef enum {
    SW_CONTR_INVALID = 0,
    SW_CONTR_PACKET_IN, //TODO fake this
    SW_CONTR_TX_REQ=31,
    SW_CONTR_TX_RES=32,
    SW_CONTR_RX_REQ=33,
    SW_CONTR_RX_RES=34,
    SW_CONTR_TIMEOUT=35
} lldpa_contr_stype;

typedef struct of_bsn_header {
    uint8_t version;
    uint8_t type;
    uint16_t length; //header lengh + payload length
    uint32_t xid;
    uint32_t experimenter;
    uint32_t subtype;
    uint32_t status; // 0 means success
    of_port_no_t port_no;
    uint8_t slot_num;
    uint8_t pad[3];
    uint32_t interval_ms;
    octets_t payload[0];
} of_bsn_header_t;

typedef struct lldpa_pkt {
    uint32_t              interval_ms;
    uint32_t              alarm_id;
    LLDPAAlarmCallback_t  *alarm_cb;
    uint32_t              len;
    octets_t              *pdata;
} lldpa_pkt_t;

typedef struct lldpa_port {
    of_port_no_t  port_no;
    lldpa_pkt_t   rx_pkt;
    lldpa_pkt_t   tx_pkt;
    tx_fn_t*      tx_fn; //Will consume and free pkt
    uint32_t      rx_pkt_matched;
    tx_fn_t*      tx_ctrl_fn; //Will consume and free pkt
} lldpa_port_t;


lldpa_port_t* lldpa_port_create(int portno);
int lldpa_port_free(lldpa_port_t* lldpa, int force);

void lldpa_port_set_fwd_pkt_fn(lldpa_port_t* lldpa, tx_fn_t* tx_fn);
void lldpa_port_set_snd_ctrl_msg_fn(lldpa_port_t* lldpa, tx_fn_t* tx_fn);

int lldpa_port_rx_matched (lldpa_port_t *lldpa, void* buf, uint32_t len);

/* pkt is of_bsn_header_t - msg from CTRL */
void lldpa_agent_handle_msg (lldpa_port_t* lldpa, void* msg);

/*
 * buf is pkt in form of LLDPPDU
 * Matched: reset alarm
 * No Matched: forward to controller
 */
void lldpa_agent_handle_pkt (lldpa_port_t *lldpa, void* buf, uint32_t len);


#endif /* __LLDPA_H__ */
