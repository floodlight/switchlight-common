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

#ifndef __LACP_H__
#define __LACP_H__

#include <lacpa/lacpa_config.h>
#include <lacpa/lacpa_porting.h>
#include <stdbool.h>
#include <indigo/error.h>
#include <loci/loci.h>
#include <OFStateManager/ofstatemanager.h>
#include <indigo/of_connection_manager.h>

/* <auto.start.enum(ALL).header> */
/** lacpa_error */
typedef enum lacpa_error_e {
    LACPA_ERROR_NONE,
    LACPA_ERROR_PARTNER_AGGREGATION_OFF,
    LACPA_ERROR_PARTNER_INSYNC,
    LACPA_ERROR_PARTNER_COLLECTION_OFF,
    LACPA_ERROR_PARTNER_DISTRIBUTION_OFF,
    LACPA_ERROR_LAST = LACPA_ERROR_PARTNER_DISTRIBUTION_OFF,
    LACPA_ERROR_COUNT,
    LACPA_ERROR_INVALID = -1,
} lacpa_error_t;

/** Strings macro. */
#define LACPA_ERROR_STRINGS \
{\
    "NONE", \
    "PARTNER_AGGREGATION_OFF", \
    "PARTNER_INSYNC", \
    "PARTNER_COLLECTION_OFF", \
    "PARTNER_DISTRIBUTION_OFF", \
}
/** Enum names. */
const char* lacpa_error_name(lacpa_error_t e);

/** Enum values. */
int lacpa_error_value(const char* str, lacpa_error_t* e, int substr);

/** Enum descriptions. */
const char* lacpa_error_desc(lacpa_error_t e);

/** validator */
#define LACPA_ERROR_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LACPA_ERROR_PARTNER_DISTRIBUTION_OFF))

/** lacpa_error_map table. */
extern aim_map_si_t lacpa_error_map[];
/** lacpa_error_desc_map table. */
extern aim_map_si_t lacpa_error_desc_map[];

/** lacpa_machine */
typedef enum lacpa_machine_e {
    LACPA_MACHINE_AGENT_STOPPED,
    LACPA_MACHINE_AGENT_CURRENT,
    LACPA_MACHINE_AGENT_EXPIRED,
    LACPA_MACHINE_AGENT_DEFAULTED,
    LACPA_MACHINE_LAST = LACPA_MACHINE_AGENT_DEFAULTED,
    LACPA_MACHINE_COUNT,
    LACPA_MACHINE_INVALID = -1,
} lacpa_machine_t;

/** Strings macro. */
#define LACPA_MACHINE_STRINGS \
{\
    "AGENT_STOPPED", \
    "AGENT_CURRENT", \
    "AGENT_EXPIRED", \
    "AGENT_DEFAULTED", \
}
/** Enum names. */
const char* lacpa_machine_name(lacpa_machine_t e);

/** Enum values. */
int lacpa_machine_value(const char* str, lacpa_machine_t* e, int substr);

/** Enum descriptions. */
const char* lacpa_machine_desc(lacpa_machine_t e);

/** validator */
#define LACPA_MACHINE_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LACPA_MACHINE_AGENT_DEFAULTED))

/** lacpa_machine_map table. */
extern aim_map_si_t lacpa_machine_map[];
/** lacpa_machine_desc_map table. */
extern aim_map_si_t lacpa_machine_desc_map[];

/** lacpa_event */
typedef enum lacpa_event_e {
    LACPA_EVENT_DISABLED,
    LACPA_EVENT_ENABLED,
    LACPA_EVENT_PDU_RECEIVED,
    LACPA_EVENT_CURRENT_TIMER_EXPIRED,
    LACPA_EVENT_EXPIRY_TIMER_EXPIRED,
    LACPA_EVENT_CHURN_DETECTION_EXPIRED,
    LACPA_EVENT_PROTOCOL_CONVERGED,
    LACPA_EVENT_PROTOCOL_UNCONVERGED,
    LACPA_EVENT_LAST = LACPA_EVENT_PROTOCOL_UNCONVERGED,
    LACPA_EVENT_COUNT,
    LACPA_EVENT_INVALID = -1,
} lacpa_event_t;

/** Strings macro. */
#define LACPA_EVENT_STRINGS \
{\
    "DISABLED", \
    "ENABLED", \
    "PDU_RECEIVED", \
    "CURRENT_TIMER_EXPIRED", \
    "EXPIRY_TIMER_EXPIRED", \
    "CHURN_DETECTION_EXPIRED", \
    "PROTOCOL_CONVERGED", \
    "PROTOCOL_UNCONVERGED", \
}
/** Enum names. */
const char* lacpa_event_name(lacpa_event_t e);

/** Enum values. */
int lacpa_event_value(const char* str, lacpa_event_t* e, int substr);

/** Enum descriptions. */
const char* lacpa_event_desc(lacpa_event_t e);

/** validator */
#define LACPA_EVENT_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LACPA_EVENT_PROTOCOL_UNCONVERGED))

/** lacpa_event_map table. */
extern aim_map_si_t lacpa_event_map[];
/** lacpa_event_desc_map table. */
extern aim_map_si_t lacpa_event_desc_map[];

/** lacpa_transmit */
typedef enum lacpa_transmit_e {
    LACPA_TRANSMIT_NONE,
    LACPA_TRANSMIT_AGENT_ENABLED,
    LACPA_TRANSMIT_INFO_MISMATCH,
    LACPA_TRANSMIT_LCAP_ACTIVITY_MISTMATCH,
    LACPA_TRANSMIT_AGGREGATION_MISTMATCH,
    LACPA_TRANSMIT_SYNCHRONIZATION_MISTMATCH,
    LACPA_TRANSMIT_COLLECTING_MISTMATCH,
    LACPA_TRANSMIT_DISTRIBUTING_MISTMATCH,
    LACPA_TRANSMIT_SYNCHRONIZATION_SET,
    LACPA_TRANSMIT_COLLECTING_SET,
    LACPA_TRANSMIT_DISTRIBUTING_SET,
    LACPA_TRANSMIT_PERIODIC_TIMER_EXPIRED,
    LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED,
    LACPA_TRANSMIT_LAST = LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED,
    LACPA_TRANSMIT_COUNT,
    LACPA_TRANSMIT_INVALID = -1,
} lacpa_transmit_t;

/** Strings macro. */
#define LACPA_TRANSMIT_STRINGS \
{\
    "NONE", \
    "AGENT_ENABLED", \
    "INFO_MISMATCH", \
    "LCAP_ACTIVITY_MISTMATCH", \
    "AGGREGATION_MISTMATCH", \
    "SYNCHRONIZATION_MISTMATCH", \
    "COLLECTING_MISTMATCH", \
    "DISTRIBUTING_MISTMATCH", \
    "SYNCHRONIZATION_SET", \
    "COLLECTING_SET", \
    "DISTRIBUTING_SET", \
    "PERIODIC_TIMER_EXPIRED", \
    "CURRENT_TIMER_EXPIRED", \
}
/** Enum names. */
const char* lacpa_transmit_name(lacpa_transmit_t e);

/** Enum values. */
int lacpa_transmit_value(const char* str, lacpa_transmit_t* e, int substr);

/** Enum descriptions. */
const char* lacpa_transmit_desc(lacpa_transmit_t e);

/** validator */
#define LACPA_TRANSMIT_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED))

/** lacpa_transmit_map table. */
extern aim_map_si_t lacpa_transmit_map[];
/** lacpa_transmit_desc_map table. */
extern aim_map_si_t lacpa_transmit_desc_map[];
/* <auto.end.enum(ALL).header> */

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : PROTOCOL DATA
 *
 *****************************************************************************/
#define FALSE                  0
#define TRUE                   1

typedef uint8_t lacpa_state_t;

typedef struct lacpa_info_e { /* lacpa_info */
    uint16_t         sys_priority;
    of_mac_addr_t    sys_mac;
    uint16_t         port_priority;
    uint16_t         port_num;
    uint16_t         key;
    lacpa_state_t    state;
    of_port_no_t     port_no;
} lacpa_info_t;

typedef struct lacp_pdu_e { /* lacpa_pdu */
    lacpa_info_t     actor;
    lacpa_info_t     partner;
} lacpa_pdu_t;

typedef struct lacpa_port_e   lacpa_port_t;
typedef struct lacpa_system_e lacpa_system_t;

/******************************************************************************
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : PHYSICAL PORT INSTANCE
 *****************************************************************************/
struct lacpa_port_e { /* lacpa_port */
    of_mac_addr_t    src_mac;
    lacpa_info_t     actor;
    lacpa_info_t     partner;
    lacpa_machine_t  lacp_state;
    lacpa_event_t    lacp_event;
    bool             lacp_enabled;
    bool             is_converged;
    lacpa_error_t    error;
    lacpa_transmit_t ntt_reason;
    lacpa_system_t   *system;
};

/******************************************************************************
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : SYSTEM DATA & API DECLARATIONS
 *****************************************************************************/
struct lacpa_system_e { /* lacpa_system */
    uint32_t         lacp_active_port_count;
    lacpa_port_t     *ports;
};

extern lacpa_system_t lacp_system;
 
extern indigo_error_t lacpa_init_system (lacpa_system_t *system);
extern void lacpa_deinit_system (lacpa_system_t *system);
extern bool lacpa_is_system_initialized (void);
extern lacpa_port_t *lacpa_find_port (lacpa_system_t *system, uint32_t port_no);

extern ind_core_listener_result_t 
lacpa_packet_in_listner (of_packet_in_t *packet_in);
extern ind_core_listener_result_t 
lacpa_controller_msg_listner (indigo_cxn_id_t cxn, of_object_t *obj);
 
/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : LACPA EXTERNAL API DECLARATIONS
 *
 *****************************************************************************/
extern void lacpa_init_port (lacpa_system_t *system, lacpa_info_t *port,
                             uint8_t lacp_enabled);
extern bool lacpa_receive_utest (lacpa_port_t *port, uint8_t *data, 
                                 uint32_t bytes);
extern void lacpa_send_utest (lacpa_port_t *port, uint8_t *data,
                              uint32_t bytes);
extern void lacpa_send_packet_out (lacpa_port_t *port, of_octets_t *octets); 
extern void lacpa_update_controller (lacpa_port_t *port);

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : DEBUG API DECLARATIONS
 *
 *****************************************************************************/
extern void lacpa_dump_port (lacpa_port_t *port);
extern void lacpa_dump_state (lacpa_port_t *port);

#endif /* __LACP__H__ */
