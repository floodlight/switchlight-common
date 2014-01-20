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
#include <OS/os_time.h>
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

/** lacpa_log_flag */
typedef enum lacpa_log_flag_e {
    LACPA_LOG_FLAG_PORTSTATS,
    LACPA_LOG_FLAG_LAST = LACPA_LOG_FLAG_PORTSTATS,
    LACPA_LOG_FLAG_COUNT,
    LACPA_LOG_FLAG_INVALID = -1,
} lacpa_log_flag_t;

/** Strings macro. */
#define LACPA_LOG_FLAG_STRINGS \
{\
    "portstats", \
}
/** Enum names. */
const char* lacpa_log_flag_name(lacpa_log_flag_t e);

/** Enum values. */
int lacpa_log_flag_value(const char* str, lacpa_log_flag_t* e, int substr);

/** Enum descriptions. */
const char* lacpa_log_flag_desc(lacpa_log_flag_t e);

/** validator */
#define LACPA_LOG_FLAG_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= LACPA_LOG_FLAG_PORTSTATS))

/** lacpa_log_flag_map table. */
extern aim_map_si_t lacpa_log_flag_map[];
/** lacpa_log_flag_desc_map table. */
extern aim_map_si_t lacpa_log_flag_desc_map[];

/** lacpa_transmit */
typedef enum lacpa_transmit_e {
    LACPA_TRANSMIT_NONE,
    LACPA_TRANSMIT_AGENT_ENABLED,
    LACPA_TRANSMIT_INFO_MISMATCH,
    LACPA_TRANSMIT_ACTIVITY_MISMATCH,
    LACPA_TRANSMIT_AGGREGATION_MISMATCH,
    LACPA_TRANSMIT_SYNCHRONIZATION_MISMATCH,
    LACPA_TRANSMIT_COLLECTING_MISMATCH,
    LACPA_TRANSMIT_DISTRIBUTING_MISMATCH,
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
    "ACTIVITY_MISMATCH", \
    "AGGREGATION_MISMATCH", \
    "SYNCHRONIZATION_MISMATCH", \
    "COLLECTING_MISMATCH", \
    "DISTRIBUTING_MISMATCH", \
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
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : EXTERNAL API DEFINITIONS
 *
 *****************************************************************************/
indigo_error_t lacpa_init (void);
bool lacpa_is_initialized (void);

#endif /* __LACP__H__ */
