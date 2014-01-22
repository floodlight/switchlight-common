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

#ifndef __ICMPA_H__
#define __ICMPA_H__

#include <stdbool.h>
#include <indigo/error.h>

/* <auto.start.enum(ALL).header> */
/** icmpa_log_flag */
typedef enum icmpa_log_flag_e {
    ICMPA_LOG_FLAG_PACKET,
    ICMPA_LOG_FLAG_LAST = ICMPA_LOG_FLAG_PACKET,
    ICMPA_LOG_FLAG_COUNT,
    ICMPA_LOG_FLAG_INVALID = -1,
} icmpa_log_flag_t;

/** Strings macro. */
#define ICMPA_LOG_FLAG_STRINGS \
{\
    "packet", \
}
/** Enum names. */
const char* icmpa_log_flag_name(icmpa_log_flag_t e);

/** Enum values. */
int icmpa_log_flag_value(const char* str, icmpa_log_flag_t* e, int substr);

/** Enum descriptions. */
const char* icmpa_log_flag_desc(icmpa_log_flag_t e);

/** validator */
#define ICMPA_LOG_FLAG_VALID(_e) \
    ( (0 <= (_e)) && ((_e) <= ICMPA_LOG_FLAG_PACKET))

/** icmpa_log_flag_map table. */
extern aim_map_si_t icmpa_log_flag_map[];
/** icmpa_log_flag_desc_map table. */
extern aim_map_si_t icmpa_log_flag_desc_map[];
/* <auto.end.enum(ALL).header> */

/******************************************************************************
 *
 * ICMP : INTERNET CONTROL MESSAGE PROTOCOL : EXTERNAL API DEFINITIONS
 *
 *****************************************************************************/

indigo_error_t icmpa_init (void);
bool icmpa_is_initialized (void);
void icmpa_finish (void);

#endif /* __ICMPA__H__ */
