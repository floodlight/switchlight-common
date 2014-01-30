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

#ifndef __ICMPA_LOG_H__
#define __ICMPA_LOG_H__

#define AIM_LOG_MODULE_NAME icmpa
#include <AIM/aim_log.h>
#include <icmpa/icmpa.h>

/* <auto.start.aim_custom_log_macro(ALL).header> */

/******************************************************************************
 *
 * Custom Module Log Macros
 *
 *****************************************************************************/

/** Log a module-level packet */
#define ICMPA_LOG_MOD_PACKET(...) \
    AIM_LOG_MOD_CUSTOM(ICMPA_LOG_FLAG_PACKET, "PACKET", __VA_ARGS__)
/** Log a module-level packet with ratelimiting */
#define ICMPA_LOG_MOD_RL_PACKET(_rl, _time, ...)           \
    AIM_LOG_MOD_RL_CUSTOM(ICMPA_LOG_FLAG_PACKET, "PACKET", _rl, _time, __VA_ARGS__)

/******************************************************************************
 *
 * Custom Object Log Macros
 *
 *****************************************************************************/

/** Log an object-level packet */
#define ICMPA_LOG_OBJ_PACKET(_obj, ...) \
    AIM_LOG_OBJ_CUSTOM(_obj, ICMPA_LOG_FLAG_PACKET, "PACKET", __VA_ARGS__)
/** Log an object-level packet with ratelimiting */
#define ICMPA_LOG_OBJ_RL_PACKET(_obj, _rl, _time, ...) \
    AIM_LOG_OBJ_RL_CUSTOM(_obj, ICMPA_LOG_FLAG_PACKET, "PACKET", _rl, _time, __VA_ARGS__)

/******************************************************************************
 *
 * Default Macro Mappings
 *
 *****************************************************************************/
#ifdef AIM_LOG_OBJ_DEFAULT

/** PACKET -> OBJ_PACKET */
#define ICMPA_LOG_PACKET ICMPA_LOG_OBJ_PACKET
/** RL_PACKET -> OBJ_RL_PACKET */
#define ICMPA_LOG_RL_PACKET ICMPA_LOG_RL_OBJ_PACKET


#else

/** PACKET -> MOD_PACKET */
#define ICMPA_LOG_PACKET ICMPA_LOG_MOD_PACKET
/** RL_PACKET -> MOD_RL_PACKET */
#define ICMPA_LOG_RL_PACKET ICMPA_LOG_MOD_RL_PACKET

#endif
/* <auto.end.aim_custom_log_macro(ALL).header> */

#endif /* __ICMPA_LOG_H__ */
