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

#ifndef __LACPA_LOG_H__
#define __LACPA_LOG_H__

#define AIM_LOG_MODULE_NAME lacpa
#include <AIM/aim_log.h>
#include <lacpa/lacpa.h>

/* <auto.start.aim_custom_log_macro(ALL).header> */

/******************************************************************************
 *
 * Custom Module Log Macros
 *
 *****************************************************************************/

/** Log a module-level portstats */
#define LACPA_LOG_MOD_PORTSTATS(...) \
    AIM_LOG_MOD_CUSTOM(LACPA_LOG_FLAG_PORTSTATS, "PORTSTATS", __VA_ARGS__)
/** Log a module-level portstats with ratelimiting */
#define LACPA_LOG_MOD_RL_PORTSTATS(_rl, _time, ...)           \
    AIM_LOG_MOD_RL_CUSTOM(LACPA_LOG_FLAG_PORTSTATS, "PORTSTATS", _rl, _time, __VA_ARGS__)

/******************************************************************************
 *
 * Custom Object Log Macros
 *
 *****************************************************************************/

/** Log an object-level portstats */
#define LACPA_LOG_OBJ_PORTSTATS(_obj, ...) \
    AIM_LOG_OBJ_CUSTOM(_obj, LACPA_LOG_FLAG_PORTSTATS, "PORTSTATS", __VA_ARGS__)
/** Log an object-level portstats with ratelimiting */
#define LACPA_LOG_OBJ_RL_PORTSTATS(_obj, _rl, _time, ...) \
    AIM_LOG_OBJ_RL_CUSTOM(_obj, LACPA_LOG_FLAG_PORTSTATS, "PORTSTATS", _rl, _time, __VA_ARGS__)

/******************************************************************************
 *
 * Default Macro Mappings
 *
 *****************************************************************************/
#ifdef AIM_LOG_OBJ_DEFAULT

/** PORTSTATS -> OBJ_PORTSTATS */
#define LACPA_LOG_PORTSTATS LACPA_LOG_OBJ_PORTSTATS
/** RL_PORTSTATS -> OBJ_RL_PORTSTATS */
#define LACPA_LOG_RL_PORTSTATS LACPA_LOG_RL_OBJ_PORTSTATS


#else

/** PORTSTATS -> MOD_PORTSTATS */
#define LACPA_LOG_PORTSTATS LACPA_LOG_MOD_PORTSTATS
/** RL_PORTSTATS -> MOD_RL_PORTSTATS */
#define LACPA_LOG_RL_PORTSTATS LACPA_LOG_MOD_RL_PORTSTATS

#endif
/* <auto.end.aim_custom_log_macro(ALL).header> */

#endif /* __LACPA_LOG_H__ */
