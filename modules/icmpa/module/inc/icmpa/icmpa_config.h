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

/*************************************************************//**
 *
 * @file
 * @brief icmpa Configuration Header
 *
 * @addtogroup icmpa-config
 * @{
 *
 ****************************************************************/
#ifndef __ICMPA_CONFIG_H__
#define __ICMPA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef ICMPA_INCLUDE_CUSTOM_CONFIG
#include <icmpa_custom_config.h>
#endif

/* <auto.start.cdefs(ICMPA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * ICMPA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef ICMPA_CONFIG_INCLUDE_LOGGING
#define ICMPA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * ICMPA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef ICMPA_CONFIG_LOG_OPTIONS_DEFAULT
#define ICMPA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * ICMPA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef ICMPA_CONFIG_LOG_BITS_DEFAULT
#define ICMPA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * ICMPA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef ICMPA_CONFIG_PORTING_STDLIB
#define ICMPA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS ICMPA_CONFIG_PORTING_STDLIB
#endif

/**
 * ICMPA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef ICMPA_CONFIG_INCLUDE_UCLI
#define ICMPA_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct icmpa_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} icmpa_config_settings_t;

/** Configuration settings table. */
/** icmpa_config_settings table. */
extern icmpa_config_settings_t icmpa_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* icmpa_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int icmpa_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(ICMPA_CONFIG_HEADER).header> */

#include "icmpa_porting.h"

#endif /* __ICMPA_CONFIG_H__ */
/* @} */
