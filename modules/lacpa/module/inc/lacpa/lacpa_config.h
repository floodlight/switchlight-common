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
 * @brief lacpa Configuration Header
 *
 * @addtogroup lacpa-config
 * @{
 *
 ****************************************************************/
#ifndef __LACPA_CONFIG_H__
#define __LACPA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef LACPA_INCLUDE_CUSTOM_CONFIG
#include <lacpa_custom_config.h>
#endif

#include <slshared/slshared_config.h>

/* <auto.start.cdefs(LACPA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * LACPA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef LACPA_CONFIG_INCLUDE_LOGGING
#define LACPA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * LACPA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef LACPA_CONFIG_LOG_OPTIONS_DEFAULT
#define LACPA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * LACPA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef LACPA_CONFIG_LOG_BITS_DEFAULT
#define LACPA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * LACPA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef LACPA_CONFIG_PORTING_STDLIB
#define LACPA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS LACPA_CONFIG_PORTING_STDLIB
#endif

/**
 * LACPA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef LACPA_CONFIG_INCLUDE_UCLI
#define LACPA_CONFIG_INCLUDE_UCLI 1
#endif

/**
 * LACPA_CONFIG_OF_PORTS_MAX
 *
 * Maximum number of OF ports. */


#ifndef LACPA_CONFIG_OF_PORTS_MAX
#define LACPA_CONFIG_OF_PORTS_MAX SLSHARED_CONFIG_OF_PORT_MAX
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct lacpa_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} lacpa_config_settings_t;

/** Configuration settings table. */
/** lacpa_config_settings table. */
extern lacpa_config_settings_t lacpa_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* lacpa_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int lacpa_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(LACPA_CONFIG_HEADER).header> */

#include "lacpa_porting.h"

#endif /* __LACPA_CONFIG_H__ */
/* @} */
