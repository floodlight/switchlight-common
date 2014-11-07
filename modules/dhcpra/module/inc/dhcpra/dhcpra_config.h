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
 * @brief dhcpra Configuration Header
 *
 * @addtogroup dhcpra-config
 * @{
 *
 ****************************************************************/
#ifndef __DHCPRA_CONFIG_H__
#define __DHCPRA_CONFIG_H__

#include <slshared/slshared_config.h>

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef DHCPRA_INCLUDE_CUSTOM_CONFIG
#include <dhcpra_custom_config.h>
#endif

/* <auto.start.cdefs(DHCPRA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * DHCPRA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef DHCPRA_CONFIG_INCLUDE_LOGGING
#define DHCPRA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT
#define DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * DHCPRA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef DHCPRA_CONFIG_LOG_BITS_DEFAULT
#define DHCPRA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * DHCPRA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef DHCPRA_CONFIG_PORTING_STDLIB
#define DHCPRA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS DHCPRA_CONFIG_PORTING_STDLIB
#endif

/**
 * DHCPRA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef DHCPRA_CONFIG_INCLUDE_UCLI
#define DHCPRA_CONFIG_INCLUDE_UCLI 0
#endif

/**
 * DHCPRA_CONFIG_OF_PORTS_MAX
 *
 * Maximum number of OF ports. */


#ifndef DHCPRA_CONFIG_OF_PORTS_MAX
#define DHCPRA_CONFIG_OF_PORTS_MAX SLSHARED_CONFIG_OF_PORT_MAX
#endif

/**
 * DHCPRA_CONFIG_SYSTEM_VLAN
 *
 * System Vlan. */


#ifndef DHCPRA_CONFIG_SYSTEM_VLAN
#define DHCPRA_CONFIG_SYSTEM_VLAN SLSHARED_CONFIG_SYSTEM_VLAN
#endif

/**
 * DHCPRA_CONFIG_ETHERTYPE_DOT1Q
 *
 * Ethertype for Dot1q header. */


#ifndef DHCPRA_CONFIG_ETHERTYPE_DOT1Q
#define DHCPRA_CONFIG_ETHERTYPE_DOT1Q SLSHARED_CONFIG_ETHERTYPE_DOT1Q
#endif

/**
 * DHCPRA_CONFIG_DOT1Q_HEADER_SIZE
 *
 * Size of Dot1q header. */


#ifndef DHCPRA_CONFIG_DOT1Q_HEADER_SIZE
#define DHCPRA_CONFIG_DOT1Q_HEADER_SIZE SLSHARED_CONFIG_DOT1Q_HEADER_SIZE
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct dhcpra_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} dhcpra_config_settings_t;

/** Configuration settings table. */
/** dhcpra_config_settings table. */
extern dhcpra_config_settings_t dhcpra_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* dhcpra_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int dhcpra_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(DHCPRA_CONFIG_HEADER).header> */

#include "dhcpra_porting.h"

#endif /* __DHCPRA_CONFIG_H__ */
/* @} */
