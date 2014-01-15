/**************************************************************************//**
 *
 * @file
 * @brief router_ip_table Configuration Header
 *
 * @addtogroup router_ip_table-config
 * @{
 *
 *****************************************************************************/
#ifndef __ROUTER_IP_TABLE_CONFIG_H__
#define __ROUTER_IP_TABLE_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef ROUTER_IP_TABLE_INCLUDE_CUSTOM_CONFIG
#include <router_ip_table_custom_config.h>
#endif

/* <auto.start.cdefs(ROUTER_IP_TABLE_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING
#define ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT
#define ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT
#define ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB
#define ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB 1
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB
#endif

/**
 * ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI
#define ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct router_ip_table_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} router_ip_table_config_settings_t;

/** Configuration settings table. */
/** router_ip_table_config_settings table. */
extern router_ip_table_config_settings_t router_ip_table_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* router_ip_table_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int router_ip_table_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(ROUTER_IP_TABLE_CONFIG_HEADER).header> */

#include "router_ip_table_porting.h"

#endif /* __ROUTER_IP_TABLE_CONFIG_H__ */
/* @} */
