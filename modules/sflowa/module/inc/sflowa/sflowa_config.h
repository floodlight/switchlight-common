/**************************************************************************//**
 *
 * @file
 * @brief sflowa Configuration Header
 *
 * @addtogroup sflowa-config
 * @{
 *
 *****************************************************************************/
#ifndef __SFLOWA_CONFIG_H__
#define __SFLOWA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef SFLOWA_INCLUDE_CUSTOM_CONFIG
#include <sflowa_custom_config.h>
#endif

#include <slshared/slshared_config.h>

/* <auto.start.cdefs(SFLOWA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * SFLOWA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef SFLOWA_CONFIG_INCLUDE_LOGGING
#define SFLOWA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT
#define SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * SFLOWA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef SFLOWA_CONFIG_LOG_BITS_DEFAULT
#define SFLOWA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * SFLOWA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef SFLOWA_CONFIG_PORTING_STDLIB
#define SFLOWA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS SFLOWA_CONFIG_PORTING_STDLIB
#endif

/**
 * SFLOWA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef SFLOWA_CONFIG_INCLUDE_UCLI
#define SFLOWA_CONFIG_INCLUDE_UCLI 0
#endif

/**
 * SFLOWA_CONFIG_OF_PORTS_MAX
 *
 * Maximum number of OF ports. */


#ifndef SFLOWA_CONFIG_OF_PORTS_MAX
#define SFLOWA_CONFIG_OF_PORTS_MAX SLSHARED_CONFIG_OF_PORT_MAX
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct sflowa_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} sflowa_config_settings_t;

/** Configuration settings table. */
/** sflowa_config_settings table. */
extern sflowa_config_settings_t sflowa_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* sflowa_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int sflowa_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(SFLOWA_CONFIG_HEADER).header> */

#include "sflowa_porting.h"

#endif /* __SFLOWA_CONFIG_H__ */
/* @} */
