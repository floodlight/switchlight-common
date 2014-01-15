/**************************************************************************//**
 *
 * @file
 * @brief arpa Configuration Header
 *
 * @addtogroup arpa-config
 * @{
 *
 *****************************************************************************/
#ifndef __ARPA_CONFIG_H__
#define __ARPA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef ARPA_INCLUDE_CUSTOM_CONFIG
#include <arpa_custom_config.h>
#endif

/* <auto.start.cdefs(ARPA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * ARPA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef ARPA_CONFIG_INCLUDE_LOGGING
#define ARPA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * ARPA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef ARPA_CONFIG_LOG_OPTIONS_DEFAULT
#define ARPA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * ARPA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef ARPA_CONFIG_LOG_BITS_DEFAULT
#define ARPA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * ARPA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef ARPA_CONFIG_PORTING_STDLIB
#define ARPA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS ARPA_CONFIG_PORTING_STDLIB
#endif

/**
 * ARPA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef ARPA_CONFIG_INCLUDE_UCLI
#define ARPA_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct arpa_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} arpa_config_settings_t;

/** Configuration settings table. */
/** arpa_config_settings table. */
extern arpa_config_settings_t arpa_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* arpa_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int arpa_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(ARPA_CONFIG_HEADER).header> */

#include "arpa_porting.h"

#endif /* __ARPA_CONFIG_H__ */
/* @} */
