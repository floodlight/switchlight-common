/**************************************************************************//**
 *
 * @file
 * @brief cdpa Configuration Header
 *
 * @addtogroup cdpa-config
 * @{
 *
 *****************************************************************************/
#ifndef __CDPA_CONFIG_H__
#define __CDPA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef CDPA_INCLUDE_CUSTOM_CONFIG
#include <cdpa_custom_config.h>
#endif

/* <auto.start.cdefs(CDPA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * CDPA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef CDPA_CONFIG_INCLUDE_LOGGING
#define CDPA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * CDPA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef CDPA_CONFIG_LOG_OPTIONS_DEFAULT
#define CDPA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * CDPA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef CDPA_CONFIG_LOG_BITS_DEFAULT
#define CDPA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * CDPA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef CDPA_CONFIG_PORTING_STDLIB
#define CDPA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS CDPA_CONFIG_PORTING_STDLIB
#endif

/**
 * CDPA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef CDPA_CONFIG_INCLUDE_UCLI
#define CDPA_CONFIG_INCLUDE_UCLI 0
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct cdpa_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} cdpa_config_settings_t;

/** Configuration settings table. */
/** cdpa_config_settings table. */
extern cdpa_config_settings_t cdpa_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* cdpa_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int cdpa_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(CDPA_CONFIG_HEADER).header> */

#include "cdpa_porting.h"

#endif /* __CDPA_CONFIG_H__ */
/* @} */
