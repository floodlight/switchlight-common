/**************************************************************************//**
 *
 * @file
 * @brief arpra Configuration Header
 *
 * @addtogroup arpra-config
 * @{
 *
 *****************************************************************************/
#ifndef __ARPRA_CONFIG_H__
#define __ARPRA_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef ARPRA_INCLUDE_CUSTOM_CONFIG
#include <arpra_custom_config.h>
#endif

/* <auto.start.cdefs(ARPRA_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * ARPRA_CONFIG_INCLUDE_LOGGING
 *
 * Include or exclude logging. */


#ifndef ARPRA_CONFIG_INCLUDE_LOGGING
#define ARPRA_CONFIG_INCLUDE_LOGGING 1
#endif

/**
 * ARPRA_CONFIG_LOG_OPTIONS_DEFAULT
 *
 * Default enabled log options. */


#ifndef ARPRA_CONFIG_LOG_OPTIONS_DEFAULT
#define ARPRA_CONFIG_LOG_OPTIONS_DEFAULT AIM_LOG_OPTIONS_DEFAULT
#endif

/**
 * ARPRA_CONFIG_LOG_BITS_DEFAULT
 *
 * Default enabled log bits. */


#ifndef ARPRA_CONFIG_LOG_BITS_DEFAULT
#define ARPRA_CONFIG_LOG_BITS_DEFAULT AIM_LOG_BITS_DEFAULT
#endif

/**
 * ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
 *
 * Default enabled custom log bits. */


#ifndef ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
#define ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT 0
#endif

/**
 * ARPRA_CONFIG_PORTING_STDLIB
 *
 * Default all porting macros to use the C standard libraries. */


#ifndef ARPRA_CONFIG_PORTING_STDLIB
#define ARPRA_CONFIG_PORTING_STDLIB 1
#endif

/**
 * ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
 *
 * Include standard library headers for stdlib porting macros. */


#ifndef ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
#define ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS ARPRA_CONFIG_PORTING_STDLIB
#endif

/**
 * ARPRA_CONFIG_INCLUDE_UCLI
 *
 * Include generic uCli support. */


#ifndef ARPRA_CONFIG_INCLUDE_UCLI
#define ARPRA_CONFIG_INCLUDE_UCLI 1
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct arpra_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} arpra_config_settings_t;

/** Configuration settings table. */
/** arpra_config_settings table. */
extern arpra_config_settings_t arpra_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* arpra_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int arpra_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(ARPRA_CONFIG_HEADER).header> */

#include "arpra_porting.h"

#endif /* __ARPRA_CONFIG_H__ */
/* @} */
