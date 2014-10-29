/**************************************************************************//**
 *
 * @file
 * @brief slshared Configuration Header
 *
 * @addtogroup slshared-config
 * @{
 *
 *****************************************************************************/
#ifndef __SLSHARED_CONFIG_H__
#define __SLSHARED_CONFIG_H__

#ifdef GLOBAL_INCLUDE_CUSTOM_CONFIG
#include <global_custom_config.h>
#endif
#ifdef SLSHARED_INCLUDE_CUSTOM_CONFIG
#include <slshared_custom_config.h>
#endif

/* <auto.start.cdefs(SLSHARED_CONFIG_HEADER).header> */
#include <AIM/aim.h>
/**
 * SLSHARED_CONFIG_OF_PORT_MAX
 *
 * Maximum OF port number range for all agents. */


#ifndef SLSHARED_CONFIG_OF_PORT_MAX
#define SLSHARED_CONFIG_OF_PORT_MAX 512
#endif



/**
 * All compile time options can be queried or displayed
 */

/** Configuration settings structure. */
typedef struct slshared_config_settings_s {
    /** name */
    const char* name;
    /** value */
    const char* value;
} slshared_config_settings_t;

/** Configuration settings table. */
/** slshared_config_settings table. */
extern slshared_config_settings_t slshared_config_settings[];

/**
 * @brief Lookup a configuration setting.
 * @param setting The name of the configuration option to lookup.
 */
const char* slshared_config_lookup(const char* setting);

/**
 * @brief Show the compile-time configuration.
 * @param pvs The output stream.
 */
int slshared_config_show(struct aim_pvs_s* pvs);

/* <auto.end.cdefs(SLSHARED_CONFIG_HEADER).header> */

#endif /* __SLSHARED_CONFIG_H__ */
/* @} */
