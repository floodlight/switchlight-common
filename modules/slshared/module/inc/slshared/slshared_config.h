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
 * SLSHARED_CONFIG_ETHERTYPE_DOT1Q
 *
 * Ether type for Dot1q header */


#ifndef SLSHARED_CONFIG_ETHERTYPE_DOT1Q
#define SLSHARED_CONFIG_ETHERTYPE_DOT1Q 33024
#endif

/**
 * SLSHARED_CONFIG_SYSTEM_VLAN
 *
 * System vlan */


#ifndef SLSHARED_CONFIG_SYSTEM_VLAN
#define SLSHARED_CONFIG_SYSTEM_VLAN 4094
#endif

/**
 * SLSHARED_CONFIG_MAX_MTU_SIZE
 *
 * Maximum size of L2 frame */


#ifndef SLSHARED_CONFIG_MAX_MTU_SIZE
#define SLSHARED_CONFIG_MAX_MTU_SIZE 1500
#endif

/**
 * SLSHARED_CONFIG_DOT1Q_HEADER_SIZE
 *
 * Size of Dot1q header */


#ifndef SLSHARED_CONFIG_DOT1Q_HEADER_SIZE
#define SLSHARED_CONFIG_DOT1Q_HEADER_SIZE 18
#endif

/**
 * SLSHARED_CONFIG_IPV4_HEADER_SIZE
 *
 * Size of IPv4 header */


#ifndef SLSHARED_CONFIG_IPV4_HEADER_SIZE
#define SLSHARED_CONFIG_IPV4_HEADER_SIZE 20
#endif

/**
 * SLSHARED_CONFIG_UDP_HEADER_SIZE
 *
 * Size of udp header */


#ifndef SLSHARED_CONFIG_UDP_HEADER_SIZE
#define SLSHARED_CONFIG_UDP_HEADER_SIZE 8
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
