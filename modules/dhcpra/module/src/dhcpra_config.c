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

#include <dhcpra/dhcpra_config.h>

/* <auto.start.cdefs(DHCPRA_CONFIG_HEADER).source> */
#define __dhcpra_config_STRINGIFY_NAME(_x) #_x
#define __dhcpra_config_STRINGIFY_VALUE(_x) __dhcpra_config_STRINGIFY_NAME(_x)
dhcpra_config_settings_t dhcpra_config_settings[] =
{
#ifdef DHCPRA_CONFIG_INCLUDE_LOGGING
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_INCLUDE_LOGGING), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_INCLUDE_LOGGING) },
#else
{ DHCPRA_CONFIG_INCLUDE_LOGGING(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ DHCPRA_CONFIG_LOG_OPTIONS_DEFAULT(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_LOG_BITS_DEFAULT
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_LOG_BITS_DEFAULT), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ DHCPRA_CONFIG_LOG_BITS_DEFAULT(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ DHCPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_PORTING_STDLIB
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_PORTING_STDLIB), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_PORTING_STDLIB) },
#else
{ DHCPRA_CONFIG_PORTING_STDLIB(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_INCLUDE_UCLI
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_INCLUDE_UCLI), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_INCLUDE_UCLI) },
#else
{ DHCPRA_CONFIG_INCLUDE_UCLI(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_OF_PORTS_MAX
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_OF_PORTS_MAX), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_OF_PORTS_MAX) },
#else
{ DHCPRA_CONFIG_OF_PORTS_MAX(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_SYSTEM_VLAN
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_SYSTEM_VLAN), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_SYSTEM_VLAN) },
#else
{ DHCPRA_CONFIG_SYSTEM_VLAN(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_ETHERTYPE_DOT1Q
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_ETHERTYPE_DOT1Q), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_ETHERTYPE_DOT1Q) },
#else
{ DHCPRA_CONFIG_ETHERTYPE_DOT1Q(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef DHCPRA_CONFIG_DOT1Q_HEADER_SIZE
    { __dhcpra_config_STRINGIFY_NAME(DHCPRA_CONFIG_DOT1Q_HEADER_SIZE), __dhcpra_config_STRINGIFY_VALUE(DHCPRA_CONFIG_DOT1Q_HEADER_SIZE) },
#else
{ DHCPRA_CONFIG_DOT1Q_HEADER_SIZE(__dhcpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __dhcpra_config_STRINGIFY_VALUE
#undef __dhcpra_config_STRINGIFY_NAME

const char*
dhcpra_config_lookup(const char* setting)
{
    int i;
    for(i = 0; dhcpra_config_settings[i].name; i++) {
        if(strcmp(dhcpra_config_settings[i].name, setting)) {
            return dhcpra_config_settings[i].value;
        }
    }
    return NULL;
}

int
dhcpra_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; dhcpra_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", dhcpra_config_settings[i].name, dhcpra_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(DHCPRA_CONFIG_HEADER).source> */

