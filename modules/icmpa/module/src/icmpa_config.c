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

#include <icmpa/icmpa_config.h>

/* <auto.start.cdefs(ICMPA_CONFIG_HEADER).source> */
#define __icmpa_config_STRINGIFY_NAME(_x) #_x
#define __icmpa_config_STRINGIFY_VALUE(_x) __icmpa_config_STRINGIFY_NAME(_x)
icmpa_config_settings_t icmpa_config_settings[] =
{
#ifdef ICMPA_CONFIG_INCLUDE_LOGGING
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_INCLUDE_LOGGING), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_INCLUDE_LOGGING) },
#else
{ ICMPA_CONFIG_INCLUDE_LOGGING(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_LOG_OPTIONS_DEFAULT
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_LOG_OPTIONS_DEFAULT), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ ICMPA_CONFIG_LOG_OPTIONS_DEFAULT(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_LOG_BITS_DEFAULT
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_LOG_BITS_DEFAULT), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ ICMPA_CONFIG_LOG_BITS_DEFAULT(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ ICMPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_PORTING_STDLIB
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_PORTING_STDLIB), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_PORTING_STDLIB) },
#else
{ ICMPA_CONFIG_PORTING_STDLIB(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_INCLUDE_UCLI
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_INCLUDE_UCLI), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_INCLUDE_UCLI) },
#else
{ ICMPA_CONFIG_INCLUDE_UCLI(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_OF_PORTS_MAX
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_OF_PORTS_MAX), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_OF_PORTS_MAX) },
#else
{ ICMPA_CONFIG_OF_PORTS_MAX(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_SYSTEM_VLAN
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_SYSTEM_VLAN), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_SYSTEM_VLAN) },
#else
{ ICMPA_CONFIG_SYSTEM_VLAN(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_ETHERTYPE_DOT1Q
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_ETHERTYPE_DOT1Q), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_ETHERTYPE_DOT1Q) },
#else
{ ICMPA_CONFIG_ETHERTYPE_DOT1Q(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ICMPA_CONFIG_IPV4_HEADER_SIZE
    { __icmpa_config_STRINGIFY_NAME(ICMPA_CONFIG_IPV4_HEADER_SIZE), __icmpa_config_STRINGIFY_VALUE(ICMPA_CONFIG_IPV4_HEADER_SIZE) },
#else
{ ICMPA_CONFIG_IPV4_HEADER_SIZE(__icmpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __icmpa_config_STRINGIFY_VALUE
#undef __icmpa_config_STRINGIFY_NAME

const char*
icmpa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; icmpa_config_settings[i].name; i++) {
        if(strcmp(icmpa_config_settings[i].name, setting)) {
            return icmpa_config_settings[i].value;
        }
    }
    return NULL;
}

int
icmpa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; icmpa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", icmpa_config_settings[i].name, icmpa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(ICMPA_CONFIG_HEADER).source> */

