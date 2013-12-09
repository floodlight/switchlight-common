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

#include <lldpa/lldpa_config.h>

/* <auto.start.cdefs(LLDPA_CONFIG_HEADER).source> */
#define __lldpa_config_STRINGIFY_NAME(_x) #_x
#define __lldpa_config_STRINGIFY_VALUE(_x) __lldpa_config_STRINGIFY_NAME(_x)
lldpa_config_settings_t lldpa_config_settings[] =
{
#ifdef LLDPA_CONFIG_INCLUDE_LOGGING
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_INCLUDE_LOGGING), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_INCLUDE_LOGGING) },
#else
{ LLDPA_CONFIG_INCLUDE_LOGGING(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_LOG_OPTIONS_DEFAULT
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_LOG_OPTIONS_DEFAULT), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ LLDPA_CONFIG_LOG_OPTIONS_DEFAULT(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_LOG_BITS_DEFAULT
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_LOG_BITS_DEFAULT), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ LLDPA_CONFIG_LOG_BITS_DEFAULT(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ LLDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_PORTING_STDLIB
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_PORTING_STDLIB), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_PORTING_STDLIB) },
#else
{ LLDPA_CONFIG_PORTING_STDLIB(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ LLDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LLDPA_CONFIG_INCLUDE_UCLI
    { __lldpa_config_STRINGIFY_NAME(LLDPA_CONFIG_INCLUDE_UCLI), __lldpa_config_STRINGIFY_VALUE(LLDPA_CONFIG_INCLUDE_UCLI) },
#else
{ LLDPA_CONFIG_INCLUDE_UCLI(__lldpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __lldpa_config_STRINGIFY_VALUE
#undef __lldpa_config_STRINGIFY_NAME

const char*
lldpa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; lldpa_config_settings[i].name; i++) {
        if(strcmp(lldpa_config_settings[i].name, setting)) {
            return lldpa_config_settings[i].value;
        }
    }
    return NULL;
}

int
lldpa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; lldpa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", lldpa_config_settings[i].name, lldpa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(LLDPA_CONFIG_HEADER).source> */

