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

#include <lacpa/lacpa_config.h>

/* <auto.start.cdefs(LACPA_CONFIG_HEADER).source> */
#define __lacpa_config_STRINGIFY_NAME(_x) #_x
#define __lacpa_config_STRINGIFY_VALUE(_x) __lacpa_config_STRINGIFY_NAME(_x)
lacpa_config_settings_t lacpa_config_settings[] =
{
#ifdef LACPA_CONFIG_INCLUDE_LOGGING
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_INCLUDE_LOGGING), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_INCLUDE_LOGGING) },
#else
{ LACPA_CONFIG_INCLUDE_LOGGING(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_LOG_OPTIONS_DEFAULT
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_LOG_OPTIONS_DEFAULT), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ LACPA_CONFIG_LOG_OPTIONS_DEFAULT(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_LOG_BITS_DEFAULT
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_LOG_BITS_DEFAULT), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ LACPA_CONFIG_LOG_BITS_DEFAULT(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ LACPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_PORTING_STDLIB
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_PORTING_STDLIB), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_PORTING_STDLIB) },
#else
{ LACPA_CONFIG_PORTING_STDLIB(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef LACPA_CONFIG_INCLUDE_UCLI
    { __lacpa_config_STRINGIFY_NAME(LACPA_CONFIG_INCLUDE_UCLI), __lacpa_config_STRINGIFY_VALUE(LACPA_CONFIG_INCLUDE_UCLI) },
#else
{ LACPA_CONFIG_INCLUDE_UCLI(__lacpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __lacpa_config_STRINGIFY_VALUE
#undef __lacpa_config_STRINGIFY_NAME

const char*
lacpa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; lacpa_config_settings[i].name; i++) {
        if(strcmp(lacpa_config_settings[i].name, setting)) {
            return lacpa_config_settings[i].value;
        }
    }
    return NULL;
}

int
lacpa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; lacpa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", lacpa_config_settings[i].name, lacpa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(LACPA_CONFIG_HEADER).source> */

