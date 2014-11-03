/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <cdpa/cdpa_config.h>

/* <auto.start.cdefs(CDPA_CONFIG_HEADER).source> */
#define __cdpa_config_STRINGIFY_NAME(_x) #_x
#define __cdpa_config_STRINGIFY_VALUE(_x) __cdpa_config_STRINGIFY_NAME(_x)
cdpa_config_settings_t cdpa_config_settings[] =
{
#ifdef CDPA_CONFIG_INCLUDE_LOGGING
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_INCLUDE_LOGGING), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_INCLUDE_LOGGING) },
#else
{ CDPA_CONFIG_INCLUDE_LOGGING(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_LOG_OPTIONS_DEFAULT
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_LOG_OPTIONS_DEFAULT), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ CDPA_CONFIG_LOG_OPTIONS_DEFAULT(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_LOG_BITS_DEFAULT
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_LOG_BITS_DEFAULT), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ CDPA_CONFIG_LOG_BITS_DEFAULT(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ CDPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_PORTING_STDLIB
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_PORTING_STDLIB), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_PORTING_STDLIB) },
#else
{ CDPA_CONFIG_PORTING_STDLIB(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_INCLUDE_UCLI
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_INCLUDE_UCLI), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_INCLUDE_UCLI) },
#else
{ CDPA_CONFIG_INCLUDE_UCLI(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef CDPA_CONFIG_OF_PORTS_MAX
    { __cdpa_config_STRINGIFY_NAME(CDPA_CONFIG_OF_PORTS_MAX), __cdpa_config_STRINGIFY_VALUE(CDPA_CONFIG_OF_PORTS_MAX) },
#else
{ CDPA_CONFIG_OF_PORTS_MAX(__cdpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __cdpa_config_STRINGIFY_VALUE
#undef __cdpa_config_STRINGIFY_NAME

const char*
cdpa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; cdpa_config_settings[i].name; i++) {
        if(strcmp(cdpa_config_settings[i].name, setting)) {
            return cdpa_config_settings[i].value;
        }
    }
    return NULL;
}

int
cdpa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; cdpa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", cdpa_config_settings[i].name, cdpa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(CDPA_CONFIG_HEADER).source> */

