/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <sflowa/sflowa_config.h>

/* <auto.start.cdefs(SFLOWA_CONFIG_HEADER).source> */
#define __sflowa_config_STRINGIFY_NAME(_x) #_x
#define __sflowa_config_STRINGIFY_VALUE(_x) __sflowa_config_STRINGIFY_NAME(_x)
sflowa_config_settings_t sflowa_config_settings[] =
{
#ifdef SFLOWA_CONFIG_INCLUDE_LOGGING
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_INCLUDE_LOGGING), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_INCLUDE_LOGGING) },
#else
{ SFLOWA_CONFIG_INCLUDE_LOGGING(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ SFLOWA_CONFIG_LOG_OPTIONS_DEFAULT(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_LOG_BITS_DEFAULT
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_LOG_BITS_DEFAULT), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ SFLOWA_CONFIG_LOG_BITS_DEFAULT(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ SFLOWA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_PORTING_STDLIB
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_PORTING_STDLIB), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_PORTING_STDLIB) },
#else
{ SFLOWA_CONFIG_PORTING_STDLIB(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef SFLOWA_CONFIG_INCLUDE_UCLI
    { __sflowa_config_STRINGIFY_NAME(SFLOWA_CONFIG_INCLUDE_UCLI), __sflowa_config_STRINGIFY_VALUE(SFLOWA_CONFIG_INCLUDE_UCLI) },
#else
{ SFLOWA_CONFIG_INCLUDE_UCLI(__sflowa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __sflowa_config_STRINGIFY_VALUE
#undef __sflowa_config_STRINGIFY_NAME

const char*
sflowa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; sflowa_config_settings[i].name; i++) {
        if(strcmp(sflowa_config_settings[i].name, setting)) {
            return sflowa_config_settings[i].value;
        }
    }
    return NULL;
}

int
sflowa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; sflowa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", sflowa_config_settings[i].name, sflowa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(SFLOWA_CONFIG_HEADER).source> */

