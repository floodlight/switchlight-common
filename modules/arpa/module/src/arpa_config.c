/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <arpa/arpa_config.h>

/* <auto.start.cdefs(ARPA_CONFIG_HEADER).source> */
#define __arpa_config_STRINGIFY_NAME(_x) #_x
#define __arpa_config_STRINGIFY_VALUE(_x) __arpa_config_STRINGIFY_NAME(_x)
arpa_config_settings_t arpa_config_settings[] =
{
#ifdef ARPA_CONFIG_INCLUDE_LOGGING
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_INCLUDE_LOGGING), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_INCLUDE_LOGGING) },
#else
{ ARPA_CONFIG_INCLUDE_LOGGING(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_LOG_OPTIONS_DEFAULT
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_LOG_OPTIONS_DEFAULT), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ ARPA_CONFIG_LOG_OPTIONS_DEFAULT(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_LOG_BITS_DEFAULT
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_LOG_BITS_DEFAULT), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ ARPA_CONFIG_LOG_BITS_DEFAULT(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ ARPA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_PORTING_STDLIB
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_PORTING_STDLIB), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_PORTING_STDLIB) },
#else
{ ARPA_CONFIG_PORTING_STDLIB(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPA_CONFIG_INCLUDE_UCLI
    { __arpa_config_STRINGIFY_NAME(ARPA_CONFIG_INCLUDE_UCLI), __arpa_config_STRINGIFY_VALUE(ARPA_CONFIG_INCLUDE_UCLI) },
#else
{ ARPA_CONFIG_INCLUDE_UCLI(__arpa_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __arpa_config_STRINGIFY_VALUE
#undef __arpa_config_STRINGIFY_NAME

const char*
arpa_config_lookup(const char* setting)
{
    int i;
    for(i = 0; arpa_config_settings[i].name; i++) {
        if(strcmp(arpa_config_settings[i].name, setting)) {
            return arpa_config_settings[i].value;
        }
    }
    return NULL;
}

int
arpa_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; arpa_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", arpa_config_settings[i].name, arpa_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(ARPA_CONFIG_HEADER).source> */

