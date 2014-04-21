/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <arpra/arpra_config.h>

/* <auto.start.cdefs(ARPRA_CONFIG_HEADER).source> */
#define __arpra_config_STRINGIFY_NAME(_x) #_x
#define __arpra_config_STRINGIFY_VALUE(_x) __arpra_config_STRINGIFY_NAME(_x)
arpra_config_settings_t arpra_config_settings[] =
{
#ifdef ARPRA_CONFIG_INCLUDE_LOGGING
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_INCLUDE_LOGGING), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_INCLUDE_LOGGING) },
#else
{ ARPRA_CONFIG_INCLUDE_LOGGING(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_LOG_OPTIONS_DEFAULT
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_LOG_OPTIONS_DEFAULT), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ ARPRA_CONFIG_LOG_OPTIONS_DEFAULT(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_LOG_BITS_DEFAULT
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_LOG_BITS_DEFAULT), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_LOG_BITS_DEFAULT) },
#else
{ ARPRA_CONFIG_LOG_BITS_DEFAULT(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ ARPRA_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_PORTING_STDLIB
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_PORTING_STDLIB), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_PORTING_STDLIB) },
#else
{ ARPRA_CONFIG_PORTING_STDLIB(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ARPRA_CONFIG_INCLUDE_UCLI
    { __arpra_config_STRINGIFY_NAME(ARPRA_CONFIG_INCLUDE_UCLI), __arpra_config_STRINGIFY_VALUE(ARPRA_CONFIG_INCLUDE_UCLI) },
#else
{ ARPRA_CONFIG_INCLUDE_UCLI(__arpra_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __arpra_config_STRINGIFY_VALUE
#undef __arpra_config_STRINGIFY_NAME

const char*
arpra_config_lookup(const char* setting)
{
    int i;
    for(i = 0; arpra_config_settings[i].name; i++) {
        if(strcmp(arpra_config_settings[i].name, setting)) {
            return arpra_config_settings[i].value;
        }
    }
    return NULL;
}

int
arpra_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; arpra_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", arpra_config_settings[i].name, arpra_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(ARPRA_CONFIG_HEADER).source> */

