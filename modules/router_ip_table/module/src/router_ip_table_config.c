/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <router_ip_table/router_ip_table_config.h>

/* <auto.start.cdefs(ROUTER_IP_TABLE_CONFIG_HEADER).source> */
#define __router_ip_table_config_STRINGIFY_NAME(_x) #_x
#define __router_ip_table_config_STRINGIFY_VALUE(_x) __router_ip_table_config_STRINGIFY_NAME(_x)
router_ip_table_config_settings_t router_ip_table_config_settings[] =
{
#ifdef ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING) },
#else
{ ROUTER_IP_TABLE_CONFIG_INCLUDE_LOGGING(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT) },
#else
{ ROUTER_IP_TABLE_CONFIG_LOG_OPTIONS_DEFAULT(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT) },
#else
{ ROUTER_IP_TABLE_CONFIG_LOG_BITS_DEFAULT(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT) },
#else
{ ROUTER_IP_TABLE_CONFIG_LOG_CUSTOM_BITS_DEFAULT(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB) },
#else
{ ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS) },
#else
{ ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
#ifdef ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI
    { __router_ip_table_config_STRINGIFY_NAME(ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI), __router_ip_table_config_STRINGIFY_VALUE(ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI) },
#else
{ ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI(__router_ip_table_config_STRINGIFY_NAME), "__undefined__" },
#endif
    { NULL, NULL }
};
#undef __router_ip_table_config_STRINGIFY_VALUE
#undef __router_ip_table_config_STRINGIFY_NAME

const char*
router_ip_table_config_lookup(const char* setting)
{
    int i;
    for(i = 0; router_ip_table_config_settings[i].name; i++) {
        if(strcmp(router_ip_table_config_settings[i].name, setting)) {
            return router_ip_table_config_settings[i].value;
        }
    }
    return NULL;
}

int
router_ip_table_config_show(struct aim_pvs_s* pvs)
{
    int i;
    for(i = 0; router_ip_table_config_settings[i].name; i++) {
        aim_printf(pvs, "%s = %s\n", router_ip_table_config_settings[i].name, router_ip_table_config_settings[i].value);
    }
    return i;
}

/* <auto.end.cdefs(ROUTER_IP_TABLE_CONFIG_HEADER).source> */

