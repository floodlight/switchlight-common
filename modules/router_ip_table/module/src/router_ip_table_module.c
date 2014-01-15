/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <router_ip_table/router_ip_table_config.h>

#include "router_ip_table_log.h"

static int
datatypes_init__(void)
{
#define ROUTER_IP_TABLE_ENUMERATION_ENTRY(_enum_name, _desc)     AIM_DATATYPE_MAP_REGISTER(_enum_name, _enum_name##_map, _desc,                               AIM_LOG_INTERNAL);
#include <router_ip_table/router_ip_table.x>
    return 0;
}

void __router_ip_table_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    datatypes_init__();
}

