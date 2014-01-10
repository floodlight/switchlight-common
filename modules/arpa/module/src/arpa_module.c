/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <arpa/arpa_config.h>

#include "arpa_log.h"

static int
datatypes_init__(void)
{
#define ARPA_ENUMERATION_ENTRY(_enum_name, _desc)     AIM_DATATYPE_MAP_REGISTER(_enum_name, _enum_name##_map, _desc,                               AIM_LOG_INTERNAL);
#include <arpa/arpa.x>
    return 0;
}

void __arpa_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    datatypes_init__();
}

