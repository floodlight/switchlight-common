/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <sflowa/sflowa_config.h>

#include "sflowa_log.h"

static int
datatypes_init__(void)
{
#define SFLOWA_ENUMERATION_ENTRY(_enum_name, _desc)     AIM_DATATYPE_MAP_REGISTER(_enum_name, _enum_name##_map, _desc,                               AIM_LOG_INTERNAL);
#include <sflowa/sflowa.x>
    return 0;
}

void __sflowa_module_init__(void)
{
    AIM_LOG_STRUCT_REGISTER();
    datatypes_init__();
}

