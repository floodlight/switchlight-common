/**************************************************************************//**
 *
 * @file
 * @brief router_ip_table Porting Macros.
 *
 * @addtogroup router_ip_table-porting
 * @{
 *
 *****************************************************************************/
#ifndef __ROUTER_IP_TABLE_PORTING_H__
#define __ROUTER_IP_TABLE_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if ROUTER_IP_TABLE_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef ROUTER_IP_TABLE_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define ROUTER_IP_TABLE_MALLOC GLOBAL_MALLOC
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_MALLOC malloc
    #else
        #error The macro ROUTER_IP_TABLE_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_FREE
    #if defined(GLOBAL_FREE)
        #define ROUTER_IP_TABLE_FREE GLOBAL_FREE
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_FREE free
    #else
        #error The macro ROUTER_IP_TABLE_FREE is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define ROUTER_IP_TABLE_MEMSET GLOBAL_MEMSET
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_MEMSET memset
    #else
        #error The macro ROUTER_IP_TABLE_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define ROUTER_IP_TABLE_MEMCPY GLOBAL_MEMCPY
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_MEMCPY memcpy
    #else
        #error The macro ROUTER_IP_TABLE_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define ROUTER_IP_TABLE_STRNCPY GLOBAL_STRNCPY
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_STRNCPY strncpy
    #else
        #error The macro ROUTER_IP_TABLE_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define ROUTER_IP_TABLE_VSNPRINTF GLOBAL_VSNPRINTF
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_VSNPRINTF vsnprintf
    #else
        #error The macro ROUTER_IP_TABLE_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define ROUTER_IP_TABLE_SNPRINTF GLOBAL_SNPRINTF
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_SNPRINTF snprintf
    #else
        #error The macro ROUTER_IP_TABLE_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ROUTER_IP_TABLE_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define ROUTER_IP_TABLE_STRLEN GLOBAL_STRLEN
    #elif ROUTER_IP_TABLE_CONFIG_PORTING_STDLIB == 1
        #define ROUTER_IP_TABLE_STRLEN strlen
    #else
        #error The macro ROUTER_IP_TABLE_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __ROUTER_IP_TABLE_PORTING_H__ */
/* @} */
