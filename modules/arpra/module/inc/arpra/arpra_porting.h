/**************************************************************************//**
 *
 * @file
 * @brief arpra Porting Macros.
 *
 * @addtogroup arpra-porting
 * @{
 *
 *****************************************************************************/
#ifndef __ARPRA_PORTING_H__
#define __ARPRA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if ARPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef ARPRA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define ARPRA_MALLOC GLOBAL_MALLOC
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_MALLOC malloc
    #else
        #error The macro ARPRA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_FREE
    #if defined(GLOBAL_FREE)
        #define ARPRA_FREE GLOBAL_FREE
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_FREE free
    #else
        #error The macro ARPRA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define ARPRA_MEMSET GLOBAL_MEMSET
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_MEMSET memset
    #else
        #error The macro ARPRA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define ARPRA_MEMCPY GLOBAL_MEMCPY
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_MEMCPY memcpy
    #else
        #error The macro ARPRA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define ARPRA_STRNCPY GLOBAL_STRNCPY
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_STRNCPY strncpy
    #else
        #error The macro ARPRA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define ARPRA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_VSNPRINTF vsnprintf
    #else
        #error The macro ARPRA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define ARPRA_SNPRINTF GLOBAL_SNPRINTF
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_SNPRINTF snprintf
    #else
        #error The macro ARPRA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define ARPRA_STRLEN GLOBAL_STRLEN
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_STRLEN strlen
    #else
        #error The macro ARPRA_STRLEN is required but cannot be defined.
    #endif
#endif

#ifndef ARPRA_MEMCMP
    #if defined(GLOBAL_MEMCMP)
        #define ARPRA_MEMCMP GLOBAL_MEMCMP
    #elif ARPRA_CONFIG_PORTING_STDLIB == 1
        #define ARPRA_MEMCMP memcmp
    #else
        #error The macro ARPRA_MEMCMP is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __ARPRA_PORTING_H__ */
/* @} */
