/**************************************************************************//**
 *
 * @file
 * @brief sflowa Porting Macros.
 *
 * @addtogroup sflowa-porting
 * @{
 *
 *****************************************************************************/
#ifndef __SFLOWA_PORTING_H__
#define __SFLOWA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if SFLOWA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef SFLOWA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define SFLOWA_MALLOC GLOBAL_MALLOC
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_MALLOC malloc
    #else
        #error The macro SFLOWA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_FREE
    #if defined(GLOBAL_FREE)
        #define SFLOWA_FREE GLOBAL_FREE
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_FREE free
    #else
        #error The macro SFLOWA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define SFLOWA_MEMSET GLOBAL_MEMSET
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_MEMSET memset
    #else
        #error The macro SFLOWA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define SFLOWA_MEMCPY GLOBAL_MEMCPY
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_MEMCPY memcpy
    #else
        #error The macro SFLOWA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define SFLOWA_STRNCPY GLOBAL_STRNCPY
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_STRNCPY strncpy
    #else
        #error The macro SFLOWA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define SFLOWA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_VSNPRINTF vsnprintf
    #else
        #error The macro SFLOWA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define SFLOWA_SNPRINTF GLOBAL_SNPRINTF
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_SNPRINTF snprintf
    #else
        #error The macro SFLOWA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef SFLOWA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define SFLOWA_STRLEN GLOBAL_STRLEN
    #elif SFLOWA_CONFIG_PORTING_STDLIB == 1
        #define SFLOWA_STRLEN strlen
    #else
        #error The macro SFLOWA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __SFLOWA_PORTING_H__ */
/* @} */
