/**************************************************************************//**
 *
 * @file
 * @brief cdpa Porting Macros.
 *
 * @addtogroup cdpa-porting
 * @{
 *
 *****************************************************************************/
#ifndef __CDPA_PORTING_H__
#define __CDPA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if CDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef CDPA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define CDPA_MALLOC GLOBAL_MALLOC
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_MALLOC malloc
    #else
        #error The macro CDPA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_FREE
    #if defined(GLOBAL_FREE)
        #define CDPA_FREE GLOBAL_FREE
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_FREE free
    #else
        #error The macro CDPA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define CDPA_MEMSET GLOBAL_MEMSET
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_MEMSET memset
    #else
        #error The macro CDPA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define CDPA_MEMCPY GLOBAL_MEMCPY
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_MEMCPY memcpy
    #else
        #error The macro CDPA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define CDPA_STRNCPY GLOBAL_STRNCPY
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_STRNCPY strncpy
    #else
        #error The macro CDPA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define CDPA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_VSNPRINTF vsnprintf
    #else
        #error The macro CDPA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define CDPA_SNPRINTF GLOBAL_SNPRINTF
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_SNPRINTF snprintf
    #else
        #error The macro CDPA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef CDPA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define CDPA_STRLEN GLOBAL_STRLEN
    #elif CDPA_CONFIG_PORTING_STDLIB == 1
        #define CDPA_STRLEN strlen
    #else
        #error The macro CDPA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __CDPA_PORTING_H__ */
/* @} */
