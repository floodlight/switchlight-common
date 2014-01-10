/**************************************************************************//**
 *
 * @file
 * @brief arpa Porting Macros.
 *
 * @addtogroup arpa-porting
 * @{
 *
 *****************************************************************************/
#ifndef __ARPA_PORTING_H__
#define __ARPA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if ARPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef ARPA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define ARPA_MALLOC GLOBAL_MALLOC
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_MALLOC malloc
    #else
        #error The macro ARPA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_FREE
    #if defined(GLOBAL_FREE)
        #define ARPA_FREE GLOBAL_FREE
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_FREE free
    #else
        #error The macro ARPA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define ARPA_MEMSET GLOBAL_MEMSET
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_MEMSET memset
    #else
        #error The macro ARPA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define ARPA_MEMCPY GLOBAL_MEMCPY
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_MEMCPY memcpy
    #else
        #error The macro ARPA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define ARPA_STRNCPY GLOBAL_STRNCPY
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_STRNCPY strncpy
    #else
        #error The macro ARPA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define ARPA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_VSNPRINTF vsnprintf
    #else
        #error The macro ARPA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define ARPA_SNPRINTF GLOBAL_SNPRINTF
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_SNPRINTF snprintf
    #else
        #error The macro ARPA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ARPA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define ARPA_STRLEN GLOBAL_STRLEN
    #elif ARPA_CONFIG_PORTING_STDLIB == 1
        #define ARPA_STRLEN strlen
    #else
        #error The macro ARPA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __ARPA_PORTING_H__ */
/* @} */
