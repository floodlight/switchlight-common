/****************************************************************
 *
 *        Copyright 2013, Big Switch Networks, Inc.
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *        http://www.eclipse.org/legal/epl-v10.html
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 *
 ****************************************************************/

/*************************************************************//**
 *
 * @file
 * @brief icmpa Porting Macros.
 *
 * @addtogroup icmpa-porting
 * @{
 *
 ****************************************************************/
#ifndef __ICMPA_PORTING_H__
#define __ICMPA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if ICMPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef ICMPA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define ICMPA_MALLOC GLOBAL_MALLOC
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_MALLOC malloc
    #else
        #error The macro ICMPA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_FREE
    #if defined(GLOBAL_FREE)
        #define ICMPA_FREE GLOBAL_FREE
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_FREE free
    #else
        #error The macro ICMPA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define ICMPA_MEMSET GLOBAL_MEMSET
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_MEMSET memset
    #else
        #error The macro ICMPA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define ICMPA_MEMCPY GLOBAL_MEMCPY
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_MEMCPY memcpy
    #else
        #error The macro ICMPA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define ICMPA_STRNCPY GLOBAL_STRNCPY
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_STRNCPY strncpy
    #else
        #error The macro ICMPA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define ICMPA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_VSNPRINTF vsnprintf
    #else
        #error The macro ICMPA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define ICMPA_SNPRINTF GLOBAL_SNPRINTF
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_SNPRINTF snprintf
    #else
        #error The macro ICMPA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef ICMPA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define ICMPA_STRLEN GLOBAL_STRLEN
    #elif ICMPA_CONFIG_PORTING_STDLIB == 1
        #define ICMPA_STRLEN strlen
    #else
        #error The macro ICMPA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __ICMPA_PORTING_H__ */
/* @} */
