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
 * @brief lldpa Porting Macros.
 *
 * @addtogroup lldpa-porting
 * @{
 *
 ****************************************************************/
#ifndef __LLDPA_PORTING_H__
#define __LLDPA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if LLDPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef LLDPA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define LLDPA_MALLOC GLOBAL_MALLOC
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_MALLOC malloc
    #else
        #error The macro LLDPA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_FREE
    #if defined(GLOBAL_FREE)
        #define LLDPA_FREE GLOBAL_FREE
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_FREE free
    #else
        #error The macro LLDPA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define LLDPA_MEMSET GLOBAL_MEMSET
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_MEMSET memset
    #else
        #error The macro LLDPA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define LLDPA_MEMCPY GLOBAL_MEMCPY
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_MEMCPY memcpy
    #else
        #error The macro LLDPA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define LLDPA_STRNCPY GLOBAL_STRNCPY
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_STRNCPY strncpy
    #else
        #error The macro LLDPA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define LLDPA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_VSNPRINTF vsnprintf
    #else
        #error The macro LLDPA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define LLDPA_SNPRINTF GLOBAL_SNPRINTF
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_SNPRINTF snprintf
    #else
        #error The macro LLDPA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef LLDPA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define LLDPA_STRLEN GLOBAL_STRLEN
    #elif LLDPA_CONFIG_PORTING_STDLIB == 1
        #define LLDPA_STRLEN strlen
    #else
        #error The macro LLDPA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __LLDPA_PORTING_H__ */
/* @} */
