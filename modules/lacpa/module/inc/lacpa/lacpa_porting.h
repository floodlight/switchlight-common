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
 * @brief lacpa Porting Macros.
 *
 * @addtogroup lacpa-porting
 * @{
 *
 ****************************************************************/
#ifndef __LACPA_PORTING_H__
#define __LACPA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if LACPA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef LACPA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define LACPA_MALLOC GLOBAL_MALLOC
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_MALLOC malloc
    #else
        #error The macro LACPA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_FREE
    #if defined(GLOBAL_FREE)
        #define LACPA_FREE GLOBAL_FREE
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_FREE free
    #else
        #error The macro LACPA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define LACPA_MEMSET GLOBAL_MEMSET
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_MEMSET memset
    #else
        #error The macro LACPA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define LACPA_MEMCPY GLOBAL_MEMCPY
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_MEMCPY memcpy
    #else
        #error The macro LACPA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define LACPA_STRNCPY GLOBAL_STRNCPY
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_STRNCPY strncpy
    #else
        #error The macro LACPA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define LACPA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_VSNPRINTF vsnprintf
    #else
        #error The macro LACPA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define LACPA_SNPRINTF GLOBAL_SNPRINTF
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_SNPRINTF snprintf
    #else
        #error The macro LACPA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef LACPA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define LACPA_STRLEN GLOBAL_STRLEN
    #elif LACPA_CONFIG_PORTING_STDLIB == 1
        #define LACPA_STRLEN strlen
    #else
        #error The macro LACPA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __LACPA_PORTING_H__ */
/* @} */
