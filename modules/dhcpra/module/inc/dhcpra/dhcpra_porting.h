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
 * @brief dhcpra Porting Macros.
 *
 * @addtogroup dhcpra-porting
 * @{
 *
 ****************************************************************/
#ifndef __DHCPRA_PORTING_H__
#define __DHCPRA_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if DHCPRA_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef DHCPRA_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define DHCPRA_MALLOC GLOBAL_MALLOC
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_MALLOC malloc
    #else
        #error The macro DHCPRA_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_FREE
    #if defined(GLOBAL_FREE)
        #define DHCPRA_FREE GLOBAL_FREE
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_FREE free
    #else
        #error The macro DHCPRA_FREE is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define DHCPRA_MEMSET GLOBAL_MEMSET
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_MEMSET memset
    #else
        #error The macro DHCPRA_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define DHCPRA_MEMCPY GLOBAL_MEMCPY
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_MEMCPY memcpy
    #else
        #error The macro DHCPRA_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define DHCPRA_STRNCPY GLOBAL_STRNCPY
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_STRNCPY strncpy
    #else
        #error The macro DHCPRA_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define DHCPRA_VSNPRINTF GLOBAL_VSNPRINTF
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_VSNPRINTF vsnprintf
    #else
        #error The macro DHCPRA_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define DHCPRA_SNPRINTF GLOBAL_SNPRINTF
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_SNPRINTF snprintf
    #else
        #error The macro DHCPRA_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef DHCPRA_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define DHCPRA_STRLEN GLOBAL_STRLEN
    #elif DHCPRA_CONFIG_PORTING_STDLIB == 1
        #define DHCPRA_STRLEN strlen
    #else
        #error The macro DHCPRA_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __DHCPRA_PORTING_H__ */
/* @} */
