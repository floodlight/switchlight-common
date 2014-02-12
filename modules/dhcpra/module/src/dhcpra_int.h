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
 * dhcpra Internal Header
 *
 ****************************************************************/
#ifndef __DHCPRA_INT_H__
#define __DHCPRA_INT_H__

#include <dhcpra/dhcpra_config.h>

#include <loci/loci.h>

#define AIM_LOG_MODULE_NAME dhcpra
#include <AIM/aim_log.h>
#define DHCPRA_DEBUG(fmt, ...)                       \
            AIM_LOG_INFO(fmt, ##__VA_ARGS__)

/* 
 * Information about opt.
 * For option 82, Circuit ID and Remote ID are popular used
 * Currently BSN uses only Circuit ID
 * We decide to keep Remote ID for future supports
 */
typedef struct opt_info {
    of_octets_t circuit_id;
    of_octets_t remote_id;  
} opt_info_t;

typedef struct {
    uint32_t      internalVID;
    uint32_t      virtualRouterIP;
    uint32_t      dhcpServerIP;
    of_mac_addr_t virtualRouterMAC;
    opt_info_t    optID;
} dhc_relay_t;

#define VLAN_MAX 4095
#define INVALID_VLAN 0xffffffff

enum {
    DHCPRA_DUMP_DISABLE_ALL_PORTS = -2,
    DHCPRA_DUMP_ENABLE_ALL_PORTS  = -1
};

/* Set vlan to INVALID if not exist */
typedef void (*cir_to_vlan_fn)(uint32_t *vlan, u_int8_t *cir_id, int cir_id_len);

#endif /* __DHCPRA_INT_H__ */
