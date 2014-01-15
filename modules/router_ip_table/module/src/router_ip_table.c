/****************************************************************
 *
 *        Copyright 2014, Big Switch Networks, Inc.
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

#include <router_ip_table/router_ip_table.h>
#include <indigo/of_state_manager.h>

#include "router_ip_table_log.h"

#define MAX_VLAN 4095
#define INVALID_IP 0

struct router_ip_entry {
    uint32_t ip;
};

static indigo_core_gentable_t *router_ip_table;

static const indigo_core_gentable_ops_t router_ip_ops;

static struct router_ip_entry router_ips[MAX_VLAN+1];


/* Public interface */

indigo_error_t
router_ip_table_init()
{
    indigo_core_gentable_register("router_ip", &router_ip_ops, NULL, MAX_VLAN+1, 256,
                                  &router_ip_table);

    return INDIGO_ERROR_NONE;
}

void
router_ip_table_finish()
{
    indigo_core_gentable_unregister(router_ip_table);
}

indigo_error_t
router_ip_table_lookup(uint16_t vlan, uint32_t *ip)
{
    if (vlan > MAX_VLAN) {
        return INDIGO_ERROR_RANGE;
    }

    struct router_ip_entry *entry = &router_ips[vlan];
    if (entry->ip == INVALID_IP) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *ip = entry->ip;
    return INDIGO_ERROR_NONE;
}


/* router_ip table operations */

static indigo_error_t
router_ip_parse_key(of_list_bsn_tlv_t *key, uint16_t *vlan)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(key, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_VLAN_VID) {
        of_bsn_tlv_vlan_vid_value_get(&tlv.vlan_vid, vlan);
    } else {
        AIM_LOG_ERROR("expected vlan key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*vlan > MAX_VLAN) {
        AIM_LOG_ERROR("VLAN out of range (%u)", *vlan);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(key, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_parse_value(of_list_bsn_tlv_t *value, uint32_t *ip)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(value, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv.ipv4, ip);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*ip == INVALID_IP) {
        AIM_LOG_ERROR("IP invalid (%u)", *ip);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(value, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_add(void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    uint16_t vlan;
    uint32_t ip;

    rv = router_ip_parse_key(key, &vlan);
    if (rv < 0) {
        return rv;
    }

    rv = router_ip_parse_value(value, &ip);
    if (rv < 0) {
        return rv;
    }

    struct router_ip_entry *entry = &router_ips[vlan];
    entry->ip = ip;

    *entry_priv = entry;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    uint32_t ip;
    struct router_ip_entry *entry = entry_priv;

    rv = router_ip_parse_value(value, &ip);
    if (rv < 0) {
        return rv;
    }

    entry->ip = ip;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct router_ip_entry *entry = entry_priv;
    entry->ip = INVALID_IP;
    return INDIGO_ERROR_NONE;
}

static void
router_ip_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
}

static const indigo_core_gentable_ops_t router_ip_ops = {
    .add = router_ip_add,
    .modify = router_ip_modify,
    .del = router_ip_delete,
    .get_stats = router_ip_get_stats,
};
