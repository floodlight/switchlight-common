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
#include <BigHash/bighash.h>
#include <AIM/aim_list.h>

#include "router_ip_table_log.h"

#define MAX_VLAN 4095
#define INVALID_IP 0

struct router_ip_entry {
    bighash_entry_t hash_entry;
    uint32_t ip;
    of_mac_addr_t mac;
};

#define TEMPLATE_NAME router_ip_enteries_hashtable
#define TEMPLATE_OBJ_TYPE struct router_ip_entry
#define TEMPLATE_KEY_FIELD ip 
#define TEMPLATE_ENTRY_FIELD hash_entry
#include <BigHash/bighash_template.h>

static indigo_core_gentable_t *router_ip_table;

static const indigo_core_gentable_ops_t router_ip_ops;

static struct router_ip_entry router_ips[MAX_VLAN+1];

static bighash_table_t *router_ip_enteries;

/* Public interface */

indigo_error_t
router_ip_table_init()
{
    indigo_core_gentable_register("router_ip", &router_ip_ops, NULL, MAX_VLAN+1, 256,
                                  &router_ip_table);
    router_ip_enteries = bighash_table_create(MAX_VLAN+1);

    return INDIGO_ERROR_NONE;
}

void
router_ip_table_finish()
{
    indigo_core_gentable_unregister(router_ip_table);
    bighash_table_destroy(router_ip_enteries, NULL);
}

indigo_error_t
router_ip_table_lookup(uint16_t vlan, uint32_t *ip, of_mac_addr_t *mac)
{
    if (vlan > MAX_VLAN) {
        return INDIGO_ERROR_RANGE;
    }

    struct router_ip_entry *entry = &router_ips[vlan];
    if (entry->ip == INVALID_IP) {
        return INDIGO_ERROR_NOT_FOUND;
    }

    *ip = entry->ip;
    *mac = entry->mac;
    return INDIGO_ERROR_NONE;
}

bool
is_router_ip(uint32_t ip)
{
    struct router_ip_entry *entry = router_ip_enteries_hashtable_first(
                                        router_ip_enteries, &ip);
    if (entry == NULL) {
        return false;
    } 

    return true;
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
router_ip_parse_value(of_list_bsn_tlv_t *value, uint32_t *ip, of_mac_addr_t *mac)
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

    if (of_list_bsn_tlv_next(value, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_MAC) {
        of_bsn_tlv_mac_value_get(&tlv.mac, mac);
    } else {
        AIM_LOG_ERROR("expected mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
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
    of_mac_addr_t mac;

    rv = router_ip_parse_key(key, &vlan);
    if (rv < 0) {
        return rv;
    }

    rv = router_ip_parse_value(value, &ip, &mac);
    if (rv < 0) {
        return rv;
    }

    struct router_ip_entry *entry = &router_ips[vlan];
    entry->ip = ip;
    entry->mac = mac;

    *entry_priv = entry;

    router_ip_enteries_hashtable_insert(router_ip_enteries, entry);

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    uint32_t ip;
    struct router_ip_entry *entry = entry_priv;
    of_mac_addr_t mac;

    rv = router_ip_parse_value(value, &ip, &mac);
    if (rv < 0) {
        return rv;
    }
   
    bighash_remove(router_ip_enteries, &entry->hash_entry); 
     
    entry->ip = ip;
    entry->mac = mac;

    router_ip_enteries_hashtable_insert(router_ip_enteries, entry); 
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
router_ip_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    struct router_ip_entry *entry = entry_priv;
    bighash_remove(router_ip_enteries, &entry->hash_entry);
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
