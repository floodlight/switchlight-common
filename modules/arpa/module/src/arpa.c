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

#include <arpa/arpa.h>
#include <indigo/of_state_manager.h>

#include "arpa_log.h"

static indigo_core_gentable_t *arp_table;

static const indigo_core_gentable_ops_t arp_ops;


/* Public interface */

indigo_error_t
arpa_init()
{
    indigo_core_gentable_register("arp", &arp_ops, NULL, 16384, 1024,
                                  &arp_table);

    return INDIGO_ERROR_NONE;
}

void
arpa_finish()
{
    indigo_core_gentable_unregister(arp_table);
}


/* arp table operations */

static indigo_error_t
arp_parse_key(of_list_bsn_tlv_t *key, uint16_t *vlan, uint32_t *ip)
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

    if (of_list_bsn_tlv_next(key, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of key list");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv.ipv4, ip);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(key, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_parse_value(of_list_bsn_tlv_t *value, of_mac_addr_t *mac)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(value, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
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
arp_add(void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    uint16_t vlan;
    uint32_t ip;
    of_mac_addr_t mac;

    rv = arp_parse_key(key, &vlan, &ip);
    if (rv < 0) {
        return rv;
    }

    rv = arp_parse_value(value, &mac);
    if (rv < 0) {
        return rv;
    }

    *entry_priv = NULL;
    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    of_mac_addr_t mac;

    rv = arp_parse_value(value, &mac);
    if (rv < 0) {
        return rv;
    }

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
arp_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    return INDIGO_ERROR_NONE;
}

static void
arp_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
}

static const indigo_core_gentable_ops_t arp_ops = {
    .add = arp_add,
    .modify = arp_modify,
    .del = arp_delete,
    .get_stats = arp_get_stats,
};
