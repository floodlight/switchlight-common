
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

#include "dhcpra_int.h"
#include "dhcpr_table.h"
#include <indigo/of_state_manager.h>
#include <BigHash/bighash.h>
#include <murmur/murmur.h>
#include <AIM/aim_list.h> /* for container_of */

#define INVALID_IP 0

static indigo_core_gentable_t *dhcpr_table;
static const indigo_core_gentable_ops_t dhcpr_table_ops;

/* This is the main table to keep the relay configuration*/
static dhc_relay_t *dhcpr_vlan_table[VLAN_MAX+1];
static int dhcpr_vlan_entry_count;

/* This is aux tables for other lookup purpose only */
BIGHASH_DEFINE_STATIC(dhcpr_circuit_table, 256); /* Circuit to vlan */
BIGHASH_DEFINE_STATIC(dhcpr_vrouter_ip_table, 256); /* Virtual router ip to vlan */

#define DHCPR_TABLE_DEBUG(fmt, ...)                       \
            AIM_LOG_TRACE(fmt, ##__VA_ARGS__)

/* static string storage variable return */
static char*
dhcpr_inet_ntoa (uint32_t in)
{
    static char ret[18];
    register uint8_t *p = (uint8_t *)&in;
    aim_snprintf(ret, sizeof(ret),
        "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
    return ret;
}

static void
dhcpr_free_circuit_id(of_octets_t *circuit_id)
{
    if (circuit_id->data) {
        AIM_TRUE_OR_DIE(circuit_id->bytes);
        aim_free(circuit_id->data);
        circuit_id->bytes = 0;
        circuit_id->data = NULL;
    } else {
        AIM_TRUE_OR_DIE(circuit_id->bytes == 0);
    }
}

static void
dhcpr_free_dhc_relay(dhc_relay_t *de)
{
    AIM_TRUE_OR_DIE(de);
    dhcpr_free_circuit_id(&de->opt_id.circuit_id);
    aim_free(de);
}

static bool
is_valid_vlan_value (uint32_t vlan)
{
    return (vlan <= VLAN_MAX);
}

static uint32_t
hash_octet_key(of_octets_t *data)
{
    return murmur_hash(data->data, data->bytes, 0);
}

static bool
is_key_equal(of_octets_t *k1, of_octets_t *k2)
{
    if (k1->bytes != k2->bytes) {
        return false;
    }

    return memcmp(k1->data, k2->data, k1->bytes) == 0;
}

static dhc_relay_t *
find_hash_entry_by_octet_id(bighash_table_t *table, of_octets_t *id)
{
    bighash_entry_t *e;
    for (e = bighash_first(table, hash_octet_key(id)); e; e = bighash_next(e)) {
        dhc_relay_t *te = container_of(e, circuit_hash_entry, dhc_relay_t);
        if (is_key_equal(&te->opt_id.circuit_id, id))
            return te;
    }
    return NULL;
}

static uint32_t
hash_ip_key(uint32_t ip)
{
    return murmur_hash(&ip, sizeof(ip), 0);
}

static dhc_relay_t *
find_hash_entry_by_virtual_router_ip(bighash_table_t *table,  uint32_t vr_ip)
{
    bighash_entry_t *e;
    for (e = bighash_first(table, hash_ip_key(vr_ip)); e; e = bighash_next(e)) {
        dhc_relay_t *te = container_of(e, vrouter_hash_entry, dhc_relay_t);
        if (te->vrouter_ip == vr_ip)
            return te;
    }
    return NULL;
}

/* dhcpr table operations */
static indigo_error_t
dhcpr_table_parse_key(of_list_bsn_tlv_t *key, uint16_t *vlan)
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

    if (!is_valid_vlan_value(*vlan)) {
        AIM_LOG_ERROR("VLAN out of range (%u)", *vlan);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(key, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    DHCPR_TABLE_DEBUG("dhc_relay entry key=%u", *vlan);
    return INDIGO_ERROR_NONE;
}

/*
 * Allocate memory for circuit id (cid) if necessary
 * Otherwise, set it to null
 *
 * Return error (<0) will never allocate any memory
 * */
static indigo_error_t
dhcpr_table_parse_value(of_list_bsn_tlv_t *value, uint32_t *vr_ip, of_mac_addr_t *vr_mac,
                                uint32_t *dhcp_ser_ip, of_octets_t *cid)
{
    of_bsn_tlv_t  tlv;
    of_octets_t   temp_cid;

    temp_cid.bytes = 0;
    temp_cid.data  = NULL;

    /* Gateway - Virtual router IP */
    if (of_list_bsn_tlv_first(value, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list, expect gateway router ip");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv.ipv4, vr_ip);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*vr_ip == INVALID_IP) {
        AIM_LOG_ERROR("IP invalid (%u)", *vr_ip);
        return INDIGO_ERROR_PARAM;
    }

    /* 2. Virtual Router Mac */
    if (of_list_bsn_tlv_next(value, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list, expect MAC");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_MAC) {
        of_bsn_tlv_mac_value_get(&tlv.mac, vr_mac);
    } else {
        AIM_LOG_ERROR("expected mac value TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    /* 3. DHCP Server IP */
    if (of_list_bsn_tlv_next(value, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list, expect DHCP ip");
        return INDIGO_ERROR_PARAM;
    }

    if (tlv.header.object_id == OF_BSN_TLV_IPV4) {
        of_bsn_tlv_ipv4_value_get(&tlv.ipv4, dhcp_ser_ip);
    } else {
        AIM_LOG_ERROR("expected ipv4 key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*dhcp_ser_ip == INVALID_IP) {
        AIM_LOG_ERROR("IP invalid (%u)", *dhcp_ser_ip);
        return INDIGO_ERROR_PARAM;
    }

    /* 4. Circuit ID if any */
    if (of_list_bsn_tlv_next(value, &tlv) < 0) {

        /* End of tlv list */

    } else if (tlv.header.object_id == OF_BSN_TLV_CIRCUIT_ID) {
        of_bsn_tlv_circuit_id_value_get(&tlv.circuit_id, &temp_cid);
        if(temp_cid.bytes==0) {
            AIM_LOG_ERROR("Expected circuit_id len != 0");
            return INDIGO_ERROR_PARAM;
        }
    } else {
        AIM_LOG_ERROR("expected circuit_id key TLV, instead got %s", of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    cid->bytes = temp_cid.bytes;
    cid->data  = NULL;
    if (temp_cid.bytes) {
        cid->data = aim_memdup(temp_cid.data, temp_cid.bytes);
    }

    DHCPR_TABLE_DEBUG("dhc_relay entry value:");
    DHCPR_TABLE_DEBUG("virtual router ip %s", dhcpr_inet_ntoa(*vr_ip));
    DHCPR_TABLE_DEBUG("Mac address %x:%x:%x:%x:%x:%x",
                        vr_mac->addr[0], vr_mac->addr[1], vr_mac->addr[2],
                        vr_mac->addr[3], vr_mac->addr[4], vr_mac->addr[5]);
    DHCPR_TABLE_DEBUG("Dhcp server ip %s", dhcpr_inet_ntoa(*dhcp_ser_ip));
    DHCPR_TABLE_DEBUG("CIRCUIT_ID: len=%d packet=%{data}",
                           temp_cid.bytes, temp_cid.data, temp_cid.bytes);

    return INDIGO_ERROR_NONE;
}

/*
 * We have 2 internal tables
 * Allocate 1 hash entry
 * If return error, caller doesn't need to free any memory
 */
static indigo_error_t
dhcpr_add_entry_to_internal_tables(dhc_relay_t *entry)
{

    if(dhcpr_vlan_table[entry->internal_vlan_id]) {
        AIM_LOG_ERROR("Error vlan entry = %u exists", entry->internal_vlan_id);
        return INDIGO_ERROR_EXISTS;
    }

    /*
     * Vlan and virtualRtouerIP is a mapping 1:1
     * New vlan entry: new virtual_router_ip
     */
    if(find_hash_entry_by_virtual_router_ip(&dhcpr_vrouter_ip_table, entry->vrouter_ip)) {
        AIM_LOG_ERROR("Virtual Router entry exists for vlan=%u", entry->internal_vlan_id);
        return INDIGO_ERROR_EXISTS;
    }

    /* Circuit exist, then check and prepare a circuit hash entry */
    if(entry->opt_id.circuit_id.data) {
        /*
         * Error: if circuit_id exists
         * Vlan and circuit_id is a mapping 1:1
         */
        if(find_hash_entry_by_octet_id(&dhcpr_circuit_table, &entry->opt_id.circuit_id)) {
            AIM_LOG_ERROR("Circuit id exists for vlan=%u", entry->internal_vlan_id);
            return INDIGO_ERROR_EXISTS;
        }

        bighash_insert(&dhcpr_circuit_table, &entry->circuit_hash_entry, hash_octet_key(&entry->opt_id.circuit_id));
    }

    bighash_insert(&dhcpr_vrouter_ip_table, &entry->vrouter_hash_entry, hash_ip_key(entry->vrouter_ip));

    dhcpr_vlan_table[entry->internal_vlan_id] = entry;
    dhcpr_vlan_entry_count++;

    return INDIGO_ERROR_NONE;
}


static indigo_error_t
dhcpr_table_add(void *table_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value, void **entry_priv)
{
    indigo_error_t rv;
    uint16_t       vlan;
    uint32_t       vr_ip;
    of_mac_addr_t  vr_mac;
    uint32_t       dhcp_server_ip;
    of_octets_t    circuit_id;
    dhc_relay_t    *entry = NULL;

    rv = dhcpr_table_parse_key(key, &vlan);
    if (rv < 0) {
        return rv;
    }

    rv = dhcpr_table_parse_value(value, &vr_ip, &vr_mac, &dhcp_server_ip, &circuit_id);
    if (rv < 0) {
        return rv;
    }

    entry = aim_zmalloc(sizeof(dhc_relay_t));

    /* Set key */
    entry->internal_vlan_id = vlan;

    /* Set value */
    entry->vrouter_ip = vr_ip;
    entry->vrouter_mac = vr_mac;
    entry->dhcp_server_ip = dhcp_server_ip;

    /* Circuit id assigned to the entry */
    entry->opt_id.circuit_id.bytes = circuit_id.bytes;
    entry->opt_id.circuit_id.data = circuit_id.data;

    rv = dhcpr_add_entry_to_internal_tables(entry);
    if (rv == INDIGO_ERROR_NONE) {
        *entry_priv = entry;
    } else {
        /* Free entry and all internal data */
        dhcpr_free_dhc_relay(entry);
    }

    return rv;
}

static indigo_error_t
dhcpr_table_modify(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *value)
{
    indigo_error_t rv;
    uint32_t       vr_ip;
    of_mac_addr_t  vr_mac;
    uint32_t       dhcp_server_ip;
    of_octets_t    circuit_id;
    /* We already find the entry and it is here */
    dhc_relay_t    *entry = entry_priv;
    dhc_relay_t    *de;

    rv = dhcpr_table_parse_value(value, &vr_ip, &vr_mac, &dhcp_server_ip, &circuit_id);
    if (rv < 0) {
        return rv;
    }
    /* From this point, must free circuit_id whenever return error */

    /* Legality check - make sure hash is not corrupted */
    de = find_hash_entry_by_virtual_router_ip(&dhcpr_vrouter_ip_table, entry->vrouter_ip);
    AIM_TRUE_OR_DIE(de && de == entry);
    if (entry->opt_id.circuit_id.bytes) {
        de =  find_hash_entry_by_octet_id(&dhcpr_circuit_table, &entry->opt_id.circuit_id);
        AIM_TRUE_OR_DIE(de && (de == entry));
    }

    /* 1. Validate and update circuit if necessary */
    if ((entry->opt_id.circuit_id.bytes == circuit_id.bytes) &&
                (memcmp(entry->opt_id.circuit_id.data, circuit_id.data, circuit_id.bytes) == 0)) {

        /* 2 circuits identical: do not update circuit hash table
         * Free new circuit
         * */
        dhcpr_free_circuit_id(&circuit_id);
    } else {
        /* 2 circuits different, we need update circuit id */

        /* Validate the new circuit and return error before making any change */
        if(circuit_id.bytes) {
            if((de = find_hash_entry_by_octet_id(&dhcpr_circuit_table, &circuit_id))) {
                AIM_LOG_ERROR("CIRCUIT_ID: len=%d packet=%{data}",
                                circuit_id.bytes,
                                circuit_id.data, circuit_id.bytes);
                AIM_LOG_ERROR("Vlan %u: new circuit id exists for vlan=%u",
                                entry->internal_vlan_id, de->internal_vlan_id);

                dhcpr_free_circuit_id(&circuit_id);
                return INDIGO_ERROR_EXISTS;
            }
        }

        /* Remove old circuit if existing */
        if (entry->opt_id.circuit_id.bytes) {

            bighash_remove(&dhcpr_circuit_table, &entry->circuit_hash_entry);

            /* Free old circuit */
            dhcpr_free_circuit_id(&entry->opt_id.circuit_id);
        }

        /* Set to new value */
        entry->opt_id.circuit_id.bytes = circuit_id.bytes;
        entry->opt_id.circuit_id.data  = circuit_id.data;

        /* Insert new circuit != 0 */
        if(circuit_id.bytes) {
            bighash_insert(&dhcpr_circuit_table, &entry->circuit_hash_entry, hash_octet_key(&entry->opt_id.circuit_id));
        }
    }

    /* 2. Update gateway hash table if value is different */
    if (entry->vrouter_ip != vr_ip) {
        bighash_remove(&dhcpr_vrouter_ip_table, &entry->vrouter_hash_entry);
        entry->vrouter_ip = vr_ip;
        bighash_insert(&dhcpr_vrouter_ip_table, &entry->vrouter_hash_entry, hash_ip_key(entry->vrouter_ip));
    }

    /* 3. and 4. Update vr_mac and server_ip */
    entry->vrouter_mac = vr_mac;
    entry->dhcp_server_ip = dhcp_server_ip;

    return INDIGO_ERROR_NONE;
}

static indigo_error_t
dhcpr_table_delete(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key)
{
    dhc_relay_t   *entry = entry_priv;
    dhc_relay_t   *de;

    /* Legality check */
    de = find_hash_entry_by_virtual_router_ip (&dhcpr_vrouter_ip_table, entry->vrouter_ip);
    AIM_TRUE_OR_DIE(de && de == entry);
    bighash_remove(&dhcpr_vrouter_ip_table, &entry->vrouter_hash_entry);

    if(entry->opt_id.circuit_id.bytes) {
        de = find_hash_entry_by_octet_id(&dhcpr_circuit_table, &entry->opt_id.circuit_id);
        AIM_TRUE_OR_DIE(de && de == entry);
        bighash_remove(&dhcpr_circuit_table, &entry->circuit_hash_entry);
    }

    AIM_TRUE_OR_DIE(entry == dhcpr_vlan_table[entry->internal_vlan_id]);
    dhcpr_vlan_table[entry->internal_vlan_id] = NULL;
    dhcpr_vlan_entry_count--;

    dhcpr_free_dhc_relay(entry);

    return INDIGO_ERROR_NONE;
}

static void
dhcpr_table_get_stats(void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key, of_list_bsn_tlv_t *stats)
{
}

static const indigo_core_gentable_ops_t dhcpr_table_ops = {
    .add = dhcpr_table_add,
    .modify = dhcpr_table_modify,
    .del = dhcpr_table_delete,
    .get_stats = dhcpr_table_get_stats,
};

/* Set vlan to INVALID if can't find */
void
dhcpr_circuit_id_to_vlan(uint32_t *vlan, uint8_t *cir_id, int cir_id_len)
{
    dhc_relay_t *de = NULL;
    of_octets_t   circuit_id;

    *vlan = INVALID_VLAN;
    circuit_id.data = cir_id;
    circuit_id.bytes = cir_id_len;

    de = find_hash_entry_by_octet_id(&dhcpr_circuit_table, &circuit_id);
    if (de)
        *vlan = de->internal_vlan_id;
}

/* Set vlan to INVALID if can't find */
void
dhcpr_virtual_router_ip_to_vlan(uint32_t *vlan, uint32_t vr_ip)
{
    dhc_relay_t *de = NULL;

    *vlan = INVALID_VLAN;
    de = find_hash_entry_by_virtual_router_ip(&dhcpr_vrouter_ip_table, vr_ip);
    if (de)
        *vlan = de->internal_vlan_id;

}

/* Return value might be NULL, caller must check */
dhc_relay_t*
dhcpr_get_dhcpr_entry_from_vlan_table(uint32_t vlan)
{
    if(is_valid_vlan_value(vlan))
        return dhcpr_vlan_table[vlan];
    else
        return NULL;
}

indigo_error_t
dhcpr_table_init()
{
    /*
     * Caller provides the dhcpr_table: UNUSED in our case
     * Callee provides dhcpr_table_ops
     */
    indigo_core_gentable_register("dhcp_relay", &dhcpr_table_ops, NULL, VLAN_MAX+1, 256,
                                  &dhcpr_table);

    return INDIGO_ERROR_NONE;
}

void
dhcpr_table_finish()
{
    indigo_core_gentable_unregister(dhcpr_table);
}

int
dhcpr_table_get_vlan_entry_count()
{
    return dhcpr_vlan_entry_count;
}

int
dhcpr_table_get_virtual_router_ip_entry_count()
{
    return bighash_entry_count(&dhcpr_vrouter_ip_table) ;
}

int
dhcpr_table_get_circuit_id_entry_count()
{
    return bighash_entry_count(&dhcpr_circuit_table);
}
