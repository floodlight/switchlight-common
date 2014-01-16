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
#include <PPE/ppe.h>

#include "arpa_log.h"

struct arp_info {
    of_mac_addr_t eth_src;
    of_mac_addr_t eth_dst;
    uint16_t vlan_vid;
    uint8_t vlan_pcp;
    uint16_t operation;
    of_mac_addr_t sha;
    uint32_t spa;
    of_mac_addr_t tha;
    uint32_t tpa;
};

static indigo_core_listener_result_t arpa_handle_pkt(of_packet_in_t *packet_in);
static indigo_error_t arpa_parse_packet(of_octets_t *data, struct arp_info *info);

static indigo_core_gentable_t *arp_table;

static const indigo_core_gentable_ops_t arp_ops;


/* Public interface */

indigo_error_t
arpa_init()
{
    indigo_core_gentable_register("arp", &arp_ops, NULL, 16384, 1024,
                                  &arp_table);

    indigo_core_packet_in_listener_register(arpa_handle_pkt);

    return INDIGO_ERROR_NONE;
}

void
arpa_finish()
{
    indigo_core_gentable_unregister(arp_table);
    indigo_core_packet_in_listener_unregister(arpa_handle_pkt);
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


/* packet-in listener */

static indigo_core_listener_result_t
arpa_handle_pkt(of_packet_in_t *packet_in)
{
    uint8_t reason;
    of_octets_t octets;
    struct arp_info info;
    indigo_error_t rv;

    of_packet_in_reason_get(packet_in, &reason);
    of_packet_in_data_get(packet_in, &octets);

    if (reason != OF_PACKET_IN_REASON_BSN_ARP) {
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    rv = arpa_parse_packet(&octets, &info);
    if (rv < 0) {
        /* TODO ratelimit */
        AIM_LOG_ERROR("not a valid ARP packet: %s", indigo_strerror(rv));
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    AIM_LOG_TRACE("received ARP packet: op=%d spa=%#x tpa=%#x", info.operation, info.spa, info.tpa);

    return INDIGO_CORE_LISTENER_RESULT_PASS;
}

static indigo_error_t
arpa_parse_packet(of_octets_t *octets, struct arp_info *info)
{
    ppe_packet_t ppep;
    uint32_t tmp;

    ppe_packet_init(&ppep, octets->data, octets->bytes);
    if (ppe_parse(&ppep) < 0) {
        return INDIGO_ERROR_PARSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_ETHERNET)) {
        return INDIGO_ERROR_PARSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_8021Q)) {
        return INDIGO_ERROR_PARSE;
    }

    if (!ppe_header_get(&ppep, PPE_HEADER_ARP)) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_wide_field_get(&ppep, PPE_FIELD_ETHERNET_DST_MAC, info->eth_dst.addr);

    ppe_wide_field_get(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, info->eth_src.addr);

    ppe_field_get(&ppep, PPE_FIELD_8021Q_VLAN, &tmp);
    info->vlan_vid = tmp;

    ppe_field_get(&ppep, PPE_FIELD_8021Q_PRI, &tmp);
    info->vlan_pcp = tmp;

    ppe_field_get(&ppep, PPE_FIELD_ARP_HTYPE, &tmp);
    if (tmp != 1) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_PTYPE, &tmp);
    if (tmp != 0x0800) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_HLEN, &tmp);
    if (tmp != 6) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_PLEN, &tmp);
    if (tmp != 4) {
        return INDIGO_ERROR_PARSE;
    }

    ppe_field_get(&ppep, PPE_FIELD_ARP_OPERATION, &tmp);
    info->operation = tmp;

    ppe_wide_field_get(&ppep, PPE_FIELD_ARP_SHA, info->sha.addr);

    ppe_field_get(&ppep, PPE_FIELD_ARP_SPA, &tmp);
    info->spa = tmp;

    ppe_wide_field_get(&ppep, PPE_FIELD_ARP_THA, info->tha.addr);

    ppe_field_get(&ppep, PPE_FIELD_ARP_TPA, &tmp);
    info->tpa = tmp;

    return INDIGO_ERROR_NONE;
}
