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

#include <icmpa/icmpa_config.h>
#include <icmpa_int.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

uint8_t echo_request[ICMP_PKT_BUF_SIZE] = {0x00, 0x50, 0x56, 0xe0, 0x14, 0x49, 0x00, 0x0c, 0x29, 0x34, 0x0b, 0xde, 0x81, 0x00, 0x40, 0x07, 0x08, 0x00, 
                               0x45, 0x00, 0x00, 0x3c, 0xd7, 0x43, 0x00, 0x00, 0x80, 0x01, 0x2b, 0x73, 0xc0, 0xa8, 0x9e, 0x8b, 0xae, 0x89, 0x2a, 0x4d,
                               0x08, 0x00, 0x2a, 0x5c, 0x02, 0x00, 0x21, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 
                               0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
uint8_t ip_packet[ICMP_PKT_BUF_SIZE] = {0x00, 0x50, 0x56, 0xe0, 0x14, 0x49, 0x00, 0x0c, 0x29, 0x34, 0x0b, 0xde, 0x81, 0x00, 0x80, 0x07, 0x08, 0x00,
                               0x45, 0x00, 0x00, 0x30, 0xb3, 0x05, 0x040, 0x00, 0x80, 0x06, 0x31, 0x5b, 0x0a, 0x01, 0x01, 0x65, 0x0a, 0x01, 0x01, 0x01,
                               0x0c, 0x69, 0x00, 0x50, 0x34, 0x9c, 0x04, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x00, 0x00, 0x26, 0xe5, 0x00, 0x00,
                               0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02};

static const indigo_core_gentable_ops_t *ops;
static void *table_priv;
static const of_mac_addr_t mac = { { 0x00, 0x50, 0x56, 0xe0, 0x14, 0x49 } };

void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *_ops,
    void *_table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    if (!strcmp(name, "router_ip")) {
        ops = _ops;
        table_priv = _table_priv;
    }

    *gentable = (void *)1;
}

void
indigo_core_gentable_unregister (indigo_core_gentable_t *gentable)
{
    ASSERT(gentable == (void *)1);
}

indigo_error_t
indigo_core_packet_in_listener_register (indigo_core_packet_in_listener_f fn)
{
    return INDIGO_ERROR_NONE;
}

void
icmpa_verify_packet (of_octets_t *octets, uint32_t reason)
{
    ppe_packet_t               ppep;
    uint32_t                   icmp_type;

    if (!octets) return;

    ppe_packet_init(&ppep, octets->data, octets->bytes);    
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_ERROR("Packet_in parsing failed.");
        return;
    }

    assert(ppe_header_get(&ppep, PPE_HEADER_ICMP)); 
    ppe_field_get(&ppep, PPE_FIELD_ICMP_TYPE, &icmp_type);
    assert(icmp_type == reason); 
}

indigo_error_t
indigo_fwd_packet_out (of_packet_out_t *of_packet_out)
{
    of_port_no_t     port_no;
    of_octets_t      of_octets;
    of_list_action_t action;
    of_action_t      act;
    int              rv;

    if (!of_packet_out) return INDIGO_ERROR_NONE;

    of_packet_out_actions_bind(of_packet_out, &action);
    OF_LIST_ACTION_ITER(&action, &act, rv) {
        of_action_output_port_get(&act.output, &port_no);
    }

    of_packet_out_data_get(of_packet_out, &of_octets);

    printf("icmpa module: Send a packet out the port: %d\n", port_no);

    /*
     * Verify the outgoing ICMP packet based on expected response
     */
    if (port_no == 10) {
        icmpa_verify_packet(&of_octets, ICMP_ECHO_REPLY);
    } else if (port_no == 20) {  
        icmpa_verify_packet(&of_octets, ICMP_DEST_UNREACHABLE);
    } else if (port_no == 30) {
        icmpa_verify_packet(&of_octets, ICMP_TIME_EXCEEDED);
    }

    return INDIGO_ERROR_NONE;
}
 
indigo_error_t
icmpa_create_send_packet_in (of_octets_t *of_octets, uint8_t reason, 
                             of_port_no_t in_port)
{
    of_packet_in_t *of_packet_in;
    of_match_t     match;

    if (!of_octets) return INDIGO_ERROR_UNKNOWN;

    if ((of_packet_in = of_packet_in_new(OF_VERSION_1_3)) == NULL) {
        return INDIGO_ERROR_RESOURCE;
    }

    of_packet_in_total_len_set(of_packet_in, of_octets->bytes);
    match.version = OF_VERSION_1_3;
    match.fields.in_port = in_port;
    OF_MATCH_MASK_IN_PORT_EXACT_SET(&match);
    if ((of_packet_in_match_set(of_packet_in, &match)) != OF_ERROR_NONE) {
        printf("Failed to write match to packet-in message\n");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    if ((of_packet_in_data_set(of_packet_in, of_octets)) != OF_ERROR_NONE) {
        printf("Failed to write packet data to packet-in message\n");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    of_packet_in_reason_set(of_packet_in, reason);
 
    if (icmpa_packet_in_handler(of_packet_in) == 
        INDIGO_CORE_LISTENER_RESULT_DROP) {
        printf("Listener dropped packet-in\n");
    } else {
        printf("Listener passed packet-in\n");
    }

    of_packet_in_delete(of_packet_in);
    return INDIGO_ERROR_NONE;

}

static of_list_bsn_tlv_t *
make_key (uint16_t vlan_vid)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    of_bsn_tlv_vlan_vid_t *tlv = of_bsn_tlv_vlan_vid_new(OF_VERSION_1_3);
    of_bsn_tlv_vlan_vid_value_set(tlv, vlan_vid);
    of_list_append(list, tlv);
    of_object_delete(tlv);
    return list;
}

static of_list_bsn_tlv_t *
make_value (uint32_t ipv4, of_mac_addr_t mac)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(OF_VERSION_1_3);
        of_bsn_tlv_ipv4_value_set(tlv, ipv4);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_mac_t *tlv = of_bsn_tlv_mac_new(OF_VERSION_1_3);
        of_bsn_tlv_mac_value_set(tlv, mac);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    return list;
}

int aim_main (int argc, char* argv[])
{
    of_octets_t       octets;
    of_list_bsn_tlv_t *key, *value;
    void              *entry_priv; 

    if (!icmpa_is_initialized()) {
        icmpa_init();
    }

    router_ip_table_init();
    key = make_key(7); 
    value = make_value(0xae892a4d, mac);
    ops->add(table_priv, key, value, &entry_priv);

    octets.data = echo_request; 
    octets.bytes = ICMP_PKT_BUF_SIZE;
    icmpa_create_send_packet_in(&octets, 
                                OF_PACKET_IN_REASON_BSN_ICMP_ECHO_REQUEST, 10);
    octets.data = ip_packet; 
    icmpa_create_send_packet_in(&octets, 
                                OF_PACKET_IN_REASON_BSN_DEST_NETWORK_UNREACHABLE, 20);
    icmpa_create_send_packet_in(&octets, OF_PACKET_IN_REASON_INVALID_TTL, 30);

    /*
     * Unhandled ICMP reason, to test if the packet is passed
     */
    icmpa_create_send_packet_in(&octets, 139, 30);

    ops->del(table_priv, entry_priv, key);
    of_object_delete(key);
    of_object_delete(value);
    router_ip_table_finish();

    return 0;
}

