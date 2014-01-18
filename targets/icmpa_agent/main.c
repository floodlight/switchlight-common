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

/*
 * This file contains routines for testing a ping using tap interfaces.
 * The step-by-step procedure for setting up the tap intf is documented below.
 */

/*
 * Procedure for setting up tap interfaces:
 * 1. Setup tap interfaces. Running icmp_agent module binary 
 *    will do that. ./build/gcc-local/bin/icmp-agent
 * 3. Add the below config's:
      ifconfig tap0 10.0.0.1/24  
      sudo arp -s 10.0.0.2 00:0c:29:c0:94:bf
 * 4. Verify tap0 interface is UP (ifconfig -a tap0)
 *    If Down bring the interface up: sudo ifconfig tap0 up
 * 5. Run the ./build/gcc-local/bin/icmp-agent again 
 * 6. Perform ping: ping 10.0.0.2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <AIM/aim.h>
#include <VPI/vpi.h>
#include <poll.h>
#include <icmpa/icmpa_config.h>
#include <icmpa_int.h>

vpi_t vpi1;

static bool packet_received_untagged = false;
static const indigo_core_gentable_ops_t *ops;
static void *table_priv;
static const of_mac_addr_t mac = { { 0x00, 0x0c, 0x29, 0xc0, 0x94, 0xbf } };

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

indigo_error_t
icmpa_create_send_packet_in (of_octets_t *of_octets, uint8_t reason,
                             of_port_no_t in_port)
{
    of_packet_in_t *of_packet_in;
    of_match_t     match;
    ppe_packet_t   ppep;
    ppe_header_t   format;
    uint8_t        buf[256];

    if (!of_octets) return INDIGO_ERROR_UNKNOWN;

    /*
     * Check if the packet_in is untagged, then add the Vlan tag 
     */
    ppe_packet_init(&ppep, of_octets->data, of_octets->bytes);
    if (ppe_parse(&ppep) < 0) {
        printf("add_vlan_tag: Packet_in parsing failed.\n");
        return INDIGO_ERROR_UNKNOWN;
    } 

    ppe_packet_format_get(&ppep, &format);
    if (format != PPE_HEADER_8021Q) {
        packet_received_untagged = true;
        of_octets->bytes += 4;
        ICMPA_MEMCPY(buf, of_octets->data, of_octets->bytes);
        ICMPA_MEMCPY(of_octets->data+16, buf+12, of_octets->bytes-16);
        of_octets->data[12] = ETHERTYPE_DOT1Q >> 8;
        of_octets->data[13] = ETHERTYPE_DOT1Q & 0xFF;
        of_octets->data[14] = 0;
        of_octets->data[15] = 7;  
    }

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

indigo_error_t
indigo_fwd_packet_out (of_packet_out_t *of_packet_out)
{
    of_port_no_t     port_no;
    of_octets_t      of_octets;
    of_list_action_t action;
    of_action_t      act;
    int              rv;
    ppe_packet_t     ppep;
    ppe_header_t     format;

    if (!of_packet_out) return INDIGO_ERROR_PARAM;

    of_packet_out_actions_bind(of_packet_out, &action);
    OF_LIST_ACTION_ITER(&action, &act, rv) {
        of_action_output_port_get(&act.output, &port_no);
    }

    of_packet_out_data_get(of_packet_out, &of_octets);

    /*
     * If this is a tagged Packet, remove the Vlan tag 
     */
    ppe_packet_init(&ppep, of_octets.data, of_octets.bytes);
    if (ppe_parse(&ppep) < 0) {
        printf("remove_vlan_tag: Packet_in parsing failed.");
        return INDIGO_ERROR_UNKNOWN;
    }

    ppe_packet_format_get(&ppep, &format);
    if (format == PPE_HEADER_8021Q && packet_received_untagged) {
        ICMPA_MEMMOVE(of_octets.data +12, of_octets.data +16, 
                      of_octets.bytes -16); 
        of_octets.bytes -= 4;
        packet_received_untagged = false;
    }  
 
    vpi_send(vpi1, of_octets.data, of_octets.bytes);
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

int main (int argc, char* argv[])
{
    uint8_t           buf[256];
    struct            pollfd fds[2];
    of_octets_t       of_octets;
    of_list_bsn_tlv_t *key, *value;
    void              *entry_priv;

    vpi_init();

    if (!icmpa_is_initialized()) {
        icmpa_init();
    }

    router_ip_table_init();
    key = make_key(7);
    value = make_value(0x0a000002, mac);
    ops->add(table_priv, key, value, &entry_priv);
 
    vpi1 = vpi_create("tap|tap0");  
    if (!vpi1) {
        assert(vpi1);
        return 0;
    }

    fds[0].fd = vpi_descriptor_get(vpi1);
    fds[0].events = POLLIN;

    of_octets.bytes = 0;
    of_octets.data = buf;
    while (poll(fds, 2, -1) >= 0) {
        if (fds[0].revents & POLLIN) {
            of_octets.bytes = vpi_recv(vpi1, buf, 256, 0);
            printf("received_pkt on tap0 with %d bytes\n", of_octets.bytes);
            icmpa_create_send_packet_in(&of_octets, 
                                OF_PACKET_IN_REASON_BSN_ICMP_ECHO_REQUEST, 10);
        }

    }
    
    vpi_unref(vpi1);
    vpi_close();
    ops->del(table_priv, entry_priv, key);
    of_object_delete(key);
    of_object_delete(value);
    router_ip_table_finish();

    return 0;
}

