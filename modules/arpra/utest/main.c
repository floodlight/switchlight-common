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

#include <arpra/arpra_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

#include <arpra/arpra.h>
#include <arpra_int.h>
#include <indigo/of_state_manager.h>

static const of_mac_addr_t mac1 = { { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
static const of_mac_addr_t mac2 = { { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } };
of_port_no_t port_no;
uint8_t data1[46] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x81, 0x00, 0x40, 0x07, 0x08, 0x06,
                     0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x18, 0xa6, 0xac, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
uint8_t data2[46] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x81, 0x00, 0x40, 0x07, 0x08, 0x06,
                     0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x18, 0xa6, 0xac, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78};
uint8_t data3[46] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x81, 0x00, 0x40, 0x07, 0x08, 0x06,
                     0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54, 0x18, 0xa6, 0xac, 0x01,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd};
bool arp_reply_received = false;

indigo_error_t
indigo_core_packet_in_listener_register (indigo_core_packet_in_listener_f fn)
{
    return INDIGO_ERROR_NONE;
}

void
indigo_core_packet_in_listener_unregister (indigo_core_packet_in_listener_f fn)
{
}

void
arpra_verify_packet (of_octets_t *octets) 
{
    ppe_packet_t  ppep;
    uint32_t      tmp;
    of_mac_addr_t mac;    

    if (!octets) return;

    ppe_packet_init(&ppep, octets->data, octets->bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_ERROR("Packet_in parsing failed.");
        return;
    }

    AIM_ASSERT(ppe_header_get(&ppep, PPE_HEADER_ARP));

    ppe_field_get(&ppep, PPE_FIELD_ARP_OPERATION, &tmp);
    AIM_ASSERT(tmp == 2); 

    ppe_field_get(&ppep, PPE_FIELD_ARP_SPA, &tmp);
    ppe_wide_field_get(&ppep, PPE_FIELD_ARP_SHA, mac.addr);

    if (port_no == 10) {
        AIM_ASSERT(tmp == 0x1234);
        AIM_ASSERT(!memcmp(&mac, &mac1, sizeof(of_mac_addr_t)));
    } else if (port_no == 20) {
        AIM_ASSERT(tmp == 0x5678);
        AIM_ASSERT(!memcmp(&mac, &mac2, sizeof(of_mac_addr_t)));
    }

    arp_reply_received = true;
}

indigo_error_t
indigo_fwd_packet_out (of_packet_out_t *of_packet_out)
{
    of_octets_t      of_octets;

    if (!of_packet_out) return INDIGO_ERROR_NONE;

    of_packet_out_data_get(of_packet_out, &of_octets);

    printf("arpra: Send a packet out the port: %d\n", port_no);

    /*
     * Verify the ARP Reply packet based on expected response
     */
    arpra_verify_packet(&of_octets);

    return INDIGO_ERROR_NONE;    
}

indigo_error_t
arpra_create_send_packet_in (of_octets_t *of_octets, of_port_no_t in_port)
{
    of_packet_in_t *of_packet_in;
    of_match_t     match;

    memset(&match, 0, sizeof(of_match_t));

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

    if (arpra_packet_in_handler(of_packet_in) ==
        INDIGO_CORE_LISTENER_RESULT_DROP) {
        printf("Listener dropped packet-in\n");
    } else {
        printf("Listener passed packet-in\n");
    }

    of_packet_in_delete(of_packet_in);
    return INDIGO_ERROR_NONE;

}

int aim_main (int argc, char* argv[])
{
    of_mac_addr_t mac;
    of_octets_t   octets;

    arpra_init();

    /* 
     * Add entries in the arp cache 
     */
    arpra_add_cache_entry(0x1234, mac1);
    AIM_ASSERT(arpra_lookup(0x1234, &mac) == true);
    AIM_ASSERT(!memcmp(&mac, &mac1, sizeof(of_mac_addr_t)));

    arpra_add_cache_entry(0x5678, mac2);
    AIM_ASSERT(arpra_lookup(0x5678, &mac) == true); 
    AIM_ASSERT(!memcmp(&mac, &mac2, sizeof(of_mac_addr_t)));
  
    /*
     * Lookup a non-existent entry
     */ 
    AIM_ASSERT(arpra_lookup(0xabcd, &mac) == false);

    /*
     * Send a arp request 
     */
    octets.data = data1;
    octets.bytes = 46;
    port_no = 10; 
    arpra_create_send_packet_in(&octets, port_no);    
    
    /*
     * Test if we actually received responses from icmpa
     */
    AIM_ASSERT(arp_reply_received == true);
    arp_reply_received = false;

    octets.data = data2;
    port_no = 20;
    arpra_create_send_packet_in(&octets, port_no);
    AIM_ASSERT(arp_reply_received == true);
    arp_reply_received = false;

    /*
     * Send an arp request for an ip not in the arp cache
     */
    octets.data = data3;
    port_no = 30; 
    arpra_create_send_packet_in(&octets, port_no);
    AIM_ASSERT(arp_reply_received == false);

    /*
     * Delete entries from the arp cache
     */
    arpra_delete_cache_entry(0x1234, mac1);
    AIM_ASSERT(arpra_lookup(0x1234, &mac) == false);    

    arpra_delete_cache_entry(0x5678, mac2);
    AIM_ASSERT(arpra_lookup(0x5678, &mac) == false);

    arpra_finish(); 
    return 0;
}

