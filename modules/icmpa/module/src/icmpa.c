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
 * Implementation of Icmp Agent.
 *
 * This file contains code for icmp error msg generation and handling 
 * icmp request msg's (ECHO, etc.)
 */

#include "icmpa_int.h"

/*
 * icmpa_get_vlan_id
 *
 * Check if the packet has 802.1q header and extract the vlan id 
 */
static bool
icmpa_get_vlan_id (ppe_packet_t *ppep, uint32_t *vlan_id)
{
    ppe_header_t format;

    if (!ppep || !vlan_id) return false;

    ppe_packet_format_get(ppep, &format);
    if (format != PPE_HEADER_8021Q) return false;

    ppe_field_get(ppep, PPE_FIELD_8021Q_VLAN, vlan_id);

    return true;
}

/*
 * icmpa_build_pdu
 * 
 * Build an ICMP packet
 */
static bool
icmpa_build_pdu (ppe_packet_t *ppep_rx, of_octets_t *octets, uint32_t vlan_id,
                 uint32_t ip_total_len, uint32_t router_ip, 
                 uint32_t type, uint32_t code, uint32_t hdr_data, 
                 uint8_t *icmp_data, uint32_t icmp_data_len)
{
    ppe_packet_t               ppep_tx;
    uint8_t                    src_mac[OF_MAC_ADDR_BYTES];
    uint8_t                    dest_mac[OF_MAC_ADDR_BYTES];
    uint32_t                   dest_ip;

    if (!ppep_rx || !octets || !icmp_data) return false;

    AIM_LOG_TRACE("Build ICMP PDU with type: %d, code: %d", type, code);
    ppe_packet_init(&ppep_tx, octets->data, octets->bytes);

    /*
     * Set ethertype as 802.1Q and type as IPv4
     * Parse to recognize tagged Ethernet packet.
     */
    octets->data[12] = ETHERTYPE_DOT1Q >> 8;
    octets->data[13] = ETHERTYPE_DOT1Q & 0xFF;
    octets->data[16] = PPE_ETHERTYPE_IP4 >> 8;
    octets->data[17] = PPE_ETHERTYPE_IP4 & 0xFF;
    if (ppe_parse(&ppep_tx) < 0) {
        AIM_LOG_ERROR("ICMPA: Packet_out parsing failed after IPv4 header");
        return false;
    }

    /*
     * Get the Src Mac, Dest Mac from the incoming frame
     */
    ppe_wide_field_get(ppep_rx, PPE_FIELD_ETHERNET_SRC_MAC, src_mac);
    ppe_wide_field_get(ppep_rx, PPE_FIELD_ETHERNET_DST_MAC, dest_mac);

    /*
     * Set the Src Mac, Dest Mac and the Vlan-ID in the outgoing frame
     */
    ppe_wide_field_set(&ppep_tx, PPE_FIELD_ETHERNET_SRC_MAC, dest_mac);
    ppe_wide_field_set(&ppep_tx, PPE_FIELD_ETHERNET_DST_MAC, src_mac);
    ppe_field_set(&ppep_tx, PPE_FIELD_8021Q_VLAN, vlan_id);

    /*
     * Src IP = Router IP
     * Dest IP = Get the Src IP and use it as the Dest IP 
     */
    ppe_field_get(ppep_rx, PPE_FIELD_IP4_SRC_ADDR, &dest_ip);

    /*
     * Build the IP header 
     */
    ppe_build_ipv4_header(&ppep_tx, router_ip, dest_ip, ip_total_len, 1, 128);

    /*
     * Build the ICMP packet (header + icmp data)
     */
    ppe_build_icmp_packet(&ppep_tx, type, code, hdr_data, icmp_data,
                          icmp_data_len);

    if (AIM_LOG_CUSTOM_ENABLED(ICMPA_LOG_FLAG_PACKET)) {
        ICMPA_LOG_PACKET("DUMPING OUTGOING ICMP PACKET");
        ppe_packet_dump(&ppep_tx, aim_log_pvs_get(&AIM_LOG_STRUCT));
    }

    return true;
}

/*
 * icmpa_reply
 *
 * Driving logic for building and sending reply messages.
 * Currently we are only handling ICMP ECHO Requests. 
 */
bool
icmpa_reply (of_octets_t *octets_in, of_port_no_t port_no)
{
    of_octets_t                octets_out;
    ppe_packet_t               ppep;   
    uint32_t                   icmp_type; 
    uint32_t                   hdr_data;
    uint32_t                   ip_total_len, ip_hdr_size;
    uint32_t                   icmp_data_len;
    uint8_t                    data[ICMP_PKT_BUF_SIZE];
    uint32_t                   vlan_id;
    uint32_t                   router_ip, dest_ip;
    of_mac_addr_t              router_mac;


    if (!octets_in) return false;

    ICMPA_MEMSET(data, 0, ICMP_PKT_BUF_SIZE); 
    ppe_packet_init(&ppep, octets_in->data, octets_in->bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&icmp_pktin_log_limiter, os_time_monotonic(),
                         "ICMPA: Packet_in parsing failed.");
        return false;
    }
     
    if (!ppe_header_get(&ppep, PPE_HEADER_ICMP)) {
        AIM_LOG_RL_TRACE(&icmp_pktin_log_limiter, os_time_monotonic(),
                         "Not an ICMP Packet");
        return false;
    }  

    ppe_field_get(&ppep, PPE_FIELD_ICMP_TYPE, &icmp_type); 
 
    /*
     * Check to make sure this is an ICMP ECHO Request
     */
    if (icmp_type != ICMP_ECHO_REQUEST) {
        AIM_LOG_TRACE("Not a ICMP ECHO Request Packet, type: %d", icmp_type);
        return false;
    }  

    /*
     * We should never receive an untagged frame
     */
    if (!icmpa_get_vlan_id(&ppep, &vlan_id)) {
        AIM_LOG_ERROR("ICMPA: Received Untagged Packet_in");
        return false;    
    } 

    /*
     * Echo requests should always be destined to Router IP
     */
    if (router_ip_table_lookup(vlan_id, &router_ip, &router_mac) < 0) {
        AIM_LOG_ERROR("ICMPA: Router IP lookup failed for vlan: %d", vlan_id);
        return false;
    }

    ppe_field_get(&ppep, PPE_FIELD_IP4_DST_ADDR, &dest_ip); 
    if (router_ip != dest_ip) {
        AIM_LOG_ERROR("ICMPA: Echo request dest_ip: 0x%.8x is not router IP: "
                      "0x%.8x", dest_ip, router_ip);
        return false;
    } 

    AIM_LOG_TRACE("Processing ICMP ECHO Request");
    if (AIM_LOG_CUSTOM_ENABLED(ICMPA_LOG_FLAG_PACKET)) {
        ICMPA_LOG_PACKET("DUMPING INCMOING ICMP PACKET");
        ppe_packet_dump(&ppep, aim_log_pvs_get(&AIM_LOG_STRUCT));
    }

    /*
     * Build the ICMP packet
     */
    octets_out.data = data;
    octets_out.bytes = octets_in->bytes;  
    ppe_field_get(&ppep, PPE_FIELD_IP4_HEADER_SIZE, &ip_hdr_size);
    ppe_field_get(&ppep, PPE_FIELD_IP4_TOTAL_LENGTH, &ip_total_len);
    ppe_field_get(&ppep, PPE_FIELD_ICMP_HEADER_DATA, &hdr_data);

    ip_hdr_size *= 4;
    if (ip_hdr_size > IP_HEADER_SIZE) {
        AIM_LOG_ERROR("ICMPA: IP Options set as ip header size: %d is more "
                      "than 20 Bytes", ip_hdr_size);
        return false;
    }

    icmp_data_len = ip_total_len - ip_hdr_size - ICMP_HEADER_SIZE;
    if (!icmpa_build_pdu(&ppep, &octets_out, vlan_id, ip_total_len, router_ip, 
        ICMP_ECHO_REPLY, 0, hdr_data, 
        ppe_fieldp_get(&ppep, PPE_FIELD_ICMP_PAYLOAD), icmp_data_len)) {
        AIM_LOG_ERROR("ICMPA: icmpa_build_pdu failed");
        return false;
    }

    if (icmpa_send_packet_out(&octets_out, port_no) < 0) {
        AIM_LOG_ERROR("ICMPA: Send packet_out failed for port: %d", port_no);
        return false;
    }

    return true;
}

/*
 * icmpa_send
 * 
 * Send an ICMP message in response to below situation's
 * 1. TTL Expired
 * 2. Fragmentation Required
 * 3. Network Unreachable
 * 4. Port Unreachable
 *
 * RFC 1122: 3.2.2 MUST send at least the IP header and 8 bytes of header.
 */
bool 
icmpa_send (of_octets_t *octets_in, of_port_no_t port_no, uint32_t type, 
            uint32_t code)
{
    of_octets_t                octets_out;
    ppe_packet_t               ppep;
    uint8_t                    *ip_hdr = NULL; 
    uint32_t                   ip_total_len;
    uint8_t                    data[ICMP_PKT_BUF_SIZE];    
    uint32_t                   vlan_id;
    uint32_t                   router_ip;
    of_mac_addr_t              router_mac;

    if (!octets_in) return false;

    ICMPA_MEMSET(data, 0, ICMP_PKT_BUF_SIZE);   
    ppe_packet_init(&ppep, octets_in->data, octets_in->bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&icmp_pktin_log_limiter, os_time_monotonic(),
                         "ICMPA: Packet_in parsing failed.");
        return false;
    }

    ip_hdr = ppe_header_get(&ppep, PPE_HEADER_IP4);
    if (!ip_hdr) {
        AIM_LOG_RL_TRACE(&icmp_pktin_log_limiter, os_time_monotonic(),
                         "Not an IP Packet");
        return false;
    }
   
    /*
     * We should never receive an untagged frame
     */
    if (!icmpa_get_vlan_id(&ppep, &vlan_id)) {
        AIM_LOG_ERROR("ICMPA: Received Untagged Packet_in");
        return false;
    }

    if (router_ip_table_lookup(vlan_id, &router_ip, &router_mac) < 0) {
        AIM_LOG_ERROR("ICMPA: Router IP lookup failed for vlan: %d", vlan_id);
        return false;
    } 

    AIM_LOG_TRACE("Send ICMP message with type: %d, code: %d", type, code); 

    /*
     * Build the ICMP packet
     */
    octets_out.data = data;
    octets_out.bytes = ICMP_PKT_SIZE;
    ppe_field_get(&ppep, PPE_FIELD_IP4_TOTAL_LENGTH, &ip_total_len);
    if (ip_total_len < ICMP_DATA_LEN) {
        AIM_LOG_ERROR("ICMPA: IP Total len: %d is less than required 28 Bytes",
                      ip_total_len);
        return false;
    } 

    if (!icmpa_build_pdu(&ppep, &octets_out, vlan_id, IP_TOTAL_LEN, router_ip, 
        type, code, 0, ip_hdr, ICMP_DATA_LEN)) {
        AIM_LOG_ERROR("ICMPA: icmpa_build_pdu failed");
        return false;
    }        

    if (icmpa_send_packet_out(&octets_out, port_no) < 0) {
        AIM_LOG_ERROR("ICMPA: Send packet_out failed for port: %d", port_no);
        return false;
    }

    return true;
}
