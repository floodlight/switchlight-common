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

#include <dhcpra/dhcpra.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dhcp.h"
#include "dhcpra_int.h"
#include "dhcpr_table.h"
#include "dhcrelay.h"

#include <indigo/of_state_manager.h>
#include <OS/os.h>
#include <SocketManager/socketmanager.h>
#include <PPE/ppe.h>

#define MAX_SYSTEM_PORT 96
typedef struct {
    uint32_t dhcp_request;
    uint32_t dhcp_request_relay;
    uint32_t dhcp_reply;
    uint32_t dhcp_reply_relay;
}dhcp_relay_stat_t;

static dhcp_relay_stat_t dhcp_stat_ports[MAX_SYSTEM_PORT+1];

/* This variable is set by ucli for debugging purpose*/
int dhcpra_dump_data = DHCPRA_DUMP_DISABLE_ALL_PORTS;

/* Maximum DHCP packet out */
#define OUT_PKT_BUF_SIZE DHCP_MTU_MAX

/* Maximum hop count */
static int max_hop_count = 10;

static aim_ratelimiter_t dhcpra_pktin_log_limiter;

/*
 * NOTE: We can call ppe_build_ipv4_header to build ip header by
 *       providing sub protocol such UDP, ICMP, TCP, then DHCP
 * However, we have to do parsing couple times to recognize sub protocols
 * It is simple and fast to fill packet directly
 * Then we call parsing one time only for legality check and filling checksum
 */
struct ip {
    uint8_t  ip_fvhl; /* header length, version: Default 0x45 */
    uint8_t  ip_tos;  /* type of service: IPTOS_LOWDELAY */
    uint16_t ip_len;  /* total length: ip_hdr + payload(udp + payload): User */
    uint16_t ip_id;   /* identification: 0*/
    uint16_t ip_off;  /* fragment offset field: 0 */
    uint8_t  ip_ttl;  /* time to live: 128 */
    uint8_t  ip_p;    /* protocol: UDP */
    uint16_t ip_sum;  /* checksum: User */
    struct in_addr ip_src, ip_dst; /* source and dest address: User */
};

struct udp {
    u_int16_t uh_sport;     /* source port - 0 */
    u_int16_t uh_dport;     /* destination port - User */
    u_int16_t uh_ulen;      /* udp length: udp_hdr + payload - User */
    u_int16_t uh_sum;       /* udp checksum - User*/
};

#define ETHERTYPE_DOT1Q 0x8100
#define DOT1Q_IP_HEADER_OFFSET 18
#define UDP_HEADER_OFFSET      (DOT1Q_IP_HEADER_OFFSET + sizeof(struct ip))
#define DHCP_HEADER_OFFSET     (UDP_HEADER_OFFSET + sizeof(struct udp))

#define HEX_LEN 80
#define PER_LINE 16
static inline void
dhcpra_pkt_hexdump(unsigned char *buf, int bytes)
{
    int idx;
    char display[HEX_LEN];
    int disp_offset = 0;
    int buf_offset = 0;

    /*one byte is printed into 2 chars, extra byte for NULL char*/
    char whole_pkt_display[OUT_PKT_BUF_SIZE*2+1];
    int pkt_offset = 0;

    DHCPRA_DEBUG("DHCPRA_PKT_HEXDUMP");

    /* Legality check */
    if (bytes > OUT_PKT_BUF_SIZE) {
        DHCPRA_DEBUG("bytes_to_read=%d, pkt_offset=%d, display_size=%d",
                      bytes, pkt_offset, sizeof(whole_pkt_display));
        return;
    }

    /* Dump 16 bytes for quick view */
    while (bytes > 0) {

        disp_offset = 0;
        for (idx = 0; (idx < PER_LINE) && (idx < bytes); idx++) {

            /* aim_snprintf: only return number of chars, excluding null */
            disp_offset += aim_snprintf(&display[disp_offset], sizeof("xx"),
                                        "%02x", buf[buf_offset + idx]);

            pkt_offset += aim_snprintf(&whole_pkt_display[pkt_offset], sizeof("xx"),
                                       "%02x", buf[buf_offset + idx]);
        }

        DHCPRA_DEBUG("%s",display);

        bytes -= idx;
        buf_offset += idx;


    }

    /* Dump the whole packet at once for external tool analysis */
    DHCPRA_DEBUG("%s", whole_pkt_display);

}

static void
set_dot1q_ipv4_type (uint8_t *pkt)
{
    /* Set dot1q */
    pkt[12] = ETHERTYPE_DOT1Q >> 8;
    pkt[13] = ETHERTYPE_DOT1Q & 0xFF;

    /* Set ipv4 type */
    pkt[16] = PPE_ETHERTYPE_IP4 >> 8;
    pkt[17] = PPE_ETHERTYPE_IP4 & 0xFF;
}

#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
static void
set_ipv4_proto_type (uint8_t *pkt, int dhcp_len)
{
    struct ip *ip = (struct ip*)(pkt + DOT1Q_IP_HEADER_OFFSET);
    ip->ip_fvhl   = 0x45; /* Type 4, len 5 words */
    ip->ip_tos    = IPTOS_LOWDELAY;
    ip->ip_len    = htons(sizeof(struct ip) + sizeof(struct udp) + dhcp_len);
    ip->ip_id     = 0;
    ip->ip_off    = 0;
    ip->ip_ttl    = 128;
    ip->ip_p      = IPPROTO_UDP; /* 17 */
    /* check sum, ip addr will be set later */
}

static void
set_udp_port (uint8_t *pkt, u_int16_t dhcp_len, u_int16_t sport, u_int16_t dport)
{
    struct udp *udp = (struct udp*) (pkt + UDP_HEADER_OFFSET);
    udp->uh_sport   = htons(sport);
    udp->uh_dport   = htons(dport);
    udp->uh_ulen    = htons(sizeof(struct udp) + dhcp_len);
    /* check sum will be set later using ppe_packet_update */
}

static void
init_ppe_header (uint8_t *pkt, uint32_t dhcp_len, uint32_t sport, uint32_t dport)
{
    set_dot1q_ipv4_type (pkt);
    set_ipv4_proto_type (pkt, dhcp_len);
    set_udp_port (pkt, dhcp_len, sport, dport);
}

static void
dhcpra_send_pkt (of_octets_t *octets, of_port_no_t port_no)
{
    of_packet_out_t    *pkt_out;
    of_list_action_t   *list;
    of_action_output_t *action;
    int                rv;

     /* Always use OF_VERSION_1_3 */
    uint32_t version  = OF_VERSION_1_3;
    uint32_t out_port = OF_PORT_DEST_USE_TABLE; /* (0xfffffff9) OFPP_TABLE */
    uint32_t in_port  = OF_PORT_DEST_LOCAL;

    pkt_out = of_packet_out_new (version);
    if(!pkt_out){
        AIM_LOG_ERROR("Failed to allocate packet out");
        return;
    }
    of_packet_out_buffer_id_set(pkt_out, -1);
    of_packet_out_in_port_set(pkt_out, in_port);

    action = of_action_output_new(version);
    if(!action){
        of_packet_out_delete(pkt_out);
        AIM_LOG_ERROR("Failed to allocation action");
        return;
    }
    of_action_output_port_set(action, out_port);

    list = of_list_action_new(version);
    if(!list){
        of_packet_out_delete(pkt_out);
        of_object_delete(action);
        AIM_LOG_ERROR("Failed to allocate action list");
        return;
    }

    of_list_append(list, action);
    of_object_delete(action);

    rv = of_packet_out_actions_set(pkt_out, list);
    AIM_TRUE_OR_DIE(rv==OF_ERROR_NONE);

    of_object_delete(list);

    if ((rv = of_packet_out_data_set(pkt_out, octets)) != OF_ERROR_NONE) {
        AIM_LOG_ERROR("Packet out failed to set data %d", rv);
        of_packet_out_delete(pkt_out);
        return;
    }

    DHCPRA_DEBUG("Port %d: Fwd pkt out in_port=%x, out_port=%x",
                    port_no, in_port, out_port);

    if ((rv = indigo_fwd_packet_out(pkt_out)) != INDIGO_ERROR_NONE) {
        AIM_LOG_ERROR("Fwd pkt out failed %s", indigo_strerror(rv));
    }

    /* Fwding pkt out HAS to delete obj */
    of_packet_out_delete(pkt_out);

}

static uint32_t
get_virtual_router_ip (dhc_relay_t *dc)
{
    return (dc->vrouter_ip);
}

static uint32_t
get_dhcp_server_ip(dhc_relay_t *dc)
{
    return (dc->dhcp_server_ip);
}

static uint8_t *
get_virtual_router_mac(dhc_relay_t *dc)
{
    return (dc->vrouter_mac).addr;
}

/*
 * It drops a packet if
 * - the packet is malformed
 * - relay_agent_ip / routerIP doesn't mapped to any internal vlan
 *
 * Using relay_agent_ip map, it gets the internal vlan which the dhcp client is on
 * Circuit_id is only optional and used for legality check only
 * */
static int
dhcpra_handle_bootreply(of_octets_t *pkt, int dhcp_pkt_len, 
                        uint32_t relay_agent_ip,
                        uint8_t *relay_mac_addr,
                        uint32_t vlan_pcp,
                        of_port_no_t port_no,
                        int port_dump_data)
{
    ppe_packet_t       ppep;
    of_octets_t        data_tx;
    uint32_t           host_ip_addr;
    uint8_t            host_mac_address[OF_MAC_ADDR_BYTES];
    uint32_t           dhcp_pkt_new_len;
    uint32_t           vlan_id  = INVALID_VLAN;
    uint32_t           relay_agent_ip_to_vlan_id  = INVALID_VLAN;
    dhc_relay_t        *dc   = NULL;
    struct dhcp_packet *dhcp_pkt;

    dhcp_pkt = (struct dhcp_packet *)(pkt->data + DHCP_HEADER_OFFSET);
    
    /* Only support Ethernet */
    if (dhcp_pkt->htype != HTYPE_ETHER) {
        AIM_LOG_RL_ERROR (&dhcpra_pktin_log_limiter, os_time_monotonic(),
                          "Discard packets with unsupported hw type=%d on port=%d",
                          dhcp_pkt->htype, port_no);
        return 0;
    }

    if (dhcp_pkt->hlen != sizeof(host_mac_address)) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Discard packets with unsupport hw len=%d on port=%d",
                         dhcp_pkt->hlen, port_no);
        return 0;
    }

    if (!(dhcp_pkt->flags & htons(BOOTP_BROADCAST))) {
        /* Unicast */
        host_ip_addr  = ntohl(dhcp_pkt->yiaddr.s_addr);
        DHCPRA_MEMCPY(host_mac_address, dhcp_pkt->chaddr, sizeof(host_mac_address));
    } else {
        /* Broadcast */
        host_ip_addr  = htonl(INADDR_BROADCAST);
        DHCPRA_MEMSET (host_mac_address, 0xff, sizeof(host_mac_address));
    }

    /* Parse DCHP and strip option if any */
    dhcp_pkt_new_len = dhc_strip_relay_agent_options(dhcp_pkt, dhcp_pkt_len, &vlan_id);
    DHCPRA_DEBUG("dhcp_len %u, dhcp_new_len %u", dhcp_pkt_len, dhcp_pkt_new_len);

    if (dhcp_pkt_new_len == 0) {
        /* Option invalid: Drop packets */
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Discard a malformed packet");
        return 0;
    }

    /* This vlan_id should exist */
    dhcpr_virtual_router_key_to_vlan(&relay_agent_ip_to_vlan_id,
                                     relay_agent_ip,
                                     relay_mac_addr);
    if (relay_agent_ip_to_vlan_id == INVALID_VLAN) {
        /*
         * Can't find vlan using relay_agent_ip. This dhcp pkt is out of date, drop it
         * This might happen when controller removed a configuration from relay agent
         * before server is aware of configuration changed
         * */
        AIM_LOG_RL_WARN(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                        "Unsupported vlan_vid=%d on port=%d, relayIP=%d.%d.%d.%d",
                        vlan_id, port_no,
                        ((uint8_t*)&relay_agent_ip)[3],
                        ((uint8_t*)&relay_agent_ip)[2],
                        ((uint8_t*)&relay_agent_ip)[1],
                        ((uint8_t*)&relay_agent_ip)[0]);
        return 0;
    }

    if (vlan_id == INVALID_VLAN) {
        /* Option 82 doesn't exist, use relay_agent_ip_to_vlan_id */
        vlan_id = relay_agent_ip_to_vlan_id;
    } else {
        /* Legality check */
        AIM_TRUE_OR_DIE(vlan_id == relay_agent_ip_to_vlan_id,
                        "vlan_id=%u != agentIP_to_vlan=%d, vr_ip=%x, %s",
                        vlan_id, relay_agent_ip_to_vlan_id,
                        relay_agent_ip, inet_ntoa(*(struct in_addr *)&relay_agent_ip));
    }

    /* At this point, we should have a valid vlan */
    dc = dhcpr_get_dhcpr_entry_from_vlan_table(vlan_id);
    AIM_TRUE_OR_DIE(dc, "vlan_id %d", vlan_id);

    /* Set Ether, DOT1Q, IP, UDP src, dst, dhcp payload len */
    init_ppe_header(pkt->data, dhcp_pkt_new_len, 
                    PPE_PSERVICE_PORT_DHCP_SERVER, PPE_PSERVICE_PORT_DHCP_CLIENT);

    data_tx.data  = pkt->data;
    data_tx.bytes = dhcp_pkt_new_len + DHCP_HEADER_OFFSET;
    
    ppe_packet_init(&ppep, data_tx.data, data_tx.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_DIE("Packet parsing failed. packet=%{data}", data_tx.data, data_tx.bytes);
    }

    /*
     * Set VLAN / Assume EtherType TEID: x8100 / Keep PCP/DEI the same
     * Set IP src (Switch mgmt) / dst: broadcast or unicast
     * Set MAC Src (Switch generic MAC)
     * Set MAC Dst to packet->clientHW (for L2 forwarding)
     * Transmit will pump to OFPP_TABLE port
     */
    ppe_field_set(&ppep, PPE_FIELD_8021Q_VLAN, vlan_id);
    ppe_field_set(&ppep, PPE_FIELD_8021Q_PRI,  vlan_pcp);

    ppe_field_set(&ppep, PPE_FIELD_IP4_SRC_ADDR, relay_agent_ip);
    ppe_field_set(&ppep, PPE_FIELD_IP4_DST_ADDR, host_ip_addr);

    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, get_virtual_router_mac(dc));
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_DST_MAC, host_mac_address);

    /* Update ALL check sum: IP and UDP */
    ppe_packet_update(&ppep);

    if(port_dump_data) {
        DHCPRA_DEBUG("Port %d: BootReply: dumping packet sent to client", port_no);
        dhcpra_pkt_hexdump(data_tx.data, data_tx.bytes);
    }

    /* Send out */
    dhcp_stat_ports[port_no].dhcp_reply_relay++;
    dhcpra_send_pkt (&data_tx, port_no);
    return 0;
}

/*
 * It drops a packet if
 * - the packet is malformed
 * - its internal vlan has no dhcp relay configuration
 *
 * Use virtual_router_ip as relay_agent_ip
 * Circuit_id is only optional
 * */
static int
dhcpra_handle_bootrequest(of_octets_t *pkt, int dhcp_pkt_len, uint32_t vlan_id,
                          uint32_t vlan_pcp, of_port_no_t port_no,
                          int port_dump_data)
{
    ppe_packet_t        ppep;
    of_octets_t         data_tx;
    uint32_t            max_dhcp_pkt_len;
    uint32_t            dhcp_pkt_new_len;
    struct dhcp_packet  *dhcp_pkt;
    struct opt_info     *opt;
    uint32_t            switch_ip;
    dhc_relay_t*        dc;
    uint8_t             host_mac_address[OF_MAC_ADDR_BYTES];
    uint32_t            message_type = 0;

    if(!(dc = dhcpr_get_dhcpr_entry_from_vlan_table(vlan_id))){
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Unsupported vlan_vid=%d on port=%d", vlan_id, port_no);
        return 0;
    }

    opt = &dc->opt_id;
    dhcp_pkt = (struct dhcp_packet *) (pkt->data + DHCP_HEADER_OFFSET);
    max_dhcp_pkt_len = OUT_PKT_BUF_SIZE - DHCP_HEADER_OFFSET;

    /* Only support Ethernet */
    if (dhcp_pkt->htype != HTYPE_ETHER) {
        AIM_LOG_RL_ERROR (&dhcpra_pktin_log_limiter, os_time_monotonic(),
                          "Discard packets with unsupported hw type=%d on port=%",
                          dhcp_pkt->htype, port_no);
        return 0;
    }

    if (dhcp_pkt->hlen != sizeof(host_mac_address)) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Discard packets with unsupport hw len=%d on port=%d",
                         dhcp_pkt->hlen, port_no);
        return 0;
    }

    DHCPRA_MEMCPY(host_mac_address, dhcp_pkt->chaddr, OF_MAC_ADDR_BYTES);

    if (dhcp_pkt->hops < max_hop_count) {
        dhcp_pkt->hops = dhcp_pkt->hops + 1;
    } else {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Discard dhcp packet: dhcp hops %d > max_hop", dhcp_pkt->hops);
        return 0;
    }

    /* If giaddr matches one of our addresses, ignore the packet */
    switch_ip = get_virtual_router_ip(dc);
    if ((dhcp_pkt->giaddr.s_addr) == htonl(switch_ip)) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Error boot request having giaddr == switch_ip");
        return 0;
    }

    /* Always parse dhcp options to get message_type
     * and attach opt 82 if circuit_id is valid
     * Return new len */
    dhcp_pkt_new_len = dhc_add_relay_agent_options(dhcp_pkt, dhcp_pkt_len,
                                                   max_dhcp_pkt_len, &message_type, opt);

    DHCPRA_DEBUG("msg_type %u, dhcp_len %u, dhcp_new_len %u",
                  message_type, dhcp_pkt_len, dhcp_pkt_new_len);

    if (dhcp_pkt_new_len == 0) {
        /* Option or circuit corrupted */
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Discard a malformed packet");
        return 0;
    }

    /*
     * If giaddr is not already set, Set it so the server can
     *    figure out what net it's from and so that we can later
     *    forward the response to the correct net.
     * If it's already set, the response will be sent directly to
     * the relay agent that set giaddr, so we won't see it
     * */
    if (!dhcp_pkt->giaddr.s_addr) {
        dhcp_pkt->giaddr.s_addr = htonl(get_virtual_router_ip(dc));
    }

    /* Set Ether, DOT1Q, IP, UDP src, dst, dhcp payload len */
    init_ppe_header(pkt->data, dhcp_pkt_new_len,
                    PPE_PSERVICE_PORT_DHCP_CLIENT, PPE_PSERVICE_PORT_DHCP_SERVER);

    data_tx.data  = pkt->data;
    data_tx.bytes = dhcp_pkt_new_len + DHCP_HEADER_OFFSET;

    ppe_packet_init(&ppep, data_tx.data, data_tx.bytes);
    if (ppe_parse(&ppep) < 0) {
        AIM_DIE("Packet parsing failed. packet=%{data}", data_tx.data, data_tx.bytes);
    }

    /*
     * vlan = internalVlan from original packet
     * Set IP src (Switch mgmt) / dst (DHCP server)
     * Set MAC Src (client MAC)
     * Set MAC Dst to VirtualMAC to trigger L3 routing
     *    then HW replaces VirtualMAC with NextHop APR using HW caches 
     * Transmit will pump to OFPP_TABLE port
     */
    ppe_field_set(&ppep, PPE_FIELD_8021Q_VLAN, vlan_id);
    ppe_field_set(&ppep, PPE_FIELD_8021Q_PRI,  vlan_pcp);

    ppe_field_set(&ppep, PPE_FIELD_IP4_SRC_ADDR, switch_ip);
    ppe_field_set(&ppep, PPE_FIELD_IP4_DST_ADDR, get_dhcp_server_ip(dc));

    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_SRC_MAC, host_mac_address);
    ppe_wide_field_set(&ppep, PPE_FIELD_ETHERNET_DST_MAC, get_virtual_router_mac(dc));

    /* Update ALL check sum: IP and UDP */
    ppe_packet_update(&ppep);

    if(port_dump_data) {
        DHCPRA_DEBUG("Port %d: BootRequest: dumping packet sent to server", port_no);
        dhcpra_pkt_hexdump(data_tx.data, data_tx.bytes);
    }

    /* Send out */
    dhcp_stat_ports[port_no].dhcp_request_relay++;
    dhcpra_send_pkt (&data_tx, port_no);

    return 0;
}

/*
 * handle packet_in
 * Not DHCP packets will pass to controller
 * If it is a DHCP packet, we handle it
 * ** request: vlan not exist, pass to controller
 * **          option incorrect, drop
 * ** reply  :
 * */
indigo_core_listener_result_t
dhcpra_handle_pkt (of_packet_in_t *packet_in)
{

    of_octets_t                data;
    of_octets_t                ldata;
    of_port_no_t               port_no;
    of_match_t                 match;
    ppe_packet_t               ppep;
    uint32_t                   opcode;
    uint8_t                    buf[OUT_PKT_BUF_SIZE];
    struct dhcp_packet         *dhcp_pkt;
    uint32_t                   vlan_vid;
    uint32_t                   vlan_pcp;
    int                        dhcp_pkt_len;
    uint32_t                   relay_agent_ip;
    int                        port_dump_data = 0;
    uint8_t                    relay_mac_addr[OF_MAC_ADDR_BYTES];

    ldata.data  = buf;
    ldata.bytes =  OUT_PKT_BUF_SIZE;

    /* Note: do not need to check for
     * packet_in reason: OF_PACKET_IN_REASON_BSN_DHCP.
     * DHCP packet from server has Virtual Router IP in dst IP,
     * This pkt is matched to an L3 entry and delivered to CPU.
     * Switch HW doesn't set dhcp packet_in reason in this case.
     */

    of_packet_in_data_get(packet_in, &data);

    /* Get port_no for debugging purpose */
    if (packet_in->version <= OF_VERSION_1_1) {
        of_packet_in_in_port_get(packet_in, &port_no);
    } else {
        if (of_packet_in_match_get(packet_in, &match) < 0) {
            AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                             "match get failed");
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        port_no = match.fields.in_port;
        DHCPRA_DEBUG("port %u",port_no);
    }

    /* Parsing ether pkt and identify if this is a DHCP Packet */
    ppe_packet_init(&ppep, data.data, data.bytes);
    
    if (ppe_parse(&ppep) < 0) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Packet parsing failed. packet=%{data}", data.data, data.bytes);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (!(dhcp_pkt = (struct dhcp_packet*)ppe_header_get(&ppep, PPE_HEADER_DHCP))) {
        /*
         * Since we listen to pkt_ins
         * Not DHCP packet, simply return
         */
        AIM_LOG_RL_TRACE(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "port %u: NOT DHCP packet",port_no);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if(port_no > MAX_SYSTEM_PORT) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Port out of range %u", port_no);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if (dhcpra_dump_data == DHCPRA_DUMP_ENABLE_ALL_PORTS ||
        dhcpra_dump_data == port_no) {
        port_dump_data = 1;
    } else {
        port_dump_data = 0;
    }

    if(port_dump_data) {
        DHCPRA_DEBUG("Port %d: Dumping packet in", port_no);
        /* ppe_packet_dump won't have a nice display in syslog */
        dhcpra_pkt_hexdump(data.data, data.bytes);
    }

    if (data.bytes > OUT_PKT_BUF_SIZE) {
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "DHCP Packet too big len=%l", data.bytes);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    if(!ppe_header_get(&ppep, PPE_HEADER_8021Q)) {
        /* Only support single tag x8100, don't support double tag x9100 */
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "DHCP Packet with unsupported VLAN tag");
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    /* Don't support PPE_FIELD_OUTER_8021Q_VLAN / PPE_FIELD_INNER_8021Q_VLAN */
    ppe_field_get(&ppep, PPE_FIELD_8021Q_VLAN, &vlan_vid);
    ppe_field_get(&ppep, PPE_FIELD_8021Q_PRI, &vlan_pcp);

    /* Copy dhcp pkt from pkt */
    dhcp_pkt_len = ppe_header_get(&ppep, PPE_HEADER_ETHERNET) + data.bytes 
                   - ppe_header_get(&ppep, PPE_HEADER_DHCP);

    /*
     * buf is a storage for reply packet
     * Original packets might have IP options, ignore all IP options
     * Reserve a fixed ETH+DOT1.Q+IP+UDP header size
     * Copy only dhcp data
     */
    DHCPRA_MEMSET(buf, 0, sizeof(buf));
    DHCPRA_MEMCPY((buf+DHCP_HEADER_OFFSET), dhcp_pkt, dhcp_pkt_len);
    
    ppe_field_get(&ppep, PPE_FIELD_DHCP_OPCODE, &opcode);

    DHCPRA_DEBUG("port %u, dhcp opcode %u",port_no, opcode);
    switch (opcode) {
    case BOOTREQUEST:
        dhcp_stat_ports[port_no].dhcp_request++;
        /* If message_type = DHCPDISCOVER: forward to controller */
        if (dhcpra_handle_bootrequest(&ldata, dhcp_pkt_len, vlan_vid, vlan_pcp,
                                      port_no, port_dump_data)) {
            DHCPRA_DEBUG("Forward REQUEST to controller");
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        break;
    case BOOTREPLY:
        dhcp_stat_ports[port_no].dhcp_reply++;
        /*
         * Using relay_agent_ip if circuit_id not existing
         * ppe_field_get already takes care of ntohl
         * it makes [0] becomes MSB
         * relay_agent_ip: p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]
         *                [MSB]                               [LSB]
         * */
        ppe_field_get(&ppep, PPE_FIELD_IP4_DST_ADDR, &relay_agent_ip);
        ppe_wide_field_get(&ppep, 
                           PPE_FIELD_ETHERNET_DST_MAC,
                           relay_mac_addr);
        if (dhcpra_handle_bootreply(&ldata, dhcp_pkt_len, 
                                    relay_agent_ip, relay_mac_addr, 
                                    vlan_pcp, port_no, port_dump_data)) {
            DHCPRA_DEBUG("Forward REPLY to controller");
            return INDIGO_CORE_LISTENER_RESULT_PASS;
        }
        break;
    default:
        AIM_LOG_RL_ERROR(&dhcpra_pktin_log_limiter, os_time_monotonic(),
                         "Unsupported opcode=%d", opcode);
        return INDIGO_CORE_LISTENER_RESULT_PASS;
    }

    return INDIGO_CORE_LISTENER_RESULT_DROP;   
}

/************************
 * DHCPRA SYSTEM INIT
 ************************/

/* Return 0: success */
int
dhcpra_system_init()
{

    /* dhcp_relay table init */
    dhcpr_table_init();

    aim_ratelimiter_init(&dhcpra_pktin_log_limiter, 1000*1000, 5, NULL);

    /* handler dhcp packet */
    indigo_core_packet_in_listener_register(dhcpra_handle_pkt);

    return 0;
}
