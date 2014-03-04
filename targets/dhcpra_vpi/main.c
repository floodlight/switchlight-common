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

/*
 * Topology: dhclient <-> tun0/tap0 <-> DHCP RELAY AGENT <-> tun1/tap1 <-> dhcpserver
 * Preparation for ARP and Route 
 *    sudo arp -s 192.168.100.2 (Router-IP) de:d6:dd:3d:82:89 -i tap1
 *    route add -net 192.168.100.0 netmask 255.255.255.0 tap1
 * Check: 'arp -a -n' and 'route'
 *
 * 1. Set up dhcp server with test_cir_id below
 *       class "id-192.168.0.2" {
 *               match if option agent.circuit-id = "hell";
 *       }
 *       pool {
 *               allow members of "id-192.168.0.2";
 *               range 192.168.100.12;
 *       }
 *    Run dhcp server on tap1 interface
 *    sudo /usr/sbin/dhcpd -f -4 -pf /run/dhcp-server/dhcpd.pid -cf /etc/dhcp/dhcpd.conf tap1
 *
 *
 * 2. sudo ./build/gcc-local/bin/dhcpra_vpi
 *
 * 3. sudo dhclient -r tap0 (release ip address)
 *    sudo dhclient -v tap0 (get new ip address)
 *
 * 4. ifconfig to verify the address. Rerun step 3 and 4 as many times as you want. 
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
#include <ctype.h>

#include <indigo/of_state_manager.h>
#include <SocketManager/socketmanager.h>
#include <PPE/ppe.h>

#include <netinet/in.h>
#include "dhcp.h"
#include "dhcpra_int.h"
#include "dhcpr_table.h"

extern indigo_core_listener_result_t
dhcpra_handle_pkt (of_packet_in_t *packet_in);
extern int dhcpra_system_init();

#define VLAN_TEST 1

char test_cir_id[] = "hell";

dhc_relay_t dummy_dhcp_opt_info = {
        .internal_vlan_id     = 0,
        .vrouter_ip = 0xc0a86402,        //Router_IP,
        .dhcp_server_ip    = 0xc0a86401, //Dhcp_Server_IP,
        .vrouter_mac = { .addr = {0x55, 0x16, 0xc7, 0x01, 0x02, 0x03} },
        .opt_id = {  .circuit_id.data = (u_int8_t *) test_cir_id,
                    .circuit_id.bytes = (sizeof(test_cir_id)-1),
                    .remote_id.data = NULL,
                    .remote_id.bytes = 0 }

};

#ifdef USE_SIMPLE_DHCPR_TABLE
dhc_relay_t *VlanToDhcprConf[VLAN_MAX+1];

void dhcpra_table_init()
{
    int i;
    /* TODO Dummy vlan option initialization */
    for (i = 0; i <= VLAN_MAX; i++) {
       VlanToDhcprConf[i] = &dummy_dhcp_opt_info;
    }

}

static int is_vlan_valid (uint32_t vlan)
{
    if (vlan >= 0 && vlan <= VLAN_MAX)
        return 1;
    else
        return 0;
}

dhc_relay_t*
get_dhcp_conf(uint32_t vlan)
{
    if(is_vlan_valid(vlan))
        return VlanToDhcprConf[vlan];
    else
        return NULL;
}
#else /* USE_COMPLEX_DHCPR_TABLE */
static const indigo_core_gentable_ops_t *ops;
static void *table_priv;
void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *_ops,
    void *_table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    if (!strcmp(name, "dhcp_relay")) {
        ops = _ops;
        table_priv = _table_priv;
    }

    *gentable = (void *)1; //no use
}

/* Dummy for compiler */
void
indigo_core_gentable_unregister (indigo_core_gentable_t *gentable)
{
    ASSERT(gentable == (void *)1);
}
/* Dummy for compiler */
indigo_error_t
indigo_core_packet_in_listener_register (indigo_core_packet_in_listener_f fn)
{
    return INDIGO_ERROR_NONE;
}
/* Dummy for compiler */
void
indigo_core_packet_in_listener_unregister(indigo_core_packet_in_listener_f fn)
{
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
make_value (uint32_t vr_ip, of_mac_addr_t mac,
            uint32_t dhcp_ser_ip, of_octets_t *cid)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(OF_VERSION_1_3);
        of_bsn_tlv_ipv4_value_set(tlv, vr_ip);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_mac_t *tlv = of_bsn_tlv_mac_new(OF_VERSION_1_3);
        of_bsn_tlv_mac_value_set(tlv, mac);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(OF_VERSION_1_3);
        of_bsn_tlv_ipv4_value_set(tlv, dhcp_ser_ip);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_circuit_id_t *tlv = of_bsn_tlv_circuit_id_new(OF_VERSION_1_3);
        AIM_TRUE_OR_DIE(of_bsn_tlv_circuit_id_value_set(tlv, cid) == OF_ERROR_NONE);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    return list;
}

void add_entry_to_dhcpr_table()
{
    indigo_error_t rv;
    int i;
    of_list_bsn_tlv_t *key, *value;
    void              *entry_priv;

    //Test
    dhc_relay_t       *dc;
    uint32_t          vlan;

    //Only add Vlan1 for now
    for (i=VLAN_TEST; i<=VLAN_TEST; i++) {
        key = make_key(i);
        value = make_value(dummy_dhcp_opt_info.vrouter_ip,
                dummy_dhcp_opt_info.vrouter_mac,
                dummy_dhcp_opt_info.dhcp_server_ip,
                &dummy_dhcp_opt_info.opt_id.circuit_id);
        if((rv = ops->add(table_priv, key, value, &entry_priv)) != INDIGO_ERROR_NONE) {
            printf("Error Add table rv=%u", rv);
            exit(1);
        } else {
            printf("\nVlan %d Added to dhcp table\n", i);

            /* Test 1: dhcp conf array */
            if (! (dc = dhcpr_get_dhcpr_entry_from_vlan_table(i))) {
                printf("Error get_dhcp_conf Vlan %d\n", i);
            }

            /* Test 2: cir -> vlan */
            dhcpr_circuit_id_to_vlan(&vlan, dummy_dhcp_opt_info.opt_id.circuit_id.data,
                                                dummy_dhcp_opt_info.opt_id.circuit_id.bytes );
            printf("circuit_id_to_vlan = %u\n", vlan);
            AIM_TRUE_OR_DIE(vlan==1);

            /* Test 3: routerip -> vlan */
            dhcpr_virtual_router_ip_to_vlan(&vlan, dummy_dhcp_opt_info.vrouter_ip);
            printf("router_ip_to_vlan = %u\n", vlan);
            AIM_TRUE_OR_DIE(vlan==1);

            printf("DHCP CONF TABLE ok\n");
        }
    }
}
#endif /* USE_SIMPLE_DHCPR_TABLE */


#define ETHERTYPE_DOT1Q 0x8100

vpi_t vpi1, vpi2;

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif
void hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
        /* print offset */
        if(i % HEXDUMP_COLS == 0) {
            printf("0x%06x: ", i);
        }

        /* print hex data */
        if(i < len) {
            printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else { /* end of block, just aligning for ASCII dump */
            printf("   ");
        }

        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) { /* end of block, not really printing */
                    putchar(' ');
                }
                else if(isprint(((char*)mem)[j])) { /* printable char */
                    putchar(0xFF & ((char*)mem)[j]);
                }
                else {/* other char */
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

void hexdump_pkt (uint8_t *bytes, int size_bytes)
{
    int i;
    printf("bytes=%d\n", size_bytes);
    for (i = 0; i < size_bytes; i++) {
        printf("%2.2x", bytes[i]);
    }
    printf("\n");
}

void get_dhcp_options(ppe_packet_t *ppep, int len, int dump, int *option)
{
    struct dhcp_packet  *dhcp_pkt;
    int                 dhcp_pkt_len;
    int                 dhcp_opt_len;

    if (!(dhcp_pkt = (struct dhcp_packet*)ppe_header_get(ppep, PPE_HEADER_DHCP))) {
        printf("NOT DHCP packet");
        return;
    }

    dhcp_pkt_len = ppe_header_get(ppep, PPE_HEADER_ETHERNET) + len 
                   - ppe_header_get(ppep, PPE_HEADER_DHCP);
    dhcp_opt_len = dhcp_pkt_len - ((uint8_t*)&(dhcp_pkt->options) - (uint8_t*)dhcp_pkt);

    if(dump) {
        printf("dhcp_pkt_len=%d, opt_len=%d\n",dhcp_pkt_len,dhcp_opt_len);
        hexdump(&(dhcp_pkt->options), dhcp_opt_len);
        hexdump_pkt((uint8_t*)dhcp_pkt, dhcp_pkt_len);
    }
    
    *option = dhcp_pkt->op;
}

indigo_error_t
dhcpra_create_send_packet_in (of_port_no_t in_port, of_octets_t *of_octets)
{
    of_packet_in_t *of_packet_in;
    of_match_t     match;
    ppe_packet_t   ppep;
    ppe_header_t   format;
    uint8_t        buf[1500];
    int            option;

    int debug_dump = 0;
    if (!of_octets) return INDIGO_ERROR_UNKNOWN;

    /*
     * Check if the packet_in is untagged, then add the Vlan tag 
     */
    ppe_packet_init(&ppep, of_octets->data, of_octets->bytes);
    if (ppe_parse(&ppep) < 0) {
        printf("RAW untag linux packet parsing failed.\n");
        return INDIGO_ERROR_UNKNOWN;
    } 

    if (!(ppe_header_get(&ppep, PPE_HEADER_DHCP))) {
        /* Since we listen to all pkt_in
         * Rate is high, no need add debug msg here
         * Not LLDP packet, simply return */
        printf("in_port=%u: NOT DHCP packet IGNORED", in_port);
        return INDIGO_ERROR_NONE;
    }

    /* Dump up to DHCP hdr */
    printf("RAW untag Linux dump\n");
    get_dhcp_options(&ppep, of_octets->bytes, debug_dump, &option);

    ppe_packet_format_get(&ppep, &format);
    if (format != PPE_HEADER_8021Q) {
        of_octets->bytes += 4;
        memcpy(buf, of_octets->data, of_octets->bytes);
        memcpy(of_octets->data+16, buf+12, of_octets->bytes-16);
        of_octets->data[12] = ETHERTYPE_DOT1Q >> 8;
        of_octets->data[13] = ETHERTYPE_DOT1Q & 0xFF;
        of_octets->data[14] = 0;
        of_octets->data[15] = VLAN_TEST; //7;  
    } else {
        printf ("Recieve tag pkg -- exit\n");
        exit(2);
    }

    if (ppe_parse(&ppep) < 0) {
        printf("VLAN Tag added: Packet_in parsing failed.\n");
        return INDIGO_ERROR_UNKNOWN;
    } 

    /* Dump Vlan tag */
    printf("Input pkt dump: VLAN=%d\n", VLAN_TEST);
    hexdump_pkt(of_octets->data, of_octets->bytes);

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

    of_packet_in_reason_set(of_packet_in, OF_PACKET_IN_REASON_BSN_DHCP);

    if ((of_packet_in_data_set(of_packet_in, of_octets)) != OF_ERROR_NONE) {
        printf("Failed to write packet data to packet-in message\n");
        of_packet_in_delete(of_packet_in);
        return INDIGO_ERROR_UNKNOWN;
    }

    printf("\n\nSubmit pkt to dhcpra to process ... \n");
    if (dhcpra_handle_pkt(of_packet_in) == 
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
    int              option;
    vpi_t            vpi;

    int debug_dump = 0;
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
        printf("Packet_out from DHCP agent parsing failed.");
        return INDIGO_ERROR_UNKNOWN;
    }
    get_dhcp_options(&ppep, of_octets.bytes, 0, &option);

    if (option == BOOTREQUEST) {
        vpi = vpi2; //Send to Server LAN
        printf("\n\n Sending to SERVER\n");
    } else if (option == BOOTREPLY) {
        vpi = vpi1; //Send back to client LAN
        printf("\n\n Sending to CLIENT\n");
    } else {
        printf("ERROR UNSUPPORTED DHCP TYPE %d\n", option);
    }

        
    hexdump_pkt(of_octets.data, of_octets.bytes);

    ppe_packet_format_get(&ppep, &format);
    if (format == PPE_HEADER_8021Q) {
        printf("Packet out must be untagged\n");
        memmove(of_octets.data +12, of_octets.data +16, 
                of_octets.bytes -16); 
        of_octets.bytes -= 4;
    }  else {
        printf("Expect Tagged Packet out\n");
        exit (1);
    }

    if (ppe_parse(&ppep) < 0) {
        printf("VLAN remove. Packet_out parsing failed.");
        return INDIGO_ERROR_UNKNOWN;
    }
    printf("RAW pkt-out dump\n");
    get_dhcp_options(&ppep, of_octets.bytes, debug_dump, &option);
    //Debugging only: ppe_packet_dump(&ppep,&aim_pvs_stdout);

    vpi_send(vpi, of_octets.data, of_octets.bytes);
    return INDIGO_ERROR_NONE;
} 

int main(int argc, char* argv[])
{
    uint8_t     buf[1500];
    struct      pollfd fds[2];
    of_octets_t of_octets;

    dhcpra_system_init();
    add_entry_to_dhcpr_table();

    printf("dhcpra_vpi start\n");
    vpi_init();
    vpi1 = vpi_create("tap|tap0");  //tap0: client LAN
    vpi2 = vpi_create("tap|tap1");  //tap1: server LAN

    if (!vpi1) {
        printf("DIE here\n");
        assert(vpi1);
        return 0;
    }

    if (!vpi2) {
        assert(vpi2);
        return 0;
    }
    
    if (argc == 2) {
        printf("Closing tap interfaces ..\n");
        printf("Return vpi1_ref_count=%d\n", vpi_unref(vpi1));
        printf("Return vpi2_ref_count=%d\n", vpi_unref(vpi2));
        vpi_close();
        return 0;
    }

    fds[0].fd = vpi_descriptor_get(vpi1);
    fds[1].fd = vpi_descriptor_get(vpi2);
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

    of_octets.bytes = 0;
    of_octets.data = buf;

    while (poll(fds, 2, -1) >= 0) {

        if (fds[0].revents & POLLIN) {
            of_octets.bytes = vpi_recv(vpi1, buf, 1500, 0);
            printf("received_pkt on tap0 with %d bytes\n", of_octets.bytes);
            dhcpra_create_send_packet_in(10, &of_octets);
        }

        if (fds[1].revents & POLLIN) {
            of_octets.bytes = vpi_recv(vpi2, buf, 1500, 0);
            printf("received_pkt on tap1 with %d bytes\n", of_octets.bytes);
            dhcpra_create_send_packet_in(20, &of_octets);
        }
    }
    
    vpi_unref(vpi1);
    vpi_unref(vpi2);
    vpi_close();
 
    return 0;
}

