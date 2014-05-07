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

#include <dhcpra/dhcpra_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <AIM/aim.h>

#include <string.h>
#include <ctype.h>

#include <indigo/of_state_manager.h>
#include <loci/loci_obj_dump.h>
#include <SocketManager/socketmanager.h>
#include <PPE/ppe.h>

#include <netinet/in.h>
#include "dhcp.h"
#include "dhcpra_int.h"
#include "dhcpr_table.h"

extern int dhcpra_system_init();
extern indigo_core_listener_result_t dhcpra_handle_pkt (of_packet_in_t *packet_in);
extern indigo_core_listener_result_t dhcpra_handle_msg (indigo_cxn_id_t cxn_id, of_object_t *msg);

char test_cir_id[] = "hell";
/* Destination Mac of Tap1 */
//uint8_t  SW_VMAC_address[OF_MAC_ADDR_BYTES] = {0x4e, 0x86, 0x02, 0xe3, 0xa0, 0x2c};

dhc_relay_t dummy_dhcp_opt_info = {
        .internal_vlan_id     = 0, //Will be set when initialization
        .vrouter_ip = 0xc0a86402, //G_Sw_Mgmt_IP,
        .dhcp_server_ip    = 0xc0a86401, //G_Dhcp_Server_IP,
        .vrouter_mac = { .addr = {0x55, 0x16, 0xc7, 0x01, 0x02, 0x03} },
        .opt_id = {  .circuit_id.data = (u_int8_t *) test_cir_id,
                     .circuit_id.bytes = (sizeof(test_cir_id)-1),
                     .remote_id.data = NULL,
                     .remote_id.bytes = 0 }

};

uint8_t cir_id2_array [] = { 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
of_octets_t dummy_cir_id2= { .data = cir_id2_array,
                              .bytes = sizeof(cir_id2_array)
                            };

//#define USE_SIMPLE_DHCPR_TABLE
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

int
dhcpra_relayIP_to_vlan(uint32_t *vlan, uint32_t relayIP)
{
    int ret = -1;
    dhc_relay_t *dc;

    int i = 0;
    for (i = 0; i <= VLAN_MAX; i++) {
        dc = get_dhcp_conf(i);

        if (!dc)
            continue;

        if (dc->virtualRouterIP == relayIP) {
            *vlan = i;
            break;
        }
    }

    return ret;
}

int
dhcpra_cir_id_to_vlan(uint32_t *vlan, uint8_t *cir_id, int cir_id_len)
{
    int ret = -1;
    int i = 0;
    dhc_relay_t *dc;
    struct opt_info *opt = NULL;
    for (i = 0; i <= VLAN_MAX; i++) {
        dc = get_dhcp_conf(i);
        if (!dc)
            continue;

        opt = &(dc->optID);
        if (opt->circuit_id.data &&
            opt->circuit_id.bytes == cir_id_len &&
            !memcmp(opt->circuit_id.data, cir_id, cir_id_len)) {
            *vlan = i;
            ret = 0;
            break;
        }
    }
    return ret;
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
        table_priv = _table_priv; //NULL
    }

    *gentable = (void *)1; //FAKE no use
}

/* Dummy for compiler */
void
indigo_core_gentable_unregister (indigo_core_gentable_t *gentable)
{
    AIM_TRUE_OR_DIE(gentable == (void *)1);
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
        if (cid) {
            of_bsn_tlv_circuit_id_t *tlv = of_bsn_tlv_circuit_id_new(OF_VERSION_1_3);
            AIM_TRUE_OR_DIE(of_bsn_tlv_circuit_id_value_set(tlv, cid) == OF_ERROR_NONE);
            of_list_append(list, tlv);
            of_object_delete(tlv);
        }
    }
    return list;
}

int fill_all_vlan_dhcpr_table_test()
{
    indigo_error_t rv;
    of_list_bsn_tlv_t *key, *value;
    void              *entry_priv;
    dhc_relay_t       *dhc_relay;

    int k;
    int vlan_no;
    int vr_ip_no;
    int cir_id_no;

    uint32_t      virtualRouterIP = 1;
    of_mac_addr_t mac = { .addr = {0x55, 0x16, 0xc7, 0x01, 0x02, 0x03} };
    uint32_t      dhcpServerIP    = 2;
    uint16_t      cir_value[VLAN_MAX+1];
    of_octets_t   cir_id;

    int num_of_vlan = VLAN_MAX;
    int extra_vlan = 2; //Test error

    //NOTE: no need to do htonl or htons,
    //What ever value we send here, we get over there
    //No need to convert.

    //Initialize cir_value
    for (k = 0; k <= num_of_vlan; k++) {
        cir_value[k] = (k+1);
    }


    printf("TEST:1 fill all\n");
    /* Add 1st half having circuit */
    for (k = 0; k < num_of_vlan/2 ; k++) {

        cir_id.bytes = sizeof(cir_value[k]);
        cir_id.data  = (uint8_t*)&cir_value[k];

        key = make_key(k);
        value = make_value((virtualRouterIP+k),
                           mac,
                           (dhcpServerIP+k),
                           &cir_id);

        if((rv = ops->add(table_priv, key, value, &entry_priv)) != INDIGO_ERROR_NONE) {
            printf("Error out of range table %u, rv=%u", k, rv);
            exit(1);
        }
    }

    /* Add 2nd half non circuit */
    printf("Range k=%u - %u\n", num_of_vlan/2, num_of_vlan);
    for (k = num_of_vlan/2; k<= num_of_vlan+extra_vlan ; k++) {
        key = make_key(k);
        value = make_value((virtualRouterIP+k),
                           mac,
                           (dhcpServerIP+k),
                           NULL);

        if((rv = ops->add(table_priv, key, value, &entry_priv)) != INDIGO_ERROR_NONE) {
            printf("Test Add table incorret Vlan range %u, rv=%u\n", k, rv);
        }
    }

    vlan_no = dhcpr_table_get_vlan_entry_count();
    vr_ip_no = dhcpr_table_get_virtual_router_ip_entry_count();
    cir_id_no = dhcpr_table_get_circuit_id_entry_count();
    AIM_TRUE_OR_DIE(vlan_no  == num_of_vlan+1, "vlan=%u", vlan_no);
    AIM_TRUE_OR_DIE(vr_ip_no == num_of_vlan+1, "vr_ip_no=%u", vr_ip_no);
    AIM_TRUE_OR_DIE(cir_id_no == (num_of_vlan/2),
                                    "cir_id_no=%u", cir_id_no);

    printf("TEST:2 modify all\n");
    /* Modify 1/4:
     * --Same virtual Router
     * --No circuit
     * */
    for (k = 0; k < num_of_vlan/4 ; k++) {
        dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(k);
        AIM_TRUE_OR_DIE(dhc_relay);
        key = make_key(k);
        value = make_value((virtualRouterIP+k),
                           mac,
                           (dhcpServerIP+k),
                           NULL);

        if((rv = ops->modify(table_priv, dhc_relay, key, value)) != INDIGO_ERROR_NONE) {
            printf("Error Add table %u, rv=%u", k, rv);
            exit(1);
        }
    }
    /* Modify 1/4-2/4:
     * --Diff virtual Router
     * --No circuit
     * */
    for (k = num_of_vlan/4; k < num_of_vlan/2; k++) {
        dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(k);
        AIM_TRUE_OR_DIE(dhc_relay);
        key = make_key(k);
        value = make_value((virtualRouterIP+k+num_of_vlan),
                           mac,
                           (dhcpServerIP+k),
                           NULL);

        if((rv = ops->modify(table_priv, dhc_relay, key, value)) != INDIGO_ERROR_NONE) {
            printf("Error Add table %u, rv=%u", k, rv);
            exit(1);
        }
    }

    /* Modify 2/4-3/4
     * -- Same virtual router
     * -- Add circuit
     * */
    for (k = num_of_vlan/2; k<= 3*num_of_vlan/4 ; k++) {
        dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(k);
        AIM_TRUE_OR_DIE(dhc_relay);

        cir_id.bytes = sizeof(cir_value[k]);
        cir_id.data  = (uint8_t*)&cir_value[k];
        key = make_key(k);
        value = make_value((virtualRouterIP+k),
                           mac,
                           (dhcpServerIP+k),
                           &cir_id);

        if((rv = ops->modify(table_priv, dhc_relay, key, value)) != INDIGO_ERROR_NONE) {
            printf("Error Add table %u, rv=%u", k, rv);
            exit(1);
        }
    }

    /* Modify 2/4-3/4
     * -- Diff virtual router
     * -- Add circuit
     * */
    for (k = 3*num_of_vlan/4; k<= num_of_vlan ; k++) {
        dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(k);
        AIM_TRUE_OR_DIE(dhc_relay);
        cir_id.bytes = sizeof(cir_value[k]);
        cir_id.data  = (uint8_t*)&cir_value[k];
        key = make_key(k);
        value = make_value((virtualRouterIP+k+num_of_vlan),
                           mac,
                           (dhcpServerIP+k),
                           &cir_id);

        if((rv = ops->modify(table_priv, dhc_relay, key, value)) != INDIGO_ERROR_NONE) {
            printf("Error Add table %u, rv=%u", k, rv);
            exit(1);
        }
    }

    vlan_no = dhcpr_table_get_vlan_entry_count();
    vr_ip_no = dhcpr_table_get_virtual_router_ip_entry_count();
    cir_id_no = dhcpr_table_get_circuit_id_entry_count();
    AIM_TRUE_OR_DIE(vlan_no  == num_of_vlan+1, "vlan=%u", vlan_no);
    AIM_TRUE_OR_DIE(vr_ip_no == num_of_vlan+1, "vr_ip_no=%u", vr_ip_no);
    AIM_TRUE_OR_DIE(cir_id_no == (num_of_vlan - num_of_vlan/2 + 1),
                                    "cir_id_no=%u", cir_id_no);

    printf("TEST:3 delete all\n");
    for (k = 0; k<= num_of_vlan; k++) {
        dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(k);
        AIM_TRUE_OR_DIE(dhc_relay);
        key = make_key(k);
        ops->del(table_priv, dhc_relay, key);
    }
    /* Delete all */
    vlan_no = dhcpr_table_get_vlan_entry_count();
    vr_ip_no = dhcpr_table_get_virtual_router_ip_entry_count();
    cir_id_no = dhcpr_table_get_circuit_id_entry_count();
    AIM_TRUE_OR_DIE(vlan_no == 0);
    AIM_TRUE_OR_DIE(vr_ip_no == 0);
    AIM_TRUE_OR_DIE(cir_id_no == 0);

    return 1;
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
    uint32_t          vr_ip = dummy_dhcp_opt_info.vrouter_ip+1;
    //Only add Vlan1 for now
    for (i=1; i<2; i++) {
        key = make_key(i);
        value = make_value(vr_ip,
                dummy_dhcp_opt_info.vrouter_mac,
                dummy_dhcp_opt_info.dhcp_server_ip,
                &dummy_cir_id2);

        //Test Add
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
            dhcpr_circuit_id_to_vlan(&vlan, dummy_cir_id2.data,
                                            dummy_cir_id2.bytes );
            printf("circuit_id_to_vlan = %u\n", vlan);
            AIM_TRUE_OR_DIE(vlan==1);

            /* Test 3: routerip -> vlan */
            dhcpr_virtual_router_key_to_vlan(&vlan, vr_ip, dummy_dhcp_opt_info.vrouter_mac.addr);
            printf("router_ip_to_vlan = %u, vr_ip = %s\n",
                        vlan, inet_ntoa(*(struct in_addr *) &vr_ip));
            AIM_TRUE_OR_DIE(vlan==1);

            printf("DHCP CONF TABLE ok\n");
        }

    }
}

void mod_entry_to_dhcpr_table()
{

    of_list_bsn_tlv_t *key, *value;
    dhc_relay_t       *dhc_relay;
    uint32_t          vlan_id = 1;
    uint32_t          vlan_ret = 0;

    printf("\nVlan %d Modify to dhcp table\n", vlan_id);

    if (! (dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(vlan_id))) {
        printf("Error get_dhcp_conf Vlan %d\n", vlan_id);
    }

    key = make_key(vlan_id);
    value = make_value(dummy_dhcp_opt_info.vrouter_ip,
                dummy_dhcp_opt_info.vrouter_mac,
                dummy_dhcp_opt_info.dhcp_server_ip,
                &dummy_dhcp_opt_info.opt_id.circuit_id);

    ops->modify(table_priv, dhc_relay, key, value);
    /* Test 2: cir -> vlan */
    dhcpr_circuit_id_to_vlan(&vlan_ret, dummy_cir_id2.data,
                                        dummy_cir_id2.bytes);
    printf("circuit_id_to_vlan = %d\n", vlan_ret);
    AIM_TRUE_OR_DIE(vlan_ret==INVALID_VLAN);

    /* Test 3: routerip -> vlan */
    dhcpr_virtual_router_key_to_vlan(&vlan_ret, dummy_dhcp_opt_info.vrouter_ip+1, dummy_dhcp_opt_info.vrouter_mac.addr);
    printf("router_ip_to_vlan = %d\n", vlan_ret);
    AIM_TRUE_OR_DIE(vlan_ret==INVALID_VLAN);

    /* Test 4: cir -> vlan */
   dhcpr_circuit_id_to_vlan(&vlan_ret, dummy_dhcp_opt_info.opt_id.circuit_id.data,
                                       dummy_dhcp_opt_info.opt_id.circuit_id.bytes );
   printf("circuit_id_to_vlan = %d\n", vlan_ret);
   AIM_TRUE_OR_DIE(vlan_ret==vlan_id);

   /* Test 5: routerip -> vlan */
   dhcpr_virtual_router_key_to_vlan(&vlan_ret, dummy_dhcp_opt_info.vrouter_ip, dummy_dhcp_opt_info.vrouter_mac.addr);
   printf("router_ip_to_vlan = %d\n", vlan_ret);
   AIM_TRUE_OR_DIE(vlan_ret==vlan_id);

   printf("\nVlan %d Modify to dhcp table change virtual routerIP and circuit \n", vlan_id);
}

void del_entry_to_dhcpr_table()
{

    of_list_bsn_tlv_t *key;
    dhc_relay_t       *dhc_relay;
    uint32_t          vlan_id = 1;
    uint32_t          vlan_ret = 0;


    printf("\nVlan %d Delete to dhcp table\n", vlan_id);

    if (! (dhc_relay = dhcpr_get_dhcpr_entry_from_vlan_table(vlan_id))) {
        printf("Error get_dhcp_conf Vlan %d\n", vlan_id);
    }

    key = make_key(vlan_id);

    ops->del(table_priv, dhc_relay, key);
    /* Test 2: cir -> vlan */
    dhcpr_circuit_id_to_vlan(&vlan_ret, dummy_dhcp_opt_info.opt_id.circuit_id.data,
                                    dummy_dhcp_opt_info.opt_id.circuit_id.bytes );
    printf("circuit_id_to_vlan = %d\n", vlan_ret);
    AIM_TRUE_OR_DIE(vlan_ret==INVALID_VLAN);

    /* Test 3: routerip -> vlan */
    dhcpr_virtual_router_key_to_vlan(&vlan_ret, dummy_dhcp_opt_info.vrouter_ip, dummy_dhcp_opt_info.vrouter_mac.addr);
    printf("router_ip_to_vlan = %d\n", vlan_ret);
    AIM_TRUE_OR_DIE(vlan_ret==INVALID_VLAN);

   printf("\nVlan %d Delete entry\n", vlan_id);
}
#endif /* USE_SIMPLE_DHCPR_TABLE */

#define MAX_TEST 5
int dhcp_pkt_matched[2]; //dicovery: 0, offer 1
int test_pass[MAX_TEST];

/***************************************************
 ****************DHCP DISCOVER*************************
 **************************************************/
uint16_t Dhcp_discover_easy_to_read_unused[] =
    {
        //MAC: DST, SRC, TYPE 0800
        0xffff, 0xffff,0xffff, 0x000c, 0x2926, 0xd330, 
        0x8100, 0x0001, // Manually add Dot1q: 0x8100, VLANID = 1,
        0x0800, //Ethernet Type: 0x0800: IPv4 
        //Ofset: 12 + 4 + 2 = 18
        //IP verion-header-tos,len 0x140 (328), id, flag-offset, ttl(0x80)-protoID(0x11), CS(3996)
        //   src 0, dst f (broadcast)   
        0x4510, 0x0148, 0x0000, 0x0000, 0x8011, 0x3996, 0x0000, 0x0000, 0xffff, 0xffff,
        //UDP Src port 68, dst port 67(0x43), len 308, 0xa2eb: validation disable
        0x0044 , 0x0043 , 0x0134 , 0x5b7f,
        //Bootstrap Protocol
        0x0101 , 0x0600, //Req-hw, hw-len-hop
        0xaa05 , 0xbc7c, //Transation ID
        0x0000 , 0x0000, //Sec, boot-flag(unicast)
        0x0000 , 0x0000, //Cli Addr
        0x0000 , 0x0000, //Your Addr
        0x0000 , 0x0000, //Server Addr
        0x0000 , 0x0000, //Gateway IP
        0x000c , 0x2926, //Client HW and Padding
        0xd330 , 0x0000, 
        0x0000 , 0x0000,
        0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, //Server Host Name  
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000,
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000,  //Boot File Name
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000,
        0x6382 , 0x5363, //options: Magic Cookie 
        0x3501 , 0x010c , 0x0275, //DHCP type 35 01 01, Host Name 0c 02 75 62
        0x6237 , 0x0d01 , 0x1c02 , 0x030f , 0x0677 , 0x0c2c , 0x2f1a , 0x792a, //Param Req 55(0x37) len 13(0xd)
        0xff00 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, //0xff: END
        0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000 , 0x0000, 
        0x0000 , 0x0000 , 0x0000,
    };

char Dhcp_discovery_hex_stream[] = 
    "ffffffffffff000c2926d330"
    "81000001" // Manually add Dot1q: 0x8100, VLANID = 1,
    "0800"
    "45100148000000008011399600000000ffffffff"
    "004400430134a2eb"
    "01010600f4b52a600000000000000000000000000000000000000000000c2926d33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "63825363"
    "3501010c027562370d011c02030f06770c2c2f1a792a"
    "ff00"
    "000000000000000000000000000000000000000000000000000000000000000000000000";
uint8_t Dhcp_discovery[sizeof(Dhcp_discovery_hex_stream)/2];

/* NOTE Gateway IP change causing it failed */
char Dhcp_discovery_expected_hex_stream[] = 
    "01010601f4b52a6000000000000000000000000000000000"
    "c0a86402" //"40302010" //Gateway IP
    "000c2926d33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "63825363"
    "3501010c027562370d011c02030f06770c2c2f1a792a"
    "5206"
    "0104" "68656c6c" //Circuit 'hell' is added
    "ff0000000000000000000000000000000000000000000000000000000000";

 uint8_t Dhcp_discovery_expected[sizeof(Dhcp_discovery_expected_hex_stream)/2];

/***************************************************
 ****************DHCP OFFER*************************
 **************************************************/

/* Using wireshark: sel frame, sel copy-> hex stream */
char Dhcp_offer_hex_stream[] = 
    //"000c2926d330"
    "5516c7010203" // Must be matched to dhcpra table
    "005056e016ad" // Ether hdr 
    "81000001" //Manually add Dot1q: 0x8100, VLANID = 1,
    "0800" //Ether type: IPv4
    "45100148000000001011e411ac1036fe" "c0a86402" //"ac103665" //IP
    "00430044013404a5" //Udp
    "02010600f4b52a600000000000000000ac103665ac1036fe00000000000c2926d33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "63825363" //DHCP Cookie
    "3501023604ac1036fe3304000007080104ffffff001c04ac1036ff0304ac1036020f0b6c6f63616c646f6d61696e0604ac1036022c04ac103602"
    "5206" //Manually add 8 bytes DHCP 82 option, len 6 
    "0104" //CirID_option_code 1, len 4
    "68656c6c" //CircuitID = hell
    "ff00";
uint8_t Dhcp_offer[sizeof(Dhcp_offer_hex_stream)/2];

char Dhcp_offer_expected_hex_stream[] = 
    "02010600f4b52a600000000000000000ac103665ac1036fe00000000000c2926d33000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "63825363" //DHCP Cookie
    "3501023604ac1036fe3304000007080104ffffff001c04ac1036ff0304ac1036020f0b6c6f63616c646f6d61696e0604ac1036022c04ac103602"//Unchange, Option 82 is remove
    "ff00";
uint8_t Dhcp_offer_expected [sizeof(Dhcp_offer_expected_hex_stream)/2];


/************************************/

void hexdump_pkt (uint8_t *bytes, int size_bytes)
{
    int i;
    printf("bytes=%d\n", size_bytes);
    for (i = 0; i < size_bytes; i++) {
        printf("%2.2x", bytes[i]);
    }
    printf("\n");
}
void convert_chars_to_bytes (uint8_t *bytes, char *str_ori, int size_bytes)
{
    int i;
    for (i = 0; i < size_bytes; i++) {
        sscanf(&str_ori[i * 2], "%2hhx", &bytes[i]);//1 h: short, hh: byte
    }
    //printf("convert chars to bytes\n");
    //hexdump_pkt(bytes, size_bytes);
}
  

void ntohs_array (uint16_t *array, int bytes)
{
    int i;

    for (i = 0; i < (bytes/2); i++)
        array[i] = ntohs(array[i]);

    hexdump_pkt((uint8_t *)array, bytes);
}
void htons_array (uint16_t *array, int bytes)
{
    int i = 0;
    for (i = 0; i < (bytes/2); i++)
        array[i] = htons(array[i]);

    hexdump_pkt((uint8_t *)array, bytes);
}

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

void parse_dhcp_options(ppe_packet_t *ppep, int len, int cmp, int dump)
{
    struct dhcp_packet  *dhcp_pkt;
    int                 dhcp_pkt_len;
    int                 dhcp_opt_len;
    uint8_t             *dhcp_expected = NULL;
    int                 dhcp_expected_len = 0;
    int                 match_index = 0;
    if (!(dhcp_pkt = (struct dhcp_packet*)ppe_header_get(ppep, PPE_HEADER_DHCP))) {
        printf("NOT DHCP packet");
        return;
    }

    dhcp_pkt_len = ppe_header_get(ppep, PPE_HEADER_ETHERNET) + len 
                   - ppe_header_get(ppep, PPE_HEADER_DHCP);
    dhcp_opt_len = dhcp_pkt_len - ((uint8_t*)&(dhcp_pkt->options) - (uint8_t*)dhcp_pkt);

    if (dump) {
        printf("dhcp_pkt_len=%d, opt_len=%d\n",dhcp_pkt_len,dhcp_opt_len);
        printf("hexdump: dhcp option portion only\n");
        hexdump(&(dhcp_pkt->options), dhcp_opt_len);
        printf("hexdump: dhcp pkt\n");
        hexdump_pkt((uint8_t*)dhcp_pkt, dhcp_pkt_len);
    }

    if (cmp) {
        if (dhcp_pkt->op == BOOTREQUEST){
            dhcp_expected = Dhcp_discovery_expected;
            dhcp_expected_len = sizeof(Dhcp_discovery_expected);
        } else if (dhcp_pkt->op == BOOTREPLY) {
            dhcp_expected = Dhcp_offer_expected;
            dhcp_expected_len = sizeof(Dhcp_offer_expected);
            match_index = 1;
        } else {
            printf("ERROR UNSUPPORTED DHCP TYPE %d\n", dhcp_pkt->op);
        }

        if ( dhcp_expected_len !=  dhcp_pkt_len){
            printf("DCHP pkt len:%u, expected %u", dhcp_pkt_len,dhcp_expected_len);
            return;
        }

        if (dhcp_expected) {
            if (memcmp(dhcp_expected, dhcp_pkt, dhcp_expected_len))
                printf("DCHP pkt:    FAILED");
            else {
                printf("DCHP pkt:    MATCHED");
                dhcp_pkt_matched[match_index] = 1;
            }
        }
    }
}


indigo_error_t indigo_fwd_packet_out (of_packet_out_t *pkt)
{
    
    of_octets_t     data;
    ppe_packet_t    ppep;

    printf("\n********\n***DUMPING Fwd pkt out Received and Checked\n*************\n");
    //of_packet_out_OF_VERSION_1_3_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, pkt);

    of_packet_out_data_get(pkt, &data);
	ppe_packet_init(&ppep, data.data, data.bytes);
	if (ppe_parse(&ppep) < 0) {
	    printf("\nERROR: Packet parsing failed. packet=%p, len=%u", data.data, data.bytes);
	}
    //ppe_packet_dump(&ppep,&aim_pvs_stdout);

    parse_dhcp_options(&ppep, data.bytes, 1, 1);

    return INDIGO_ERROR_NONE;
}

int
test_discovery_pkt_in(int port_no, int indigo_ret_expected)
{

#define OUT_PKT_BUF_SIZE 1500
    uint8_t  buf[OUT_PKT_BUF_SIZE];

    int rv = 0;
    of_packet_in_t *obj = 0;
    ppe_packet_t    ppep;
    of_octets_t data = {
        .bytes = sizeof(Dhcp_discovery) //346 bytes (342 + 4byteVLAN
    };

    /* Timeout due to re-register the timer */
    printf("\n\n*******************************\n");
    printf("TEST 1 DHCP Discovery: PKT_IN on port:%d\nExpect Option Added\n", port_no);
    printf("pkt_in bytes = %d\n", data.bytes);
    printf("*******************************\n");

    /* Set up GOLDEN Expected pkt*/
    AIM_TRUE_OR_DIE(sizeof(Dhcp_discovery_expected) <= OUT_PKT_BUF_SIZE);
    convert_chars_to_bytes(Dhcp_discovery_expected, 
                           Dhcp_discovery_expected_hex_stream, 
                           sizeof(Dhcp_discovery_expected));
    
    /* Setup discovery pkt */
    AIM_TRUE_OR_DIE(sizeof(Dhcp_discovery) <= OUT_PKT_BUF_SIZE);
    convert_chars_to_bytes(Dhcp_discovery, Dhcp_discovery_hex_stream, sizeof(Dhcp_discovery));
    memcpy(buf, Dhcp_discovery, sizeof(Dhcp_discovery));
    data.data = buf;

    obj = of_packet_in_new(OF_VERSION_1_0);
    AIM_TRUE_OR_DIE(obj);

    of_packet_in_reason_set(obj, OF_PACKET_IN_REASON_BSN_DHCP);
    of_packet_in_in_port_set(obj,port_no);

    if(of_packet_in_data_set(obj, &data) < 0) {
        AIM_TRUE_OR_DIE(obj);
    }

    /* Dump pkt in obj */
//    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);

    ppe_packet_init(&ppep, data.data, data.bytes);
	if (ppe_parse(&ppep) < 0) {
	    printf("\nERROR: Packet parsing failed. packet=%p, len=%u", data.data, data.bytes);
	}

    /* Dump up to DHCP hdr */
//    ppe_packet_dump(&ppep,&aim_pvs_stdout);
//    parse_dhcp_options(&ppep, data.bytes, 0, 0);

    /* Handle packet */
    rv = dhcpra_handle_pkt (obj);

    AIM_TRUE_OR_DIE(rv == indigo_ret_expected);

    of_packet_in_delete(obj);
    return rv;
}

int
test_offer_pkt_in(int port_no)
{

#define OUT_PKT_BUF_SIZE 1500
    uint8_t  buf[OUT_PKT_BUF_SIZE];

    int rv = 0;
    of_packet_in_t *obj;
    ppe_packet_t    ppep;
    of_octets_t data = {
        .bytes = sizeof(Dhcp_offer) //354 (342 + 4byte VLAN + 8bytes CirID)
    };

    printf("\n\n*******************************\n"
           "TEST 2 DHCP OFFER: PKT_IN on port:%d\nExpect Option Removed\n", port_no);
    printf("pkt_in bytes = %d\n", data.bytes);
    printf("*******************************\n\n");

     /* Set up GOLDEN Expected pkt*/
    //printf("Expected Offer pkt:\n");
    AIM_TRUE_OR_DIE(sizeof(Dhcp_offer_expected) <= OUT_PKT_BUF_SIZE);
    convert_chars_to_bytes(Dhcp_offer_expected, 
                           Dhcp_offer_expected_hex_stream, 
                           sizeof(Dhcp_offer_expected));

    /* Setup offer pkt */
    //printf("Offer pkt:\n");
    AIM_TRUE_OR_DIE(sizeof(Dhcp_offer) <= OUT_PKT_BUF_SIZE);
    convert_chars_to_bytes(Dhcp_offer,  Dhcp_offer_hex_stream, sizeof(Dhcp_offer));
    memcpy(buf, Dhcp_offer, sizeof(Dhcp_offer));
    data.data = buf;

    obj = of_packet_in_new(OF_VERSION_1_0);
    AIM_TRUE_OR_DIE(obj);
    of_packet_in_in_port_set(obj,port_no);

    of_packet_in_reason_set(obj, OF_PACKET_IN_REASON_BSN_DHCP);
    if(of_packet_in_data_set(obj, &data) < 0) {
        AIM_TRUE_OR_DIE(obj);
    }

    /* Dump pkt in obj */
    //of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);
    ppe_packet_init(&ppep, data.data, data.bytes);
	if (ppe_parse(&ppep) < 0) {
	    printf("\nERROR: Packet parsing failed. packet=%p, len=%u", data.data, data.bytes);
	}

    /* Dump up to DHCP hdr */
    //ppe_packet_dump(&ppep,&aim_pvs_stdout);
    //parse_dhcp_options(&ppep, data.bytes, 0, 0);

    /* Handle packet */
    rv = dhcpra_handle_pkt (obj);

    if (rv == INDIGO_CORE_LISTENER_RESULT_PASS) {
        printf("\nError: NOT DHCP packet-in\n");
    } else if (rv == INDIGO_CORE_LISTENER_RESULT_DROP)
        printf("\nIS DHCP packet-in\n");
    else
        printf("\nError: Unsupport packet-in\n");

    of_packet_in_delete(obj);
    return rv;
}


int aim_main(int argc, char* argv[])
{
    printf("dhcpra Utest Is Empty\n");
    dhcpra_config_show(&aim_pvs_stdout);
    dhcpra_system_init();

    printf("\n*********\n0. PRE-TEST TABLE\n********\n");
    test_pass[0] = fill_all_vlan_dhcpr_table_test();

    printf("\n*********\nI. TEST PASS AFTER ADD and MOD\n********\n");
    add_entry_to_dhcpr_table();
    mod_entry_to_dhcpr_table();

    //Port 1: Correct setup, packet process
    //Driver will take care of sending L2_SRC_MISSED to controller
    test_discovery_pkt_in(1, INDIGO_CORE_LISTENER_RESULT_DROP);
    test_offer_pkt_in(1);

    printf("\n\nSUMMARY:\nDISCOV:\t%s\n", dhcp_pkt_matched[0] ? "PASSED" : "FAILED");
    printf("OFFER:\t%s\n", dhcp_pkt_matched[1] ? "PASSED" : "FAILED");
    test_pass[1] = dhcp_pkt_matched[0];
    test_pass[2] = dhcp_pkt_matched[1];

    printf("\n*********\nII. TEST FAILED AFTER DELETE\n********\n");
    dhcp_pkt_matched[0] = 0;
    dhcp_pkt_matched[1] = 0;
    del_entry_to_dhcpr_table();

    //Incorrect VLAN drop packet
    test_discovery_pkt_in(1, INDIGO_CORE_LISTENER_RESULT_DROP);
    test_offer_pkt_in(1);
    printf("\n\nSUMMARY:\nDISCOV:\t%s\n", dhcp_pkt_matched[0] ? "PASSED" : "FAILED");
    printf("OFFER:\t%s\n", dhcp_pkt_matched[1] ? "PASSED" : "FAILED");
    test_pass[3] = !dhcp_pkt_matched[0];
    test_pass[4] = !dhcp_pkt_matched[1];

    printf("\n\n*****SUMMARY ALL 3 TESTS*****\n");
    printf("TEST DHCP TABLE: %s\n", test_pass[0] ? "PASSED" : "FAILED");
    printf("TEST DISCOVER with valid table: %s\n", test_pass[1] ? "PASSED" : "FAILED");
    printf("TEST OFFER with valid table: %s\n",    test_pass[2] ? "PASSED" : "FAILED");
    printf("TEST DISCOVER with in valid table: %s\n", test_pass[3] ? "PASSED" : "FAILED");
    printf("TEST OFFER with in valid table: %s\n",    test_pass[4] ? "PASSED" : "FAILED");

    return 0;
}

