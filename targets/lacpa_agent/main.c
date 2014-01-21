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
 * This file contains routines for setting up a bond with the linux kernel.
 * The step-by-step procedure for setting up the bond is documented below.
 *
 * Bonding with linux kernel helps to test the lacp agent against the 
 * standard linux lacp agent.
 */

/*
 * Procedure for setting up linux kernel bonding:
 * Pre-requisites: libpcap-dev
 * Debugging tolls: dmesg, tcpdump
 * 1. Enable bonding: sudo modprobe bonding
 * 2. Setup tap interfaces for the bond. Running lacp_agent module binary 
 *    will do that. ./build/gcc-local/bin/lacp-agent
 * 3. Add the below config's
 *    echo 802.3ad | sudo tee /sys/class/net/bond0/bonding/mode
 *    echo +tap0 | sudo tee /sys/class/net/bond0/bonding/slaves 
 *    echo +tap1 | sudo tee /sys/class/net/bond0/bonding/slaves
 * 4. Verify bond0, tap0, tap1 interfaces are UP (ifconfig -a <intf>)
 *    If Down bring the interfaces up: sudo ifconfig <intf> up
 * 5. Run the ./build/gcc-local/bin/lacp-agent again 
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
#include <lacpa/lacpa_config.h>
#include <lacpa/lacpa.h>
#include <lacpa_int.h>

uint8_t mac[6] = {0x00, 0x13, 0xc4, 0x12, 0x0f, 0x00};
uint8_t mac2[6] = {0x00, 0x1c, 0x04, 0x1d, 0x0e, 0x00};

vpi_t vpi1, vpi2;
lacpa_info_t info1, info2;
lacpa_port_t *port1, *port2;

indigo_error_t
lacp_create_send_packet_in (of_port_no_t in_port, of_octets_t *of_octets)
{
    of_match_t     match;
    of_packet_in_t *of_packet_in;

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

    if (lacpa_packet_in_handler(of_packet_in) == 
        INDIGO_CORE_LISTENER_RESULT_DROP) {
        printf("Listener dropped packet-in\n");
    } else {
        printf("Listener passed packet-in\n");
    }

    of_packet_in_delete(of_packet_in);
    return INDIGO_ERROR_NONE;
}

/*
 * Stub function's to avoid compilation failure lacp_agent module
 */
void
indigo_cxn_send_controller_message (indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    printf("lacpa module: Send a REPLY to the controller\n");
}

void
indigo_cxn_send_async_message (of_object_t *obj)
{
    printf("lacpa module: Send an ASYNC msg to the controller\n");
}

indigo_error_t
indigo_cxn_get_async_version (of_version_t *version)
{
    *version = OF_VERSION_1_3;
    return INDIGO_ERROR_NONE;
}

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    of_port_no_t     port_no;
    of_octets_t      of_octets;
    of_list_action_t action;
    of_action_t      act;
    int              rv;

    if (!of_packet_out) return INDIGO_ERROR_NONE;
    
    printf("lacpa module: Send a packet out the port\n");

    of_packet_out_actions_bind(of_packet_out, &action);
    OF_LIST_ACTION_ITER(&action, &act, rv) {
        of_action_output_port_get(&act.output, &port_no);
    }

    of_packet_out_data_get(of_packet_out, &of_octets);

    printf("lacpa module: Send a packet out the port: %d\n", port_no);
    if (port_no == 10) {
        vpi_send(vpi1, of_octets.data, of_octets.bytes);
    } else if (port_no == 20) {
        vpi_send(vpi2, of_octets.data, of_octets.bytes);
    }

    return INDIGO_ERROR_NONE;
}

void lacp_init(void)
{
    memset(&info1, 0, sizeof(lacpa_info_t));
    memset(&info2, 0, sizeof(lacpa_info_t));

    if (!lacpa_is_initialized()) {
        lacpa_init();
    }

    port1 = lacpa_find_port(10);
    port2 = lacpa_find_port(20);
    if (!port1 || !port2) {
        printf("FATAL ERROR - PORT ALLOCATION FAILED");
        return;
    }

    info1.sys_priority = 32768;
    memcpy(&info1.sys_mac, mac, 6);
    info1.port_priority = 32768;
    info1.port_num = 25;
    info1.key = 13;
    info1.port_no = 10;

    info2.sys_priority = 32768;
    memcpy(&info2.sys_mac, mac2, 6);
    info2.port_priority = 32768;
    info2.port_num = 0x16;
    info2.key = 0xe;
    info2.port_no = 20;
    
    lacpa_init_port(&info1, true);
    lacpa_init_port(&info2, true);

}

int main(int argc, char* argv[])
{
    uint8_t     buf[256];
    struct      pollfd fds[2];
    of_octets_t of_octets;

    vpi_init();
    lacp_init();
 
    vpi1 = vpi_create("tap|tap0");  
    vpi2 = vpi_create("tap|tap1");  

    if (!vpi1) {
        assert(vpi1);
        return 0;
    }

    if (!vpi2) {
        assert(vpi2);
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
            of_octets.bytes = vpi_recv(vpi1, buf, 256, 0);
            printf("received_pkt on tap0 with %d bytes\n", of_octets.bytes);
            lacp_create_send_packet_in(10, &of_octets);
        }

        if (fds[1].revents & POLLIN) {
            of_octets.bytes = vpi_recv(vpi2, buf, 256, 0);
            printf("received_pkt on tap1 with %d bytes\n", of_octets.bytes);
            lacp_create_send_packet_in(20, &of_octets);    
        }
    }
    
    vpi_unref(vpi1);
    vpi_unref(vpi2);
    vpi_close();
 
    return 0;
}

