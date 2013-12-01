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

uint8_t src_mac[6] = {0x00, 0x0e, 0x83, 0x16, 0xf5, 0x00};
uint8_t mac[6] = {0x00, 0x13, 0xc4, 0x12, 0x0f, 0x00};
uint8_t mac2[6] = {0x00, 0x1c, 0x04, 0x1d, 0x0e, 0x00};

vpi_t vpi1, vpi2;
lacpa_info_t info1, info2;
lacpa_port_t *port1, *port2;

/*
 * Stub function's to avoid compilation failure in lacpa/utest module
 */
extern void
indigo_cxn_send_controller_message (indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    printf("lacpa module: Send a REPLY to the controller\n");
}

extern void
indigo_cxn_send_async_message (of_object_t *obj)
{
    printf("lacpa module: Send an ASYNC msg to the controller\n");
}

extern indigo_error_t
indigo_cxn_get_async_version (of_version_t *version)
{
    *version = OF_VERSION_1_3;
    return INDIGO_ERROR_NONE;
}

extern indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *of_packet_out)
{
    printf("lacpa module: Send a packet out the port\n");
    return INDIGO_ERROR_NONE;
}

extern void
lacpa_send_utest (lacpa_port_t *port, uint8_t *data, uint32_t bytes)
{
    if (!port) return;

    if (port->actor.port_no == 10) {
        vpi_send(vpi1, data, bytes);
    } else if (port->actor.port_no == 20) {
        vpi_send(vpi2, data, bytes);
    }
}

void lacp_init(void)
{
    memset(&info1, 0, sizeof(lacpa_info_t));
    memset(&info2, 0, sizeof(lacpa_info_t));

    if (!lacpa_is_system_initialized()) {
        lacpa_init_system(&lacp_system);
    }

    port1 = lacpa_find_port(&lacp_system, 10);
    port2 = lacpa_find_port(&lacp_system, 20);
    if (!port1 || !port2) {
        printf("FATAL ERROR - PORT ALLOCATION FAILED");
        return;
    }
    memcpy(&port1->src_mac, src_mac, 6);
    memcpy(&port2->src_mac, src_mac, 6);

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
    
    lacpa_init_port(&lacp_system, &info1, TRUE);
    lacpa_init_port(&lacp_system, &info2, TRUE);

}

int main(int argc, char* argv[])
{
    uint8_t buf[256];
    struct pollfd fds[2];
    uint32_t bytes = 0;

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

    while (poll(fds, 2, -1) >= 0) {
        if (fds[0].revents & POLLIN) {
            bytes = vpi_recv(vpi1, buf, 256, 0);
            printf("received_pkt on tap0 with %d bytes\n", bytes);
            lacpa_receive_utest(port1, buf, bytes);
        }

        if (fds[1].revents & POLLIN) {
            bytes = vpi_recv(vpi2, buf, 256, 0);
            printf("received_pkt on tap1 with %d bytes\n", bytes);
            lacpa_receive_utest(port2, buf, bytes);
        }
    }
    
    vpi_unref(vpi1);
    vpi_unref(vpi2);
    vpi_close();
 
    return 0;
}

