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

#include <lldpa/lldpa_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <unistd.h>
#include <assert.h>
#include <ctype.h>

#include <AIM/aim.h>
#include <lldpa/lldpa.h>
#include <OFStateManager/ofstatemanager.h>
#include <SocketManager/socketmanager.h>

#include <loci/loci_obj_dump.h>
#include <PPE/ppe_types.h>

extern ind_core_listener_result_t lldpa_handle_msg (indigo_cxn_id_t cxn_id, of_object_t *msg);
extern ind_core_listener_result_t lldpa_handle_pkt (of_packet_in_t *packet_in);

/* Dummy packet */
uint8_t Lldppdu_Tx[] = {10,11,12,13,250,251,252,253};
/* LLDP type packet */
uint8_t Lldppdu_Rx[] = {1,2,3,4,5,6,1,2,3,4,5,6,0x88,0xcc,0xd,0xe,0xa,0xf,0xb,0xe,0xe,0xf};


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

void indigo_cxn_send_controller_message (indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    printf("\nSend REPLY msg to controller\n");
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);

    //Consume obj
    of_object_delete(obj);
}

void indigo_cxn_send_async_message     (of_object_t *obj)
{
    printf("\nSend TIMEOUT Msg to controller\n");
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);

    //Consume obj
    of_object_delete(obj);
}

indigo_error_t indigo_fwd_packet_out (of_packet_out_t *pkt)
{
    of_octets_t data;
    printf("\nFwd TX pkt out\n");
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, pkt);

    of_packet_out_data_get(pkt, &data);
    hexdump(data.data, data.bytes);

    //Don't consume obj
    return INDIGO_ERROR_NONE;
}

indigo_error_t indigo_cxn_get_async_version(of_version_t *ver)
{
    *ver = OF_VERSION_1_3;
    return INDIGO_ERROR_NONE;
}

/*NOTE:
 * This is used to test timeout.
 * When we register we do call back
 */
indigo_error_t ind_timer_event_register (ind_soc_timer_callback_f callback, void *cookie, int repeat_time_ms)
{
    callback(cookie);
    return INDIGO_ERROR_NONE;
}

indigo_error_t  ind_timer_event_unregister (ind_soc_timer_callback_f callback, void *cookie)
{
    return INDIGO_ERROR_NONE;
}

int
test_tx_request(int port_no)
{
    int rv = 0;
    uint32_t interval = 5;
    of_bsn_pdu_tx_request_t *obj;
    of_octets_t data;


    printf("\n\nTEST 1: TX_REQUEST on port:%d\nExpect: 1 TX_REQ, 2 FWD, 1 REPLY\n", port_no);

    data.data = (uint8_t*)Lldppdu_Tx;
    data.bytes = sizeof(Lldppdu_Tx);

    printf("TX_REQUEST bytes = %d\n", data.bytes);
    hexdump(data.data, data.bytes);

    obj = of_bsn_pdu_tx_request_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(obj);
    of_bsn_pdu_tx_request_port_no_set(obj,port_no);
    of_bsn_pdu_tx_request_tx_interval_ms_set(obj,interval);

    if(of_bsn_pdu_tx_request_data_set(obj, &data) < 0) {
        AIM_TRUE_OR_DIE(obj);
    }

    /*Dump tx_req obj */
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);
    lldpa_handle_msg (0, obj);

    of_bsn_pdu_tx_request_delete(obj);

    return rv;
}

int
test_rx_request(int port_no)
{
    int rv = 0;
    uint32_t interval = 5;
    of_bsn_pdu_rx_request_t *obj;
    of_octets_t data;

    printf("\n\nTEST 2: RX_REQUEST on port:%d\nExpect: 1 RX_REQ, 1 TIMEOUT, 1 REPLY\n", port_no);

    data.data = Lldppdu_Rx;
    data.bytes = sizeof(Lldppdu_Rx);

    printf("Rx_request bytes = %d\n", data.bytes);
    hexdump(data.data, data.bytes);

    obj = of_bsn_pdu_rx_request_new(OF_VERSION_1_3);
    AIM_TRUE_OR_DIE(obj);
    of_bsn_pdu_rx_request_port_no_set(obj,port_no);
    of_bsn_pdu_rx_request_timeout_ms_set(obj,interval);

    if(of_bsn_pdu_rx_request_data_set(obj, &data) < 0) {
        AIM_TRUE_OR_DIE(obj);
    }

    /*Dump rx_req obj */
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);
    lldpa_handle_msg (0, obj);

    of_bsn_pdu_tx_request_delete(obj);
    return rv;
}


int
test_pkt_in(int port_no)
{
    int rv = 0;
    of_packet_in_t *obj;
    of_octets_t data = {
            .data = Lldppdu_Rx,
            .bytes = sizeof(Lldppdu_Rx)
    };

    /* Timeout due to re-register the timer */
    printf("\n\nTEST 3: PKT_IN on port:%d\nExpect: 1 PKT_IN, 1 TIMEOUT, and MATCHED\n", port_no);
    printf("pkt_in bytes = %d\n", data.bytes);
    hexdump(data.data, data.bytes);

    obj = of_packet_in_new(OF_VERSION_1_0);
    AIM_TRUE_OR_DIE(obj);
    of_packet_in_in_port_set(obj,port_no);

    if(of_packet_in_data_set(obj, &data) < 0) {
        AIM_TRUE_OR_DIE(obj);
    }

    /*Dump rx_req obj */
    of_object_dump((loci_writer_f)aim_printf, &aim_pvs_stdout, obj);
    rv = lldpa_handle_pkt (obj);

    if (rv == IND_CORE_LISTENER_RESULT_PASS) {
        printf("\nError: NOT LLDP packet-in\n");
    } else if (rv == IND_CORE_LISTENER_RESULT_DROP)
        printf("\nIS LLDP packet-in\n");
    else
        printf("\nError: Unsupport packet-in\n");

    of_packet_in_delete(obj);
    return rv;
}

int aim_main(int argc, char* argv[])
{
    int port_test_no = 1;

    printf("lldpa Utest Start ..\n");
    lldpa_config_show(&aim_pvs_stdout);

    lldpa_system_init();

    test_tx_request(port_test_no);
    test_rx_request(port_test_no);
    test_pkt_in(port_test_no);

    lldpa_system_finish();

    return 0;
}

