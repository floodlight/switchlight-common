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

#include <cdpa/cdpa_config.h>
#include "cdpa_int.h"

#if CDPA_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
cdpa_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(cdpa)
}

static ucli_status_t
cdpa_ucli_ucli__show_cdpa_counters__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc,
                      "counters", 0,
                      "$summary#Display the cdpa system packet counters.");

    ucli_printf(uc, "*************DUMPING SYSTEM COUNTERS*************\n");
    ucli_printf(uc, "TOTAL PACKETS RECV'D   : %" PRId64 "\n", debug_counter_get(
                &cdpa_system.debug_info.cdp_total_in_packets));
    ucli_printf(uc, "TOTAL PACKETS SENT     : %" PRId64 "\n", debug_counter_get(
                &cdpa_system.debug_info.cdp_total_out_packets));
    ucli_printf(uc, "RX REQUESTS RECV'D     : %" PRId64 "\n", debug_counter_get(
                &cdpa_system.debug_info.cdp_total_rx_msgs));
    ucli_printf(uc, "TX REQUESTS RECV'D     : %" PRId64 "\n", debug_counter_get(
                &cdpa_system.debug_info.cdp_total_tx_msgs));
    ucli_printf(uc, "*************END DUMPING INFO********************\n");

    return UCLI_STATUS_OK;
}

static ucli_status_t
cdpa_ucli_ucli__clear_cdpa_counters__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc,
                      "clear", 0,
                      "$summary#Clear the cdpa system packet counters.");

    debug_counter_reset(&cdpa_system.debug_info.cdp_total_in_packets);
    debug_counter_reset(&cdpa_system.debug_info.cdp_total_out_packets);
    debug_counter_reset(&cdpa_system.debug_info.cdp_total_rx_msgs);
    debug_counter_reset(&cdpa_system.debug_info.cdp_total_tx_msgs);

    return UCLI_STATUS_OK;
}

static void
cdpa_show_portcounters__(ucli_context_t* uc, uint32_t port_no)
{
    cdpa_port_t  *port = NULL;

    /*
     * Find any port corresponding to the info received
     */
    port = cdpa_find_port(port_no);
    if (!port) return;

    ucli_printf(uc, "%d\t%d\t%d\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\t%"PRId64"\n" ,
                port->port_no, port->rx_pkt.interval_ms, port->tx_pkt.interval_ms,
                port->rx_pkt_in_cnt, port->tx_pkt_out_cnt, port->timeout_pkt_cnt,
                port->rx_pkt_mismatched_no_data, port->rx_pkt_mismatched_len,
                port->rx_pkt_mismatched_data, port->rx_pkt_matched,
                port->tx_req_cnt, port->rx_req_cnt);

}

static ucli_status_t
cdpa_ucli_ucli__show_cdpa_portcounters__(ucli_context_t* uc)
{
    uint32_t port = 0;

    UCLI_COMMAND_INFO(uc,
                      "port_counters", -1,
                      "$summary#Display the cdpa counters per port."
                      "$args#[Port]");

    ucli_printf(uc,
                "PORT    OF port number\n"
                "r_intv  Rx time interval\n"
                "t_intv  Tx time interval\n"
                "pkt_in  Num of packet_ins fr the data plane\n"
                "pk_out  Num of packet_outs to the data plane\n"
                "TOmsg   Num of timeout_msgs to the control plane\n"
                "MM_ND   Mismatched due to no data\n"
                "MM_len  Mismatched due to len\n"
                "MM_data Mismatched due to data\n"
                "Matchd  Data matched\n"
                "txReq   Num of tx req fr the control plane\n"
                "rxReq   Num of rx req fr the control plane\n");

    ucli_printf(uc, "PORT\tr_intv\tt_intv\tpkt_in\tpk_out\tTOmsg\tMM_ND\tMM_len\tMM_data\tMATCHD\ttxReq\trxReq\n");
    if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "i", &port);
        cdpa_show_portcounters__(uc, port);
    } else {
        for (port = 0; port <= CDPA_CONFIG_OF_PORTS_MAX; port++) {
            cdpa_show_portcounters__(uc, port);
        }
    }
    return UCLI_STATUS_OK;
}

static void
cdpa_clear_portcounters__(ucli_context_t* uc, uint32_t port_no)
{
    cdpa_port_t  *port = NULL;

    /*
     * Find any port corresponding to the info received
     */
    port = cdpa_find_port(port_no);
    if (!port) return;

    port->rx_pkt_in_cnt   = 0;
    port->tx_pkt_out_cnt  = 0;
    port->timeout_pkt_cnt = 0;
    port->rx_pkt_mismatched_no_data = 0;
    port->rx_pkt_mismatched_len = 0;
    port->rx_pkt_mismatched_data = 0;
    port->rx_pkt_matched = 0;
    port->tx_req_cnt = 0;
    port->rx_req_cnt = 0;
}

static ucli_status_t
cdpa_ucli_ucli__clear_cdpa_portcounters__(ucli_context_t* uc)
{
    uint32_t port = 0;

    UCLI_COMMAND_INFO(uc,
                      "clear_port_counters", -1,
                      "$summary#Clear the cdpa counters per port."
                      "$args#[Port]");

    if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "i", &port);
        cdpa_clear_portcounters__(uc, port);
    } else {
        for (port = 0; port <= CDPA_CONFIG_OF_PORTS_MAX; port++) {
            cdpa_clear_portcounters__(uc, port);
        }
    }
    return UCLI_STATUS_OK;
}

/* <auto.ucli.handlers.start> */
/******************************************************************************
 *
 * These handler table(s) were autogenerated from the symbols in this
 * source file.
 *
 *****************************************************************************/
static ucli_command_handler_f cdpa_ucli_ucli_handlers__[] =
{
    cdpa_ucli_ucli__config__,
    cdpa_ucli_ucli__show_cdpa_counters__,
    cdpa_ucli_ucli__clear_cdpa_counters__,
    cdpa_ucli_ucli__show_cdpa_portcounters__,
    cdpa_ucli_ucli__clear_cdpa_portcounters__,
    NULL
};
/******************************************************************************/
/* <auto.ucli.handlers.end> */

static ucli_module_t
cdpa_ucli_module__ =
    {
        "cdpa_ucli",
        NULL,
        cdpa_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
cdpa_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&cdpa_ucli_module__);
    n = ucli_node_create("cdpa", NULL, &cdpa_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("cdpa"));
    return n;
}

#else
void*
cdpa_ucli_node_create(void)
{
    return NULL;
}
#endif

