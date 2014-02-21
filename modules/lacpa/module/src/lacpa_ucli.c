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
#include <lacpa/lacpa_config.h>
#include "lacpa_int.h"
#include "lacpa_utils.h"

#if LACPA_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static void
lacpa_clear_port_counters__(ucli_context_t* uc, uint32_t port_no)
{
    lacpa_port_t  *port = NULL;

    /*
     * Find any port corresponding to the info received
     */
    port = lacpa_find_port(port_no);
    if (!port) return;

    if (!port->lacp_enabled) return;

    port->debug_info.lacp_port_in_packets = 0; 
    port->debug_info.lacp_port_out_packets = 0;    
    port->debug_info.lacp_convergence_notif = 0;
}

static ucli_status_t
lacpa_ucli_ucli__clear_lacp_counters__(ucli_context_t* uc)
{
    uint32_t port = 0;

    UCLI_COMMAND_INFO(uc,
                      "clear", -1,
                      "$summary#Clear the lacp system packet counters."
                      "$args#[Port]");

    if (!lacpa_is_initialized()) return UCLI_STATUS_E_ERROR;

    if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "i", &port);
        lacpa_clear_port_counters__(uc, port);
    } else {
        lacpa_clear_system_counters();
     
        for (port = 0; port <= PHY_PORT_COUNT; port++) {
            lacpa_clear_port_counters__(uc, port);
        }
    }

    return UCLI_STATUS_OK; 
}

static ucli_status_t
lacpa_ucli_ucli__show_lacp_counters__(ucli_context_t* uc)
{
    UCLI_COMMAND_INFO(uc,
                      "counters", 0,
                      "$summary#Display the lacp system packet counters.");

    if (!lacpa_is_initialized()) return UCLI_STATUS_E_ERROR;

    ucli_printf(uc, "*************DUMPING SYSTEM COUNTERS*************\n");
    ucli_printf(uc, "TOTAL PACKETS RECV'D    : %" PRId64 "\n", 
                lacpa_system.debug_info.lacp_total_in_packets); 
    ucli_printf(uc, "LACPDU's RECV'D         : %" PRId64 "\n",
                lacpa_system.debug_info.lacp_system_in_packets);
    ucli_printf(uc, "LACPDU's SENT           : %" PRId64 "\n",
                lacpa_system.debug_info.lacp_system_out_packets);
    ucli_printf(uc, "SET REQUESTS RECV'D     : %" PRId64 "\n",
                lacpa_system.debug_info.lacp_controller_set_requests);
    ucli_printf(uc, "STATS REQUESTS RECV'D   : %" PRId64 "\n",
                lacpa_system.debug_info.lacp_controller_stats_requests);             
    ucli_printf(uc, "*************END DUMPING INFO********************\n");
 
    return UCLI_STATUS_OK;
}

static void
lacpa_show_portstate__(ucli_context_t* uc, uint32_t port_no)
{
    lacpa_port_t  *port = NULL;

    /*
     * Find any port corresponding to the info received
     */
    port = lacpa_find_port(port_no);
    if (!port) return;

    if (!port->lacp_enabled) return;

    ucli_printf(uc, "*************DUMPING STATE INFO*************\n");
    ucli_printf(uc, "\nACTOR STATE FLAGS\n");
    ucli_printf(uc, "ACTOR PORT NO           : %d\n", port->actor.port_no);
    ucli_printf(uc, "ACTOR LACP ACTIVITY     : %s\n",
                LACPA_IS_STATE_LACP_ACTIVITY(port->actor.state)?
                "ACTIVE" : "PASSIVE");
    ucli_printf(uc, "ACTOR LACP TIMEOUT      : %s\n",
                LACPA_IS_STATE_LACP_TIMEOUT(port->actor.state)?
                "SHORT" : "LONG");
    ucli_printf(uc, "ACTOR AGGREGATION       : %s\n",
                LACPA_IS_STATE_AGGREGATION(port->actor.state)? "YES" : "NO");
    ucli_printf(uc, "ACTOR SYNCHRONIZATION   : %s\n",
                LACPA_IS_STATE_SYNCHRONIZATION(port->actor.state)?
                "INSYNC" : "OUTofSYNC");
    ucli_printf(uc, "ACTOR COLLECTING        : %s\n",
                LACPA_IS_STATE_COLLECTING(port->actor.state)?
                "YES" : "NO");
    ucli_printf(uc, "ACTOR DISTRIBUTING      : %s\n",
                LACPA_IS_STATE_DISTRIBUTING(port->actor.state)?
                "YES" : "NO");
    ucli_printf(uc, "\nPARTNER STATE FLAGS\n");
    ucli_printf(uc, "PARTNER PORT NO         : %d\n", port->partner.port_num);
    ucli_printf(uc, "PARTNER LACP ACTIVITY   : %s\n",
                LACPA_IS_STATE_LACP_ACTIVITY(port->partner.state)?
                "ACTIVE" : "PASSIVE");
    ucli_printf(uc, "PARTNER LACP TIMEOUT    : %s\n",
                LACPA_IS_STATE_LACP_TIMEOUT(port->partner.state)?
                "SHORT" : "LONG");
    ucli_printf(uc, "PARTNER AGGREGATION     : %s\n",
                LACPA_IS_STATE_AGGREGATION(port->partner.state)? "YES" : "NO");
    ucli_printf(uc, "PARTNER SYNCHRONIZATION : %s\n",
                LACPA_IS_STATE_SYNCHRONIZATION(port->partner.state)?
                "INSYNC" : "OUTofSYNC");
    ucli_printf(uc, "PARTNER COLLECTING      : %s\n",
                LACPA_IS_STATE_COLLECTING(port->partner.state)? "YES" : "NO");
    ucli_printf(uc, "PARTNER DISTRIBUTING    : %s\n",
                LACPA_IS_STATE_DISTRIBUTING(port->partner.state)? "YES" : "NO");
    ucli_printf(uc, "\n*************END DUMPING INFO**************\n");
}

static ucli_status_t
lacpa_ucli_ucli__show_lacp_portstate__(ucli_context_t* uc)
{
    uint32_t port = 0;

    UCLI_COMMAND_INFO(uc,
                      "flags", -1,
                      "$summary#Display the port lacp state flags."
                      "$args#[Port]");

    if (!lacpa_is_initialized()) return UCLI_STATUS_E_ERROR;

    if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "i", &port);
        lacpa_show_portstate__(uc, port);
    } else {

        for (port = 0; port <= PHY_PORT_COUNT; port++) {
            lacpa_show_portstate__(uc, port);
        }
    }

    return UCLI_STATUS_OK;
}

static void
lacpa_show_portstats__(ucli_context_t* uc, uint32_t port_no)
{
    lacpa_port_t  *port = NULL; 

    /*
     * Find any port corresponding to the info received
     */
    port = lacpa_find_port(port_no);
    if (!port) return;

    if (!port->lacp_enabled) return;

    ucli_printf(uc, "*************DUMPING PORT INFO*************\n");
    ucli_printf(uc, "\nACTOR PORT INFO\n");
    ucli_printf(uc, "ACTOR OF_PORT_NO      : %d\n", port->actor.port_no);
    ucli_printf(uc, "ACTOR SYS PRIORITY    : %d\n", port->actor.sys_priority);
    ucli_printf(uc, "ACTOR SYS MAC         : %{mac}\n", 
                port->actor.sys_mac.addr);
    ucli_printf(uc, "ACTOR PORT PRIORITY   : %d\n", port->actor.port_priority);
    ucli_printf(uc, "ACTOR PORT NUM        : %d\n", port->actor.port_num);
    ucli_printf(uc, "ACTOR KEY             : %d\n", port->actor.key);
    ucli_printf(uc, "ACTOR STATE           : 0x%02x\n", port->actor.state);
    ucli_printf(uc, "\nPARTNER PORT INFO\n");
    ucli_printf(uc, "PARTNER SYS PRIORITY  : %d\n", port->partner.sys_priority);
    ucli_printf(uc, "PARTNER SYS MAC       : %{mac}\n",
                port->partner.sys_mac.addr);
    ucli_printf(uc, "PARTNER PORT PRIORITY : %d\n",
                port->partner.port_priority);
    ucli_printf(uc, "PARTNER PORT NUM      : %d\n", port->partner.port_num);
    ucli_printf(uc, "PARTNER KEY           : %d\n", port->partner.key);
    ucli_printf(uc, "PARTNER STATE         : 0x%02x\n", port->partner.state);
    ucli_printf(uc, "\nPROTOCOL STATE INFO\n");
    ucli_printf(uc, "LACP ENABLED          : %s\n",
                port->lacp_enabled? "YES":"NO");
    ucli_printf(uc, "PROTOCOL CONVERGED    : %s\n",
                port->is_converged? "YES":"NO");
    ucli_printf(uc, "LACP STATE            : %{lacpa_machine}\n",
                port->lacp_state);
    ucli_printf(uc, "LACP EVENT            : %{lacpa_event}\n",
                port->debug_info.lacp_event);
    ucli_printf(uc, "LACP ERROR            : %{lacpa_error}\n", port->error);
    ucli_printf(uc, "LACP TANSMIT REASON   : %{lacpa_transmit}\n",
                port->debug_info.ntt_reason);
    ucli_printf(uc, "\nPACKET INFO\n"); 
    ucli_printf(uc, "LACP PACKET IN        : %" PRId64 "\n",
                port->debug_info.lacp_port_in_packets);
    ucli_printf(uc, "LACP PACKET OUT       : %" PRId64 "\n",
                port->debug_info.lacp_port_out_packets);
    ucli_printf(uc, "CONVERGENCE NOTIF     : %" PRId64 "\n",
                port->debug_info.lacp_convergence_notif);
    ucli_printf(uc, "\n*************END DUMPING INFO**************\n");     
}

static ucli_status_t
lacpa_ucli_ucli__show_lacp_portstats__(ucli_context_t* uc)
{
    uint32_t port = 0;
    
    UCLI_COMMAND_INFO(uc,
                      "stats", -1,
                      "$summary#Display the port lacp stats."
                      "$args#[Port]");

    if (!lacpa_is_initialized()) return UCLI_STATUS_E_ERROR;

    if (uc->pargs->count == 1) {
        UCLI_ARGPARSE_OR_RETURN(uc, "i", &port);
        lacpa_show_portstats__(uc, port);
    } else {
         
        for (port = 0; port <= PHY_PORT_COUNT; port++) {
            lacpa_show_portstats__(uc, port);
        }
    }

    return UCLI_STATUS_OK;
}

static ucli_status_t
lacpa_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(lacpa)
}

/* <auto.ucli.handlers.start> */
/******************************************************************************
 *
 * These handler table(s) were autogenerated from the symbols in this
 * source file.
 *
 *****************************************************************************/
static ucli_command_handler_f lacpa_ucli_ucli_handlers__[] = 
{
    lacpa_ucli_ucli__clear_lacp_counters__,
    lacpa_ucli_ucli__show_lacp_counters__,
    lacpa_ucli_ucli__show_lacp_portstate__,
    lacpa_ucli_ucli__show_lacp_portstats__,
    lacpa_ucli_ucli__config__,
    NULL
};
/******************************************************************************/
/* <auto.ucli.handlers.end> */

static ucli_module_t
lacpa_ucli_module__ =
    {
        "lacpa_ucli",
        NULL,
        lacpa_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
lacpa_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&lacpa_ucli_module__);
    n = ucli_node_create("lacpa", NULL, &lacpa_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("lacpa"));
    return n;
}

#else
void*
lacpa_ucli_node_create(void)
{
    return NULL;
}
#endif

