/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <router_ip_table/router_ip_table_config.h>

#if ROUTER_IP_TABLE_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
router_ip_table_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(router_ip_table)
}

/* <auto.ucli.handlers.start> */
/* <auto.ucli.handlers.end> */

static ucli_module_t
router_ip_table_ucli_module__ =
    {
        "router_ip_table_ucli",
        NULL,
        router_ip_table_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
router_ip_table_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&router_ip_table_ucli_module__);
    n = ucli_node_create("router_ip_table", NULL, &router_ip_table_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("router_ip_table"));
    return n;
}

#else
void*
router_ip_table_ucli_node_create(void)
{
    return NULL;
}
#endif

