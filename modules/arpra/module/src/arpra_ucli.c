/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <arpra/arpra_config.h>

#if ARPRA_CONFIG_INCLUDE_UCLI == 1

#include <uCli/ucli.h>
#include <uCli/ucli_argparse.h>
#include <uCli/ucli_handler_macros.h>

static ucli_status_t
arpra_ucli_ucli__config__(ucli_context_t* uc)
{
    UCLI_HANDLER_MACRO_MODULE_CONFIG(arpra)
}

/* <auto.ucli.handlers.start> */
/******************************************************************************
 *
 * These handler table(s) were autogenerated from the symbols in this
 * source file.
 *
 *****************************************************************************/
static ucli_command_handler_f arpra_ucli_ucli_handlers__[] = 
{
    arpra_ucli_ucli__config__,
    NULL
};
/******************************************************************************/
/* <auto.ucli.handlers.end> */

static ucli_module_t
arpra_ucli_module__ =
    {
        "arpra_ucli",
        NULL,
        arpra_ucli_ucli_handlers__,
        NULL,
        NULL,
    };

ucli_node_t*
arpra_ucli_node_create(void)
{
    ucli_node_t* n;
    ucli_module_init(&arpra_ucli_module__);
    n = ucli_node_create("arpra", NULL, &arpra_ucli_module__);
    ucli_node_subnode_add(n, ucli_module_log_node_create("arpra"));
    return n;
}

#else
void*
arpra_ucli_node_create(void)
{
    return NULL;
}
#endif

