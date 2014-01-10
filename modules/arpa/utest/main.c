/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <arpa/arpa_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

#include <arpa/arpa.h>
#include <indigo/of_state_manager.h>

int aim_main(int argc, char* argv[])
{
    printf("arpa Utest Is Empty\n");
    arpa_config_show(&aim_pvs_stdout);
    return 0;
}

void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *ops,
    void *table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    *gentable = NULL;
}

void
indigo_core_gentable_unregister(indigo_core_gentable_t *gentable)
{
}
