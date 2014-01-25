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
    AIM_TRUE_OR_DIE(arpa_init() == INDIGO_ERROR_NONE);
    arpa_finish();
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

indigo_error_t
indigo_core_packet_in_listener_register(indigo_core_packet_in_listener_f fn)
{
    return INDIGO_ERROR_NONE;
}

void
indigo_core_packet_in_listener_unregister(indigo_core_packet_in_listener_f fn)
{
}

indigo_error_t
indigo_fwd_packet_out(of_packet_out_t *obj)
{
	return INDIGO_ERROR_NONE;
}
