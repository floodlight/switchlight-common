/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <router_ip_table/router_ip_table_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

int aim_main(int argc, char* argv[])
{
    printf("router_ip_table Utest Is Empty\n");
    router_ip_table_config_show(&aim_pvs_stdout);
    return 0;
}

