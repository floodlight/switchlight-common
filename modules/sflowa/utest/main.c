/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <sflowa/sflowa_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

int aim_main(int argc, char* argv[])
{
    printf("sflowa Utest Is Empty\n");
    sflowa_config_show(&aim_pvs_stdout);
    return 0;
}

