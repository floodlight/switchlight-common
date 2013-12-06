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
#include <lldpa/lldpa.h>

/* <auto.start.enum(ALL).source> */
aim_map_si_t lldpa_contr_stype_map[] =
{
    { "TX_REQ", LLDPA_CONTR_STYPE_TX_REQ },
    { "TX_RES", LLDPA_CONTR_STYPE_TX_RES },
    { "RX_REQ", LLDPA_CONTR_STYPE_RX_REQ },
    { "RX_RES", LLDPA_CONTR_STYPE_RX_RES },
    { "TIMEOUT", LLDPA_CONTR_STYPE_TIMEOUT },
    { "DUMMY", LLDPA_CONTR_STYPE_DUMMY },
    { NULL, 0 }
};

aim_map_si_t lldpa_contr_stype_desc_map[] =
{
    { "None", LLDPA_CONTR_STYPE_TX_REQ },
    { "None", LLDPA_CONTR_STYPE_TX_RES },
    { "None", LLDPA_CONTR_STYPE_RX_REQ },
    { "None", LLDPA_CONTR_STYPE_RX_RES },
    { "None", LLDPA_CONTR_STYPE_TIMEOUT },
    { "None", LLDPA_CONTR_STYPE_DUMMY },
    { NULL, 0 }
};

const char*
lldpa_contr_stype_name(lldpa_contr_stype_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lldpa_contr_stype_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lldpa_contr_stype'";
    }
}

int
lldpa_contr_stype_value(const char* str, lldpa_contr_stype_t* e, int substr)
{
    int i;
    AIM_REFERENCE(substr);
    if(aim_map_si_s(&i, str, lldpa_contr_stype_map, 0)) {
        /* Enum Found */
        *e = i;
        return 0;
    }
    else {
        return -1;
    }
}

const char*
lldpa_contr_stype_desc(lldpa_contr_stype_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lldpa_contr_stype_desc_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lldpa_contr_stype'";
    }
}

int
lldpa_contr_stype_valid(lldpa_contr_stype_t e)
{
    return aim_map_si_i(NULL, e, lldpa_contr_stype_map, 0) ? 1 : 0;
}

/* <auto.end.enum(ALL).source> */

