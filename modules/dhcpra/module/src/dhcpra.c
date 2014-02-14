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

#include <dhcpra/dhcpra.h>
#include "dhcpra_int.h"
#include "dhcpr_table.h"

/************************
 * DHCPRA SYSTEM INIT
 ************************/

/* Return 0: success */
int
dhcpra_system_init()
{

    /* dhcp_relay table init */
    dhcpr_table_init();

    /* Will add relay agent init */

    return 0;
}


