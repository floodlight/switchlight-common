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

#ifndef DHCRELAY_H_
#define DHCRELAY_H_

int dhc_strip_relay_agent_options(struct dhcp_packet *packet,
                                  uint32_t length, uint32_t *vlan,
                                  cir_to_vlan_fn c2v);

int dhc_add_relay_agent_options(struct dhcp_packet *packet,
                                unsigned length, unsigned max_len,
                                opt_info_t *opt);

#endif /* DHCRELAY_H_ */
