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
                                  uint32_t length, uint32_t *vlan);

int dhc_add_relay_agent_options(struct dhcp_packet *packet,
                                unsigned length, unsigned max_len,
                                unsigned *message_type,
                                opt_info_t *opt);

/* Error statistics */
typedef struct {
    /* For dhcp request */
    uint32_t agent_option_errors;
    uint32_t missing_request_cookie;
    uint32_t missing_request_message;

    /* For dhcp reply */
    uint32_t missing_circuit_id;
    uint32_t bad_circuit_id;
    uint32_t corrupt_agent_options;
    uint32_t missing_dhcp_agent_option;
    uint32_t missing_reply_cookie;
    uint32_t missing_reply_message;
} dhcrelay_stat;

extern dhcrelay_stat dhc_relay_stat;

#endif /* DHCRELAY_H_ */
