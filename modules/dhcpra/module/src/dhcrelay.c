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
/*
 * Copyright(c) 2004-2011 by Internet Systems Consortium, Inc.("ISC")
 * Copyright(c) 1997-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 * This software has been written for Internet Systems Consortium
 * by Ted Lemon in cooperation with Vixie Enterprises and Nominum, Inc.
 * To learn more about Internet Systems Consortium, see
 * ``https://www.isc.org/''.  To learn more about Vixie Enterprises,
 * see ``http://www.vix.com''.   To learn more about Nominum, Inc., see
 * ``http://www.nominum.com''.
 */

#include <netinet/in.h>
#include "dhcp.h"
#include "dhcpra_int.h"
#include "dhcrelay.h"
#include "dhcpr_table.h"

/* Relay mode can have 4 options */
enum { forward_and_append,  /* Forward and append our own relay option. */
       forward_and_replace, /* Forward, but replace theirs with ours. */
       forward_untouched,   /* Forward without changes. */
       discard } agent_relay_mode = discard;


/* Error statistics, also used by ucli for debugging purpose */
dhcrelay_stat dhc_relay_stat;

/*
 * Examine a packet to see if it's a candidate to have a Relay
 * Agent Information option tacked onto its tail.   If it is, tack
 * the option on.
 *
 * Return 0: caller to drop packet
 * --if dhcp packet is corrupted.
 * --if option is corrupted
 *
 * Return length of dhcp pkt to be sent
 */
int
dhc_add_relay_agent_options(struct dhcp_packet *packet,
                        unsigned length, unsigned max_dhcp_pkt_len,
                        unsigned *message_type,
                        opt_info_t *opt) {
    int is_dhcp = 0, mms;
    unsigned optlen;
    u_int8_t *op, *nextop, *sp, *max, *end_pad = NULL;

    /* If there's no cookie, it's a bootp packet, so we should just
       forward it unchanged. */
    if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4)) {
        debug_counter_inc(&dhc_relay_stat.missing_request_cookie);
        return length;
    }

    max = ((u_int8_t *)packet) + max_dhcp_pkt_len;

    /* Commence processing after the cookie. */
    sp = op = &packet->options[4];

    while (op < max) {
        switch(*op) {
            /* Skip padding... */
        case DHO_PAD:
            /* Remember the first pad byte so we can commandeer
             * padded space.
             *
             * XXX: Is this really a good idea?  Sure, we can
             * seemingly reduce the packet while we're looking,
             * but if the packet was signed by the client then
             * this padding is part of the checksum(RFC3118),
             * and its nonpresence would break authentication.
             */
            if (end_pad == NULL)
                end_pad = sp;

            if (sp != op)
                *sp++ = *op++;
            else
                sp = ++op;

            continue;

            /* If we see a message type, it's a DHCP packet. */
        case DHO_DHCP_MESSAGE_TYPE:
            is_dhcp = 1;
            *message_type = op[2];
            goto skip;

            /*
             * If there's a maximum message size option, we
             * should pay attention to it
             */
        case DHO_DHCP_MAX_MESSAGE_SIZE:
            mms = ntohs(*(op + 2));
            if (mms < max_dhcp_pkt_len &&
                mms >= DHCP_MTU_MIN)
                max = ((u_int8_t *)packet) + mms;
            goto skip;

            /* Quit immediately if we hit an End option. */
        case DHO_END:
            goto out;

        case DHO_DHCP_AGENT_OPTIONS:
            /* We shouldn't see a relay agent option in a
               packet before we've seen the DHCP packet type,
               but if we do, we have to leave it alone. */
            if (!is_dhcp)
                goto skip;

            end_pad = NULL;

            /* There's already a Relay Agent Information option
               in this packet.   How embarrassing.   Decide what
               to do based on the mode the user specified. */
            switch(agent_relay_mode) {
            case forward_and_append:
                goto skip;
            case forward_untouched:
                return length;
            case discard:
                AIM_LOG_ERROR("Option 82 already existed");
                return 0;
            case forward_and_replace:
            default:
                break;
            }

            /* Skip over the agent option and start copying
               if we aren't copying already. */
            op += op[1] + 2;
            break;

        skip:
            /* Skip over other options. */
        default:
            /* Fail if processing this option will exceed the
             * buffer(op[1] is malformed).
             */
            nextop = op + op[1] + 2;
            if (nextop > max) {
                AIM_LOG_ERROR("Option corrupted");
                return 0;
            }
            
            end_pad = NULL;

            if (sp != op) {
                memmove(sp, op, op[1] + 2);
                sp += op[1] + 2;
                op = nextop;
            } else
                op = sp = nextop;
            
            break;
        }
    }

 out:

    /* If it's not a DHCP packet, we're not supposed to touch it. */
    if (!is_dhcp) {
        debug_counter_inc(&dhc_relay_stat.missing_request_message);
        return length;
    }

    /* If no circuit_id, we are not supposed to touch it */
    if(!opt->circuit_id.bytes) {
        return length;
    }

    /* If the packet was padded out, we can store the agent option
       at the beginning of the padding. */
    if (end_pad != NULL) {
        sp = end_pad;
    }

    /* Sanity check.  Had better not ever happen. */
    if((opt->circuit_id.bytes > 255) || (opt->circuit_id.bytes < 1)) {
        debug_counter_inc(&dhc_relay_stat.agent_option_errors);
        AIM_LOG_ERROR("Circuid_id length(%u) out of range [1 - 255]",
                      opt->circuit_id.bytes);
        return 0;
    }

    optlen = opt->circuit_id.bytes + 2;            /* RAI_CIRCUIT_ID + len */

    if (opt->remote_id.data) {
        if ((opt->remote_id.bytes >= 255) || (opt->remote_id.bytes <= 1)) {
            debug_counter_inc(&dhc_relay_stat.agent_option_errors);
            AIM_LOG_ERROR("Remote_id length(%u) out of range [2 - 254]",
                          opt->remote_id.bytes);
            return 0;
        }
        optlen += opt->remote_id.bytes + 2;    /* RAI_REMOTE_ID + len */
    }

    /* We do not support relay option fragmenting(multiple options to
     * support an option data exceeding 255 bytes).
     */
    if ((optlen < 3) ||(optlen > 255)) {
        debug_counter_inc(&dhc_relay_stat.agent_option_errors);
        AIM_LOG_ERROR("Total agent option length(%u) out of range [3 - 255]",
                      optlen);
        return 0;
    }
    
    /*
     * Is there room for the option, its code+len, and DHO_END?
     * If not, forward without adding the option.
     */
    if (max - sp >= optlen + 3) {
        DHCPRA_DEBUG("Adding %d-byte relay agent option", optlen + 3);

        /* Okay, cons up *our* Relay Agent Information option. */
        *sp++ = DHO_DHCP_AGENT_OPTIONS;
        *sp++ = optlen;
        
        /* Copy in the circuit id... */
        *sp++ = RAI_CIRCUIT_ID;
        *sp++ = opt->circuit_id.bytes;
        memcpy(sp, opt->circuit_id.data, opt->circuit_id.bytes);
        sp += opt->circuit_id.bytes;

        DHCPRA_DEBUG("Add OPTIONS=0x%x, CIRID=0x%x, len=%u",
                     DHO_DHCP_AGENT_OPTIONS, RAI_CIRCUIT_ID,
                     opt->circuit_id.bytes);

        /* Copy in remote ID... */
        if (opt->remote_id.data) {
            *sp++ = RAI_REMOTE_ID;
            *sp++ = opt->remote_id.bytes;
            memcpy(sp, opt->remote_id.data, opt->remote_id.bytes);
            sp += opt->remote_id.bytes;
        }
    } else {
        debug_counter_inc(&dhc_relay_stat.agent_option_errors);
        AIM_LOG_ERROR("No room in packet (used %d of %d) for %d-byte relay agent option: omitted",
                      (int) (sp - ((u_int8_t *) packet)),
                      (int) (max - ((u_int8_t *) packet)),
                      optlen + 3);
    }

    /*
     * Deposit an END option unless the packet is full (shouldn't
     * be possible).
     */
    if (sp < max)
        *sp++ = DHO_END;

    /* Recalculate total packet length. */
    length = sp -((u_int8_t *)packet);

    /* Make sure the packet isn't short(this is unlikely, but in case) */
    if (length < BOOTP_MIN_LEN) {
        memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
        return (BOOTP_MIN_LEN);
    }

    return length;
}


/*
 * Return  0 if successful
 * Return -1 if
 * --option is corrupt
 * --circuid_id is missing
 * --circuit_id is bogus
 */
static int
find_vlan_by_agent_option(u_int8_t *buf, int len, uint32_t *vlan) {
    int i = 0;
    u_int8_t *circuit_id = 0;
    unsigned circuit_id_len = 0;

    while (i < len) {
        /* If the next agent option overflows the end of the
           packet, the agent option buffer is corrupt. */
        if (i + 1 == len ||
            i + buf[i + 1] + 2 > len) {
            debug_counter_inc(&dhc_relay_stat.corrupt_agent_options);
            return -1;
        }
        switch(buf[i]) {
            /* Remember where the circuit ID is... */
        case RAI_CIRCUIT_ID:
            circuit_id = &buf[i + 2];
            circuit_id_len = buf[i + 1];
            i += circuit_id_len + 2;
            continue;

        default:
            i += buf[i + 1] + 2;
            break;
        }
    }

    /* If there's no circuit ID, it's not really ours, tell the caller
       it's no good. */
    if (!circuit_id) {
        debug_counter_inc(&dhc_relay_stat.missing_circuit_id);
        return -1;
    }

    dhcpr_circuit_id_to_vlan(vlan, circuit_id, circuit_id_len);

    if(*vlan != INVALID_VLAN)
        /* Successful */
        return 0;

    AIM_LOG_ERROR("Bad Circuit");
    /* If we didn't get a match, the circuit ID was bogus. */
    debug_counter_inc(&dhc_relay_stat.bad_circuit_id);

    return -1;
}


/*
 * strip agent options and obtain vlan_id
 * Return 0: dhcp is corrupted: drop.
 * --If any option is corrupted
 * --If option 82 exists, but no circuit_id
 * --If option 82 exists, circuit_id exists, no vlan
 *
 * Return length of dhcp pkt to be sent
 * */
int
dhc_strip_relay_agent_options(struct dhcp_packet *packet,
                               uint32_t length, uint32_t *vlan) {
    int is_dhcp = 0;
    u_int8_t *op, *nextop, *sp, *max;
    int dhcp_agent_option = 0;
    int status;

    /* In case we don't have option, this value is set */
    *vlan = INVALID_VLAN;

    /* If there's no cookie, it's a bootp packet, so we should just
       forward it unchanged. */
    if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4)) {
        debug_counter_inc(&dhc_relay_stat.missing_reply_cookie);
        return length;
    }

    max = ((u_int8_t *)packet) + length;
    sp = op = &packet->options[4];

    while (op < max) {
        switch(*op) {
            /* Skip padding... */
        case DHO_PAD:
            if (sp != op)
                *sp = *op;
            ++op;
            ++sp;
            continue;

            /* If we see a message type, it's a DHCP packet. */
        case DHO_DHCP_MESSAGE_TYPE:
            is_dhcp = 1;
            goto skip;
            break;

            /* Quit immediately if we hit an End option. */
        case DHO_END:
            if (sp != op)
                *sp++ = *op++;
            goto out;

        case DHO_DHCP_AGENT_OPTIONS:
            /* We shouldn't see a relay agent option in a
               packet before we've seen the DHCP packet type,
               but if we do, we have to leave it alone. */
            if (!is_dhcp)
                goto skip;

            dhcp_agent_option = 1;
            /* Do not process an agent option if it exceeds the
             * buffer.  Fail this packet.
             */
            nextop = op + op[1] + 2;
            if (nextop > max) {
                AIM_LOG_ERROR("Option corrupted");
                return 0;
            }
            
            status = find_vlan_by_agent_option(op + 2, op[1], vlan);
            if (status) {
                /* 1) circuit_id opt is corrupted
                 * 2) circuit_id is missing
                 * 3) circuit_id is bogus and not found
                 * Drop packet
                 * */
                return 0;
            }

            op = nextop;

            break;

        skip:
            /* Skip over other options. */
        default:
            /* Fail if processing this option will exceed the
             * buffer(op[1] is malformed).
             */
            nextop = op + op[1] + 2;
            if (nextop > max) {
                AIM_LOG_ERROR("Option corrupted");
                return 0;
            }
            
            if (sp != op) {
                memmove(sp, op, op[1] + 2);
                sp += op[1] + 2;
                op = nextop;
            } else
                op = sp = nextop;
            
            break;
        }
    }


 out:
    /* If it's not a DHCP packet, we're not supposed to touch it. */
    if (!is_dhcp) {
        debug_counter_inc(&dhc_relay_stat.missing_reply_message);
        return length;
    }
    
    if (!dhcp_agent_option) {
        debug_counter_inc(&dhc_relay_stat.missing_dhcp_agent_option);
    }

    /* Adjust the length... */
    if (sp != op) {
        length = sp -((u_int8_t *)packet);
        
        /* Make sure the packet isn't short(this is unlikely, but in case) */
        if (length < BOOTP_MIN_LEN) {
            memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
            length = BOOTP_MIN_LEN;
        }
    }

    return (length);
}
