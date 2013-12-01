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
#ifndef __LACPA_INT_H__
#define __LACPA_INT_H__

#include <lacpa/lacpa.h>
#include "lacpa_log.h"

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : DEFAULTS
 *
 *****************************************************************************/
#define LACP_SLOW_PERIODIC_TIMEOUT_MS   30000
#define LACP_FAST_PERIODIC_TIMEOUT_MS   1000
#define LACP_SHORT_TIMEOUT_MS           3000
#define LACP_LONG_TIMEOUT_MS            90000
#define LACP_CHURN_DETECTION_TIMEOUT_MS 60000

#define LACP_PKT_BUF_SIZE               128  //Per LACP specification
                                             //802.3ad-2000, Max LACPDU size
                                             //is 124 Bytes + 4 Byte FCS.

#define PHY_PORT_COUNT                  1024

#define DEFAULT_ZERO                    0

#define DEFAULT_LACP_VERSION            1

#define DEFAULT_ACTOR_INFO              0x01
#define DEFAULT_PARTNER_INFO            0x02
#define DEFAULT_ACTOR_PARTNER_INFO_LEN  0x14

#define DEFAULT_COLLECTOR_INFO          0x03
#define DEFAULT_COLLECTOR_INFO_LEN      0x10
#define DEFAULT_COLLECTOR_MAX_DELAY     0x8000

/*
 * LACP Actor/Partner State bits
 */
#define LACPA_STATE_LACP_ACTIVITY       0x01
#define LACPA_STATE_LACP_TIMEOUT        0x02
#define LACPA_STATE_AGGREGATION         0x04
#define LACPA_STATE_SYNCHRONIZATION     0x08
#define LACPA_STATE_COLLECTING          0x10
#define LACPA_STATE_DISTRIBUTING        0x20
#define LACPA_STATE_DEFAULTED           0x40
#define LACPA_STATE_EXPIRED             0x80

#define LACPA_SET_STATE_LACP_ACTIVITY(_state) \
    (_state |= LACPA_STATE_LACP_ACTIVITY)
#define LACPA_CLR_STATE_LACP_ACTIVITY(_state) \
    (_state &= ~LACPA_STATE_LACP_ACTIVITY)
#define LACPA_IS_STATE_LACP_ACTIVITY(_state) \
    (_state & LACPA_STATE_LACP_ACTIVITY)

#define LACPA_SET_STATE_LACP_TIMEOUT(_state) \
    (_state |= LACPA_STATE_LACP_TIMEOUT)
#define LACPA_CLR_STATE_LACP_TIMEOUT(_state) \
    (_state &= ~LACPA_STATE_LACP_TIMEOUT)
#define LACPA_IS_STATE_LACP_TIMEOUT(_state) \
    (_state & LACPA_STATE_LACP_TIMEOUT)

#define LACPA_SET_STATE_AGGREGATION(_state) \
    (_state |= LACPA_STATE_AGGREGATION)
#define LACPA_CLR_STATE_AGGREGATION(_state) \
    (_state &= ~LACPA_STATE_AGGREGATION)
#define LACPA_IS_STATE_AGGREGATION(_state) \
    (_state & LACPA_STATE_AGGREGATION)

#define LACPA_SET_STATE_SYNCHRONIZATION(_state) \
    (_state |= LACPA_STATE_SYNCHRONIZATION)
#define LACPA_CLR_STATE_SYNCHRONIZATION(_state) \
    (_state &= ~LACPA_STATE_SYNCHRONIZATION)
#define LACPA_IS_STATE_SYNCHRONIZATION(_state) \
    (_state & LACPA_STATE_SYNCHRONIZATION)

#define LACPA_SET_STATE_COLLECTING(_state) \
    (_state |= LACPA_STATE_COLLECTING)
#define LACPA_CLR_STATE_COLLECTING(_state) \
    (_state &= ~LACPA_STATE_COLLECTING)
#define LACPA_IS_STATE_COLLECTING(_state) \
    (_state & LACPA_STATE_COLLECTING)

#define LACPA_SET_STATE_DISTRIBUTING(_state) \
    (_state |= LACPA_STATE_DISTRIBUTING)
#define LACPA_CLR_STATE_DISTRIBUTING(_state) \
    (_state &= ~LACPA_STATE_DISTRIBUTING)
#define LACPA_IS_STATE_DISTRIBUTING(_state) \
    (_state & LACPA_STATE_DISTRIBUTING)

#define LACPA_SET_STATE_DEFAULTED(_state) \
    (_state |= LACPA_STATE_DEFAULTED)
#define LACPA_CLR_STATE_DEFAULTED(_state) \
    (_state &= ~LACPA_STATE_DEFAULTED)
#define LACPA_IS_STATE_DEFAULTED(_state) \
    (_state & LACPA_STATE_DEFAULTED)

#define LACPA_SET_STATE_EXPIRED(_state) \
    (_state |= LACPA_STATE_EXPIRED)
#define LACPA_CLR_STATE_EXPIRED(_state) \
    (_state &= ~LACPA_STATE_EXPIRED)
#define LACPA_IS_STATE_EXPIRED(_state) \
    (_state & LACPA_STATE_EXPIRED)

/******************************************************************************
 *
 * LACP : LINK AGGREGATION CONTROL PROTOCOL : LACPA INTERNAL API DECLARATIONS
 *
 *****************************************************************************/
extern void lacpa_machine (lacpa_port_t *port, lacpa_pdu_t *pdu);
extern bool lacpa_transmit (lacpa_port_t *port);
extern bool lacpa_receive (of_packet_in_t *packet_in, of_octets_t *octets);

extern void lacpa_periodic_machine (lacpa_port_t *port, bool timer_enabled);
extern void lacpa_churn_detection_machine (lacpa_port_t *port,
                                           bool timer_enabled);
extern void lacpa_current_while_timer (lacpa_port_t *port, bool timer_enabled);

#endif /* __LACPA_INT_H__ */
