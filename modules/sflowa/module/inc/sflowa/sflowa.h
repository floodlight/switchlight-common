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

#ifndef __SFLOWA_H__
#define __SFLOWA_H__

#include <stdbool.h>
#include <indigo/indigo.h>

/******************************************************************************
 *
 * SFLOW : EXTERNAL API DEFINITIONS
 *
 *****************************************************************************/

/**
 * @brief API to init the Sflow Agent
 */
indigo_error_t sflowa_init (void);

/**
 * @brief Sampling rate update handler
 * @param port_no The OF port number for which sampling rate is being configured
 * @param sampling_rate The ratio of packets observed at the port
 * to the samples generated. For example a sampling rate of 100 specifies that,
 * on average, 1 sample will be generated for every 100 packets observed.
 * Sampling rate of 1 signifies sample all packets and a sampling rate of 0
 * disables sampling.
 */
typedef void (*sflowa_sampling_rate_handler_f)(of_port_no_t port_no,
                                               uint32_t sampling_rate);

/**
 * @brief Register application specific handler for sampling rate update
 * @param fn Application specific handler for sampling rate update
 */
indigo_error_t sflowa_sampling_rate_handler_register(sflowa_sampling_rate_handler_f
                                                     fn);

/**
 * @brief Deregister application specific handler for sampling rate update
 * @param fn Application specific handler for sampling rate update
 */
void sflowa_sampling_rate_handler_unregister(sflowa_sampling_rate_handler_f fn);

#endif /* __SFLOWA__H__ */
