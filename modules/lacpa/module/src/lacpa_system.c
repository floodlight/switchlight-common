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

/*
 * Implementation of Lacp Agent System.
 *
 * This file contains the system wide calls for initializing/deinitializing
 * lacp system for the agent.
 *
 * Added gentable support for lacp.
 */

#include "lacpa_int.h"
#include "lacpa_utils.h"

lacpa_system_t lacpa_system;
bool lacp_system_initialized = false;
aim_ratelimiter_t lacpa_pktin_log_limiter;
aim_ratelimiter_t lacpa_parse_log_limiter;

static indigo_core_gentable_t *lacp_table;
static const indigo_core_gentable_ops_t lacp_ops;

/*
 * lacpa_is_initialized
 *
 * true = System Initialized
 * false = System Uninitialized
 */
bool
lacpa_is_initialized (void)
{
    return lacp_system_initialized;
}

/*
 * lacpa_init
 *
 * API to init the LACP System
 * This should only be done once at the beginning.
 */
indigo_error_t
lacpa_init (void)
{
    uint32_t ports_size = 0;

    if (lacpa_is_initialized()) return INDIGO_ERROR_NONE;

    AIM_LOG_INFO("init");

    ports_size = sizeof(lacpa_port_t) * (PHY_PORT_COUNT+1);
    aim_ratelimiter_init(&lacpa_pktin_log_limiter, 1000*1000, 5, NULL);
    aim_ratelimiter_init(&lacpa_parse_log_limiter, 1000*1000, 5, NULL);
    lacpa_register_system_counters();

    lacpa_system.ports = (lacpa_port_t *) LACPA_MALLOC(ports_size);
    if (lacpa_system.ports == NULL) {
        AIM_LOG_INTERNAL("Failed to allocate resources for ports..");
        return INDIGO_ERROR_RESOURCE;
    }

    AIM_LOG_TRACE("Succesfully inited LACP System for %d ports...",
                  PHY_PORT_COUNT);
    LACPA_MEMSET(lacpa_system.ports, 0, ports_size);
    lacp_system_initialized = true;

    /*
     * Register listerners for port packet_in and Controller msg's
     */
    if (indigo_core_packet_in_listener_register((indigo_core_packet_in_listener_f)
                                                lacpa_packet_in_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for port packet_in in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    if (indigo_core_message_listener_register((indigo_core_message_listener_f)
                                              lacpa_controller_msg_handler) < 0) {
        AIM_LOG_FATAL("Failed to register for Controller msg in LACPA module");
        return INDIGO_ERROR_INIT;
    }

    indigo_core_gentable_register("lacp", &lacp_ops, NULL, PHY_PORT_COUNT, 128,
                                  &lacp_table);
    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_finish
 *
 * API to deinit the LACP System
 */
void
lacpa_finish (void)
{
    indigo_core_packet_in_listener_unregister(lacpa_packet_in_handler);
    indigo_core_message_listener_unregister(lacpa_controller_msg_handler);
    indigo_core_gentable_unregister(lacp_table);

    lacpa_unregister_system_counters();

    LACPA_FREE(lacpa_system.ports);
    lacp_system_initialized = false;
}

/*
 * lacpa_find_port
 *
 * Returns port pointer in the system for valid port_no else
 * returns NULL
 */
lacpa_port_t *
lacpa_find_port (uint32_t port_no)
{
    if (port_no > PHY_PORT_COUNT) {
        AIM_LOG_INTERNAL("Port No: %d Out of Range %d", port_no, PHY_PORT_COUNT);
        return NULL;
    }

    return (&lacpa_system.ports[port_no]);
}

/*
 * lacpa_parse_key
 *
 * Parse key for lacp table entry from tlv list
 */
static indigo_error_t
lacpa_parse_key (of_list_bsn_tlv_t *tlvs, of_port_no_t *port_no)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty key list");
        return INDIGO_ERROR_PARAM;
    }

    /* port */
    if (tlv.header.object_id == OF_BSN_TLV_PORT) {
        of_bsn_tlv_port_value_get(&tlv.port, port_no);
    } else {
        AIM_LOG_ERROR("expected port key TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (*port_no > PHY_PORT_COUNT) {
        AIM_LOG_ERROR("Port out of range (%u)", *port_no);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of key list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_parse_value
 *
 * Parse values for lacp table entry from tlv list
 */
static indigo_error_t
lacpa_parse_value (of_list_bsn_tlv_t *tlvs, lacpa_info_t *info)
{
    of_bsn_tlv_t tlv;

    if (of_list_bsn_tlv_first(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("empty value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Actor system priority */
    if (tlv.header.object_id == OF_BSN_TLV_ACTOR_SYSTEM_PRIORITY) {
        of_bsn_tlv_actor_system_priority_value_get(&tlv.actor_system_priority,
                                                   &info->sys_priority);
    } else {
        AIM_LOG_ERROR("expected actor_system_priority value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Actor system mac */
    if (tlv.header.object_id == OF_BSN_TLV_ACTOR_SYSTEM_MAC) {
        of_bsn_tlv_actor_system_mac_value_get(&tlv.actor_system_mac,
                                              &info->sys_mac);
    } else {
        AIM_LOG_ERROR("expected actor_system_mac value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Actor port priority */
    if (tlv.header.object_id == OF_BSN_TLV_ACTOR_PORT_PRIORITY) {
        of_bsn_tlv_actor_port_priority_value_get(&tlv.actor_port_priority,
                                                 &info->port_priority);
    } else {
        AIM_LOG_ERROR("expected actor_port_priority value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Actor port num */
    if (tlv.header.object_id == OF_BSN_TLV_ACTOR_PORT_NUM) {
        of_bsn_tlv_actor_port_num_value_get(&tlv.actor_port_num,
                                            &info->port_num);
    } else {
        AIM_LOG_ERROR("expected actor_port_num value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) < 0) {
        AIM_LOG_ERROR("unexpected end of value list");
        return INDIGO_ERROR_PARAM;
    }

    /* Actor key */
    if (tlv.header.object_id == OF_BSN_TLV_ACTOR_KEY) {
        of_bsn_tlv_actor_key_value_get(&tlv.actor_key, &info->key);
    } else {
        AIM_LOG_ERROR("expected actor_key value TLV, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    if (of_list_bsn_tlv_next(tlvs, &tlv) == 0) {
        AIM_LOG_ERROR("expected end of value list, instead got %s",
                      of_object_id_str[tlv.header.object_id]);
        return INDIGO_ERROR_PARAM;
    }

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_add
 *
 * Add a new entry to lacp table
 */
static indigo_error_t
lacpa_add (void *table_priv, of_list_bsn_tlv_t *key_tlvs,
           of_list_bsn_tlv_t *value_tlvs, void **entry_priv)
{
    indigo_error_t rv;
    lacpa_info_t info;

    if (!lacpa_is_initialized()) return INDIGO_ERROR_INIT;

    LACPA_MEMSET(&info, 0, sizeof(lacpa_info_t));

    rv = lacpa_parse_key(key_tlvs, &info.port_no);
    if (rv < 0) {
        return rv;
    }

    rv = lacpa_parse_value(value_tlvs, &info);
    if (rv < 0) {
        return rv;
    }

    AIM_LOG_TRACE("Add lacp table entry, port: %u -> sys_priority: %u, sys_mac:"
                  " %{mac}, port_priority: %u, port_num: %u, key: %u",
                  info.port_no, info.sys_priority, info.sys_mac.addr,
                  info.port_priority, info.port_num, info.key);
    lacpa_init_port(&info, true);

    *entry_priv = lacpa_find_port(info.port_no);

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_modify
 *
 * Modify a existing entry in lacp table
 */
static indigo_error_t
lacpa_modify (void *table_priv, void *entry_priv,
              of_list_bsn_tlv_t *key_tlvs, of_list_bsn_tlv_t *value_tlvs)
{
    indigo_error_t rv;
    lacpa_info_t info;
    lacpa_port_t *port = entry_priv;

    if (!lacpa_is_initialized()) return INDIGO_ERROR_INIT;

    AIM_ASSERT(port, "Attempted to modify a NULL entry from lacp table");

    LACPA_MEMSET(&info, 0, sizeof(lacpa_info_t));

    rv = lacpa_parse_value(value_tlvs, &info);
    if (rv < 0) {
        return rv;
    }

    info.port_no = port->actor.port_no;
    AIM_LOG_TRACE("Modify lacp table entry, old port: %u -> sys_priority: %u, "
                  "sys_mac: %{mac}, port_priority: %u, port_num: %u, key: %u",
                  port->actor.port_no, port->actor.sys_priority,
                  port->actor.sys_mac.addr, port->actor.port_priority,
                  port->actor.port_num, port->actor.key);

    AIM_LOG_TRACE("New, port: %u -> sys_priority: %u, sys_mac: %{mac}, "
                  "port_priority: %u, port_num: %u, key: %u",
                  info.port_no, info.sys_priority, info.sys_mac.addr,
                  info.port_priority, info.port_num, info.key);
    lacpa_init_port(&info, true);

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_delete
 *
 * Remove a entry from lacp table
 */
static indigo_error_t
lacpa_delete (void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key_tlvs)
{
    lacpa_port_t *port = entry_priv;

    if (!lacpa_is_initialized()) return INDIGO_ERROR_INIT;

    AIM_ASSERT(port, "Attempted to delete a NULL entry from lacp table");

    AIM_LOG_TRACE("Delete lacp table entry, port: %u -> sys_priority: %u, "
                  "sys_mac: %{mac}, port_priority: %u, port_num: %u, key: %u",
                  port->actor.port_no, port->actor.sys_priority,
                  port->actor.sys_mac.addr, port->actor.port_priority,
                  port->actor.port_num, port->actor.key);
    lacpa_init_port(&port->actor, false);

    return INDIGO_ERROR_NONE;
}

/*
 * lacpa_get_stats
 *
 * Return the stats related with a entry in lacp table
 */
static void
lacpa_get_stats (void *table_priv, void *entry_priv, of_list_bsn_tlv_t *key,
                 of_list_bsn_tlv_t *stats)
{
    lacpa_port_t *port = entry_priv;

    if (!lacpa_is_initialized()) return;

    AIM_ASSERT(port, "Attempted to request stats from lacp table for "
               "NULL entry");

    AIM_LOG_TRACE("Received stats request for port: %u", port->actor.port_no);

    /* Convergence status */
    {
        of_bsn_tlv_convergence_status_t tlv;
        of_bsn_tlv_convergence_status_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_convergence_status_value_set(&tlv, !port->is_converged);
    }

    /* Actor state */
    {
        of_bsn_tlv_actor_state_t tlv;
        of_bsn_tlv_actor_state_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_actor_state_value_set(&tlv, port->actor.state);
    }

    /* Partner system priority */
    {
        of_bsn_tlv_partner_system_priority_t tlv;
        of_bsn_tlv_partner_system_priority_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_system_priority_value_set(&tlv,
                                                     port->partner.sys_priority);
    }

    /* Partner system mac */
    {
        of_bsn_tlv_partner_system_mac_t tlv;
        of_bsn_tlv_partner_system_mac_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_system_mac_value_set(&tlv, port->partner.sys_mac);
    }

    /* Partner port priority */
    {
        of_bsn_tlv_partner_port_priority_t tlv;
        of_bsn_tlv_partner_port_priority_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_port_priority_value_set(&tlv,
                                                   port->partner.port_priority);
    }

    /* Partner port num */
    {
        of_bsn_tlv_partner_port_num_t tlv;
        of_bsn_tlv_partner_port_num_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_port_num_value_set(&tlv, port->partner.port_num);
    }

    /* Partner key */
    {
        of_bsn_tlv_partner_key_t tlv;
        of_bsn_tlv_partner_key_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_key_value_set(&tlv, port->partner.key);
    }

    /* Partner state */
    {
        of_bsn_tlv_partner_state_t tlv;
        of_bsn_tlv_partner_state_init(&tlv, stats->version, -1, 1);
        of_list_bsn_tlv_append_bind(stats, (of_bsn_tlv_t *)&tlv);
        of_bsn_tlv_partner_state_value_set(&tlv, port->partner.state);
    }
}

static const indigo_core_gentable_ops_t lacp_ops = {
    .add = lacpa_add,
    .modify = lacpa_modify,
    .del = lacpa_delete,
    .get_stats = lacpa_get_stats,
};
