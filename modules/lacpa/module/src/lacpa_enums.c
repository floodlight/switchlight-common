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

#include <lacpa/lacpa_config.h>
#include <lacpa/lacpa.h>

/* <auto.start.enum(ALL).source> */
aim_map_si_t lacpa_error_map[] =
{
    { "NONE", LACPA_ERROR_NONE },
    { "PARTNER_AGGREGATION_OFF", LACPA_ERROR_PARTNER_AGGREGATION_OFF },
    { "PARTNER_INSYNC", LACPA_ERROR_PARTNER_INSYNC },
    { "PARTNER_COLLECTION_OFF", LACPA_ERROR_PARTNER_COLLECTION_OFF },
    { "PARTNER_DISTRIBUTION_OFF", LACPA_ERROR_PARTNER_DISTRIBUTION_OFF },
    { NULL, 0 }
};

aim_map_si_t lacpa_error_desc_map[] =
{
    { "None", LACPA_ERROR_NONE },
    { "None", LACPA_ERROR_PARTNER_AGGREGATION_OFF },
    { "None", LACPA_ERROR_PARTNER_INSYNC },
    { "None", LACPA_ERROR_PARTNER_COLLECTION_OFF },
    { "None", LACPA_ERROR_PARTNER_DISTRIBUTION_OFF },
    { NULL, 0 }
};

const char*
lacpa_error_name(lacpa_error_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_error_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_error'";
    }
}

int
lacpa_error_value(const char* str, lacpa_error_t* e, int substr)
{
    int i;
    AIM_REFERENCE(substr);
    if(aim_map_si_s(&i, str, lacpa_error_map, 0)) {
        /* Enum Found */
        *e = i;
        return 0;
    }
    else {
        return -1;
    }
}

const char*
lacpa_error_desc(lacpa_error_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_error_desc_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_error'";
    }
}


aim_map_si_t lacpa_machine_map[] =
{
    { "AGENT_STOPPED", LACPA_MACHINE_AGENT_STOPPED },
    { "AGENT_CURRENT", LACPA_MACHINE_AGENT_CURRENT },
    { "AGENT_EXPIRED", LACPA_MACHINE_AGENT_EXPIRED },
    { "AGENT_DEFAULTED", LACPA_MACHINE_AGENT_DEFAULTED },
    { NULL, 0 }
};

aim_map_si_t lacpa_machine_desc_map[] =
{
    { "None", LACPA_MACHINE_AGENT_STOPPED },
    { "None", LACPA_MACHINE_AGENT_CURRENT },
    { "None", LACPA_MACHINE_AGENT_EXPIRED },
    { "None", LACPA_MACHINE_AGENT_DEFAULTED },
    { NULL, 0 }
};

const char*
lacpa_machine_name(lacpa_machine_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_machine_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_machine'";
    }
}

int
lacpa_machine_value(const char* str, lacpa_machine_t* e, int substr)
{
    int i;
    AIM_REFERENCE(substr);
    if(aim_map_si_s(&i, str, lacpa_machine_map, 0)) {
        /* Enum Found */
        *e = i;
        return 0;
    }
    else {
        return -1;
    }
}

const char*
lacpa_machine_desc(lacpa_machine_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_machine_desc_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_machine'";
    }
}


aim_map_si_t lacpa_event_map[] =
{
    { "DISABLED", LACPA_EVENT_DISABLED },
    { "ENABLED", LACPA_EVENT_ENABLED },
    { "PDU_RECEIVED", LACPA_EVENT_PDU_RECEIVED },
    { "CURRENT_TIMER_EXPIRED", LACPA_EVENT_CURRENT_TIMER_EXPIRED },
    { "EXPIRY_TIMER_EXPIRED", LACPA_EVENT_EXPIRY_TIMER_EXPIRED },
    { "CHURN_DETECTION_EXPIRED", LACPA_EVENT_CHURN_DETECTION_EXPIRED },
    { "PROTOCOL_CONVERGED", LACPA_EVENT_PROTOCOL_CONVERGED },
    { "PROTOCOL_UNCONVERGED", LACPA_EVENT_PROTOCOL_UNCONVERGED },
    { NULL, 0 }
};

aim_map_si_t lacpa_event_desc_map[] =
{
    { "None", LACPA_EVENT_DISABLED },
    { "None", LACPA_EVENT_ENABLED },
    { "None", LACPA_EVENT_PDU_RECEIVED },
    { "None", LACPA_EVENT_CURRENT_TIMER_EXPIRED },
    { "None", LACPA_EVENT_EXPIRY_TIMER_EXPIRED },
    { "None", LACPA_EVENT_CHURN_DETECTION_EXPIRED },
    { "None", LACPA_EVENT_PROTOCOL_CONVERGED },
    { "None", LACPA_EVENT_PROTOCOL_UNCONVERGED },
    { NULL, 0 }
};

const char*
lacpa_event_name(lacpa_event_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_event_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_event'";
    }
}

int
lacpa_event_value(const char* str, lacpa_event_t* e, int substr)
{
    int i;
    AIM_REFERENCE(substr);
    if(aim_map_si_s(&i, str, lacpa_event_map, 0)) {
        /* Enum Found */
        *e = i;
        return 0;
    }
    else {
        return -1;
    }
}

const char*
lacpa_event_desc(lacpa_event_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_event_desc_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_event'";
    }
}


aim_map_si_t lacpa_transmit_map[] =
{
    { "NONE", LACPA_TRANSMIT_NONE },
    { "AGENT_ENABLED", LACPA_TRANSMIT_AGENT_ENABLED },
    { "INFO_MISMATCH", LACPA_TRANSMIT_INFO_MISMATCH },
    { "LCAP_ACTIVITY_MISTMATCH", LACPA_TRANSMIT_LCAP_ACTIVITY_MISTMATCH },
    { "AGGREGATION_MISTMATCH", LACPA_TRANSMIT_AGGREGATION_MISTMATCH },
    { "SYNCHRONIZATION_MISTMATCH", LACPA_TRANSMIT_SYNCHRONIZATION_MISTMATCH },
    { "COLLECTING_MISTMATCH", LACPA_TRANSMIT_COLLECTING_MISTMATCH },
    { "DISTRIBUTING_MISTMATCH", LACPA_TRANSMIT_DISTRIBUTING_MISTMATCH },
    { "SYNCHRONIZATION_SET", LACPA_TRANSMIT_SYNCHRONIZATION_SET },
    { "COLLECTING_SET", LACPA_TRANSMIT_COLLECTING_SET },
    { "DISTRIBUTING_SET", LACPA_TRANSMIT_DISTRIBUTING_SET },
    { "PERIODIC_TIMER_EXPIRED", LACPA_TRANSMIT_PERIODIC_TIMER_EXPIRED },
    { "CURRENT_TIMER_EXPIRED", LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED },
    { NULL, 0 }
};

aim_map_si_t lacpa_transmit_desc_map[] =
{
    { "None", LACPA_TRANSMIT_NONE },
    { "None", LACPA_TRANSMIT_AGENT_ENABLED },
    { "None", LACPA_TRANSMIT_INFO_MISMATCH },
    { "None", LACPA_TRANSMIT_LCAP_ACTIVITY_MISTMATCH },
    { "None", LACPA_TRANSMIT_AGGREGATION_MISTMATCH },
    { "None", LACPA_TRANSMIT_SYNCHRONIZATION_MISTMATCH },
    { "None", LACPA_TRANSMIT_COLLECTING_MISTMATCH },
    { "None", LACPA_TRANSMIT_DISTRIBUTING_MISTMATCH },
    { "None", LACPA_TRANSMIT_SYNCHRONIZATION_SET },
    { "None", LACPA_TRANSMIT_COLLECTING_SET },
    { "None", LACPA_TRANSMIT_DISTRIBUTING_SET },
    { "None", LACPA_TRANSMIT_PERIODIC_TIMER_EXPIRED },
    { "None", LACPA_TRANSMIT_CURRENT_TIMER_EXPIRED },
    { NULL, 0 }
};

const char*
lacpa_transmit_name(lacpa_transmit_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_transmit_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_transmit'";
    }
}

int
lacpa_transmit_value(const char* str, lacpa_transmit_t* e, int substr)
{
    int i;
    AIM_REFERENCE(substr);
    if(aim_map_si_s(&i, str, lacpa_transmit_map, 0)) {
        /* Enum Found */
        *e = i;
        return 0;
    }
    else {
        return -1;
    }
}

const char*
lacpa_transmit_desc(lacpa_transmit_t e)
{
    const char* name;
    if(aim_map_si_i(&name, e, lacpa_transmit_desc_map, 0)) {
        return name;
    }
    else {
        return "-invalid value for enum type 'lacpa_transmit'";
    }
}

/* <auto.end.enum(ALL).source> */

