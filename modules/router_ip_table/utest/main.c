/**************************************************************************//**
 *
 *
 *
 *****************************************************************************/
#include <router_ip_table/router_ip_table_config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <AIM/aim.h>

#include <router_ip_table/router_ip_table.h>
#include <indigo/of_state_manager.h>

static const indigo_core_gentable_ops_t *ops;
static void *table_priv;

static const of_mac_addr_t mac1 = { { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } };
static const of_mac_addr_t mac2 = { { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } };

static of_list_bsn_tlv_t *
make_key(uint16_t vlan_vid)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    of_bsn_tlv_vlan_vid_t *tlv = of_bsn_tlv_vlan_vid_new(OF_VERSION_1_3);
    of_bsn_tlv_vlan_vid_value_set(tlv, vlan_vid);
    of_list_append(list, tlv);
    of_object_delete(tlv);
    return list;
}

static of_list_bsn_tlv_t *
make_value(uint32_t ipv4, of_mac_addr_t mac)
{
    of_list_bsn_tlv_t *list = of_list_bsn_tlv_new(OF_VERSION_1_3);
    {
        of_bsn_tlv_ipv4_t *tlv = of_bsn_tlv_ipv4_new(OF_VERSION_1_3);
        of_bsn_tlv_ipv4_value_set(tlv, ipv4);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    {
        of_bsn_tlv_mac_t *tlv = of_bsn_tlv_mac_new(OF_VERSION_1_3);
        of_bsn_tlv_mac_value_set(tlv, mac);
        of_list_append(list, tlv);
        of_object_delete(tlv);
    }
    return list;
}

int aim_main(int argc, char* argv[])
{
    of_list_bsn_tlv_t *key1, *key2, *value1, *value2, *value3;
    void *entry_priv;
    indigo_error_t rv;
    uint32_t ip;
    of_mac_addr_t mac;

    router_ip_table_init();

    ASSERT(ops != NULL);

    key1 = make_key(10);
    key2 = make_key(8000); /* invalid */
    value1 = make_value(0x1234, mac1);
    value2 = make_value(0x5678, mac2);
    value3 = make_value(0, mac1); /* invalid */

    /* Successful add/modify/delete */
    {
        rv = router_ip_table_lookup(10, &ip, &mac);
        ASSERT(rv == INDIGO_ERROR_NOT_FOUND);

        rv = ops->add(table_priv, key1, value1, &entry_priv);
        ASSERT(rv == INDIGO_ERROR_NONE);

        rv = router_ip_table_lookup(10, &ip, &mac);
        ASSERT(rv == INDIGO_ERROR_NONE);
        ASSERT(ip == 0x1234);
        ASSERT(!memcmp(&mac, &mac1, sizeof(of_mac_addr_t)));

        rv = ops->modify(table_priv, entry_priv, key1, value2);
        ASSERT(rv == INDIGO_ERROR_NONE);

        rv = router_ip_table_lookup(10, &ip, &mac);
        ASSERT(rv == INDIGO_ERROR_NONE);
        ASSERT(ip == 0x5678);
        ASSERT(!memcmp(&mac, &mac2, sizeof(of_mac_addr_t)));

        rv = ops->del(table_priv, entry_priv, key1);
        ASSERT(rv == INDIGO_ERROR_NONE);

        rv = router_ip_table_lookup(10, &ip, &mac);
        ASSERT(rv == INDIGO_ERROR_NOT_FOUND);
    }

    /* Invalid key */
    {
        rv = ops->add(table_priv, key2, value1, &entry_priv);
        ASSERT(rv == INDIGO_ERROR_PARAM);
    }

    /* Invalid value */
    {
        rv = ops->add(table_priv, key1, value3, &entry_priv);
        ASSERT(rv == INDIGO_ERROR_PARAM);
    }

    of_object_delete(key1);
    of_object_delete(key2);
    of_object_delete(value1);
    of_object_delete(value2);
    of_object_delete(value3);

    router_ip_table_finish();

    return 0;
}

void
indigo_core_gentable_register(
    const of_table_name_t name,
    const indigo_core_gentable_ops_t *_ops,
    void *_table_priv,
    uint32_t max_size,
    uint32_t buckets_size,
    indigo_core_gentable_t **gentable)
{
    if (!strcmp(name, "router_ip")) {
        ops = _ops;
        table_priv = _table_priv;
    }

    *gentable = (void *)1;
}

void
indigo_core_gentable_unregister(indigo_core_gentable_t *gentable)
{
    ASSERT(gentable == (void *)1);
}
