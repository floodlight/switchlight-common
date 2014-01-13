###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
router_ip_table_INCLUDES := -I $(THIS_DIR)inc
router_ip_table_INTERNAL_INCLUDES := -I $(THIS_DIR)src
router_ip_table_DEPENDMODULE_ENTRIES := init:router_ip_table ucli:router_ip_table

