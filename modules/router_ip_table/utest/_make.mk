###############################################################################
#
# router_ip_table Unit Test Makefile.
#
###############################################################################
UMODULE := router_ip_table
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
