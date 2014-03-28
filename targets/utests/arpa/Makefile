###############################################################################
#
# 
#
###############################################################################

include ../../../init.mk
MODULE := arpa_utest
TEST_MODULE := arpa
DEPENDMODULES := AIM indigo loci PPE IOF router_ip_table OS BigHash murmur SocketManager cjson Configuration BigList debug_counter timer_wheel
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_LINK_LIBS += -lm
include $(BUILDER)/build-unit-test.mk
