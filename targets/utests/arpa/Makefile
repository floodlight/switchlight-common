###############################################################################
#
# 
#
###############################################################################

include ../../../init.mk
MODULE := arpa_utest
TEST_MODULE := arpa
DEPENDMODULES := AIM indigo loci PPE IOF
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
include $(BUILDER)/build-unit-test.mk
