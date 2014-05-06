###############################################################################
#
# 
#
###############################################################################

include ../../../init.mk
MODULE := arpra_utest
TEST_MODULE := arpra
DEPENDMODULES := AIM PPE IOF loci indigo OS uCli BigList debug_counter 
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
include $(BUILDER)/build-unit-test.mk

GLOBAL_LINK_LIBS += -lm -lncurses -rdynamic
