###############################################################################
#
# arpra Unit Test Makefile.
#
###############################################################################
UMODULE := arpra
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
