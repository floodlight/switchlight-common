###############################################################################
#
# sflowa Unit Test Makefile.
#
###############################################################################
UMODULE := sflowa
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
