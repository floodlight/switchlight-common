###############################################################################
#
# arpa Unit Test Makefile.
#
###############################################################################
UMODULE := arpa
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
