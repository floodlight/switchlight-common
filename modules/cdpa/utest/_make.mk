###############################################################################
#
# cdpa Unit Test Makefile.
#
###############################################################################
UMODULE := cdpa
UMODULE_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/utest.mk
