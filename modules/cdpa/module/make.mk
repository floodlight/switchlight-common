###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
cdpa_INCLUDES := -I $(THIS_DIR)inc
cdpa_INTERNAL_INCLUDES := -I $(THIS_DIR)src
cdpa_DEPENDMODULE_ENTRIES := init:cdpa ucli:cdpa

