###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
arpa_INCLUDES := -I $(THIS_DIR)inc
arpa_INTERNAL_INCLUDES := -I $(THIS_DIR)src
arpa_DEPENDMODULE_ENTRIES := init:arpa ucli:arpa

