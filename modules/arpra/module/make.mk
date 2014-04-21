###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
arpra_INCLUDES := -I $(THIS_DIR)inc
arpra_INTERNAL_INCLUDES := -I $(THIS_DIR)src
arpra_DEPENDMODULE_ENTRIES := init:arpra ucli:arpra

