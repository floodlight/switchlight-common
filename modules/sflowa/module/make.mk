###############################################################################
#
# 
#
###############################################################################
THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
sflowa_INCLUDES := -I $(THIS_DIR)inc
sflowa_INTERNAL_INCLUDES := -I $(THIS_DIR)src
sflowa_DEPENDMODULE_ENTRIES := init:sflowa ucli:sflowa

