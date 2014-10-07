################################################################
#
#        Copyright 2013, Big Switch Networks, Inc.
#
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#        http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
################################################################
include ../../init.mk

ALLOW_DECLARATION_AFTER_STATEMENT = 1

MODULE := icmp_agent
include $(BUILDER)/standardinit.mk

LIBRARY := icmp_agent_main
$(LIBRARY)_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/lib.mk

DEPENDMODULES := icmpa AIM PPE IOF VPI BigList OS loci indigo SocketManager \
				 cjson Configuration murmur OFConnectionManager \
                 uCli BigHash router_ip_table debug_counter timer_wheel BigRing
include $(BUILDER)/dependmodules.mk

BINARY := icmp-agent

$(BINARY)_LIBRARIES := $(LIBRARY_TARGETS)
include $(BUILDER)/bin.mk

include $(BUILDER)/targets.mk

GLOBAL_CFLAGS += -DINDIGO_LINUX_LOGGING
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_FAULT_ON_ASSERT
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
GLOBAL_CFLAGS += -g
GLOBAL_CFLAGS += -O3
GLOBAL_CFLAGS += -I$(icmpa_BASEDIR)/module/src
GLOBAL_LINK_LIBS += -lrt -lpcap -lm

ifdef USE_CALLGRIND
GLOBAL_CFLAGS += -DUSE_CALLGRIND
endif
