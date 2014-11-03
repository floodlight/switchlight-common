################################################################
#
#        Copyright 2014, Big Switch Networks, Inc.
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

include ../../../init.mk
MODULE := cdpa_utest
TEST_MODULE := cdpa
DEPENDMODULES := AIM indigo loci OS debug_counter OFStateManager SocketManager \
    cjson Configuration timer_wheel BigList BigHash minimatch murmur \
    OFConnectionManager BigRing uCli IOF
DEPENDMODULE_HEADERS := slshared
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DINDIGO_LINUX_TIME
GLOBAL_CFLAGS += -DINDIGO_MEM_STDLIB
include $(BUILDER)/build-unit-test.mk

GLOBAL_LINK_LIBS += -lm -rdynamic
