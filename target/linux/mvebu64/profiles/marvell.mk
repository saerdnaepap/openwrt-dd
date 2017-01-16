#
# Copyright (C) 2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/armada-88F8040-DB
  NAME:=Marvell Armada 88F8040-DB
  NAME:=Marvell Armada-8040 DB (DB-88F8040-Modular)
  CPU_TYPE:=cortex-a53
  CPU_SUBTYPE:=neon-vfpv4
  PACKAGES:=
endef

define Profile/armada-88F8040-DB/Description
  Package set compatible with the Armada 88F8040 Development Board.
endef

$(eval $(call Profile,armada-88F8040-DB))
