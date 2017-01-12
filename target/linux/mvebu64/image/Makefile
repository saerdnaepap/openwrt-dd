#
# Copyright (C) 2016 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

define CompressGzip
	gzip -9n -c $(1) > $(2)
endef

define Image/Prepare
	cp $(KDIR)/vmlinux.elf $(BIN_DIR)/$(IMG_PREFIX)-vmlinux.elf
	$(call CompressGzip,$(KDIR)/vmlinux,$(KDIR)/vmlinux.bin.gz)
endef

# Marvell Armada DB-88F8040-Modular
define Image/BuildKernel/Profile/armada-88F8040-DB
	cp $(KDIR)/Image $(BIN_DIR)/openwrt-armada-88F8040-Image
	cp $(KDIR)/Image.gz $(BIN_DIR)/openwrt-armada-88F8040-Image.gz
	cp $(DTS_DIR)/marvell/armada-8040-db-router.dtb $(BIN_DIR)/armada-88F8040.dtb
ifeq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),y)
	cp $(KDIR)/Image-initramfs $(BIN_DIR)/openwrt-armada-88F8040-Image-initramfs
endif
endef

define Image/Build/squashfs
    $(call prepare_generic_squashfs,$(KDIR)/root.squashfs)
endef

define Image/BuildKernel
	$(call Image/BuildKernel/Profile/$(PROFILE))
endef

define Image/Build
	$(call Image/Build/$(1))
ifeq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),y)
	$(call Image/Build/Initramfs)
endif
endef

$(eval $(call BuildImage))
