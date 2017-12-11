#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=create_devid
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/create_devid
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=create 802.1ar devid for TPM 2.0 devices
  DEPENDS:=+libopenssl +ibmtpm20tss
endef

define Package/create_devid/description
  Software stack for trusted platform module
  version 2.0 provided by IBM. Non-TCG compliant
  API but usage shall be simpler.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/create_devid create_devid.c tpm2-common.c -lcrypto -ltss
endef

define Package/create_devid/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/create_devid $(1)/usr/sbin
endef

$(eval $(call BuildPackage,create_devid))
  



