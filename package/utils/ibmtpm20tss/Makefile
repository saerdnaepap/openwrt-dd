#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=ibmtss
PKG_VERSION:=1045
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@SF/projects/ibmtpm20tss/files
PKG_MD5SUM:=3314ffff877a48aebc1da9b44ff5290d

PKG_FIXUP:=autoreconf

PKG_INSTALL:=1



include $(INCLUDE_DIR)/package.mk

define Package/ibmtpm20tss
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TPM 2.0 trusted software stack by IBM
  URL:=https://sourceforge.net/projects/ibmtpm20tss/
  DEPENDS:=+libc +libpthread +libstdcpp
endef

define Package/ibmtpm20tss/description
  Software stack for trusted platform module
  version 2.0 provided by IBM. Non-TCG compliant
  API but usage shall be simpler.
endef

#define Build/Prepare
#	$(Build/Prepare/Default)
#	mkdir $(PKG_BUILD_DIR)/m4
#	cp ax_pthread.m4 $(PKG_BUILD_DIR)/m4
#	(cd $(PKG_BUILD_DIR) && ./bootstrap)
#endef

#define Build/InstallDev
#	$(INSTALL_DIR) $(1)/usr/lib
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsapi.{a,so*} $(1)/usr/lib/
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtcti-device.{a,so*} $(1)/usr/lib/
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtcti-socket.{a,so*} $(1)/usr/lib/
#	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/*.pc $(1)/usr/lib/pkgconfig/
#	$(INSTALL_DIR) $(1)/usr/include
#	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/*.pc.in $(1)/usr/lib/pkgconfig/
#endef

#define Package/tpm2.0-tss/install
#	$(INSTALL_DIR) $(1)/usr/lib
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libsapi.so* $(1)/usr/lib/
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libtcti-device.so* $(1)/usr/lib/
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libtcti-socket.so* $(1)/usr/lib/
#	$(INSTALL_DIR) $(1)/usr/sbin
#	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/resourcemgr $(1)/usr/sbin
#	$(INSTALL_DIR) $(1)/etc/init.d
#	$(INSTALL_BIN) ./files/resourcemgr.init $(1)/etc/init.d/resourcemgr
#	touch $(PKG_BUILD_DIR)/installed.txt
#endef

$(eval $(call BuildPackage,ibmtpm20tss))
  



