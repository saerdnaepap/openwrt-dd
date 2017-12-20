#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=tpm2.0-tss
#PKG_VERSION:=92f7adc
#PKG_VERSION:=64b11df
PKG_RELEASE:=1

#PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/01org/TPM2.0-TSS.git
PKG_SOURCE_VERSION:=92f7adc
PKG_SOURCE_DATE:=2017-02-04
#PKG_MD5SUM:=91d7a90f18a17dd40603e3966d63b9f6

PKG_FIXUP:=autoreconf

PKG_INSTALL:=1



include $(INCLUDE_DIR)/package.mk

define Package/tpm2.0-tss
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TPM 2.0 trusted software stack by Intel
  URL:=https://github.com/01org/TPM2.0-TSS
  DEPENDS:=+libc +libpthread +libstdcpp
endef

define Package/tpm2.0-tss/description
  Software stack for trusted platform module
  version 2.0 provided by Intel.
endef

define Build/Prepare
	$(Build/Prepare/Default)
	mkdir $(PKG_BUILD_DIR)/m4
	cp ax_pthread.m4 $(PKG_BUILD_DIR)/m4
	(cd $(PKG_BUILD_DIR) && ./bootstrap)
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libsapi.{a,so*} $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtcti-device.{a,so*} $(1)/usr/lib/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libtcti-socket.{a,so*} $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/lib/pkgconfig
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/*.pc $(1)/usr/lib/pkgconfig/
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_INSTALL_DIR)/usr/include/* $(1)/usr/include/
#	$(CP) $(PKG_INSTALL_DIR)/usr/lib/pkgconfig/*.pc.in $(1)/usr/lib/pkgconfig/
endef

define Package/tpm2.0-tss/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libsapi.so* $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libtcti-device.so* $(1)/usr/lib/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/libtcti-socket.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/resourcemgr $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/resourcemgr.init $(1)/etc/init.d/resourcemgr
	touch $(PKG_BUILD_DIR)/installed.txt
endef

$(eval $(call BuildPackage,tpm2.0-tss))
  



