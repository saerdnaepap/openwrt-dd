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

PKG_BUILD_DIR:=$(BUILD_DIR)/ibmtpm20tss-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://downloads.sourceforge.net/project/ibmtpm20tss/
PKG_MD5SUM:=3314ffff877a48aebc1da9b44ff5290d

#PKG_FIXUP:=autoreconf

PKG_INSTALL:=1

UNPACK_CMD:=tar -C $(PKG_BUILD_DIR) -xzf $(DL_DIR)/$(PKG_SOURCE) 

include $(INCLUDE_DIR)/package.mk

define Package/ibmtpm20tss
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TPM 2.0 trusted software stack by IBM
  URL:=https://sourceforge.net/projects/ibmtpm20tss/
  DEPENDS:=+libopenssl
endef

define Package/ibmtpm20tss/description
  Software stack for trusted platform module
  version 2.0 provided by IBM. Non-TCG compliant
  API but usage shall be simpler.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/utils \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -DTPM_POSIX" \
		LDFLAGS="$(TARGET_LDFLAGS)" 
endef

define Build/Install
endef

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

define Package/ibmtpm20tss/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/utils/libtss.so* $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/utils/bin/* $(1)/usr/sbin
#	$(INSTALL_DIR) $(1)/etc/init.d
#	$(INSTALL_BIN) ./files/resourcemgr.init $(1)/etc/init.d/resourcemgr
endef

$(eval $(call BuildPackage,ibmtpm20tss))
  



