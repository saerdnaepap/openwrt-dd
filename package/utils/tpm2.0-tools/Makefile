#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=tpm2.0-tools
PKG_VERSION:=c2d0cc3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://github.com/01org/tpm2.0-tools
PKG_MD5SUM:=152c79b363d2e7914c256cc2f4cb8b49

PKG_FIXUP:=autoreconf

PKG_INSTALL:=1

TARGET_CFLAGS+= -U_FORTIFY_SOURCE --param ssp-buffer-size=1

include $(INCLUDE_DIR)/package.mk

define Package/tpm2.0-tools
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Tools by intel to access a TPM2.0
  URL:=https://github.com/01org/tpm2.0-tools
  DEPENDS:=+libc +libpthread +libstdcpp +libopenssl +libcurl +tpm2.0-tss
endef

define Package/tpm2.0-tools/description
  Tools to access and configure a TPM2.0 device
endef

define Build/Prepare
	$(Build/Prepare/Default)
	mkdir $(PKG_BUILD_DIR)/m4
	cp *.m4 $(PKG_BUILD_DIR)/m4
	(cd $(PKG_BUILD_DIR) && ./bootstrap)
endef

define Build/Configure
	$(call Build/Configure/Default, ) #WAR to circumvent a compiler warning. Needs fix!
endef

define Package/tpm2.0-tools/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/* $(1)/usr/sbin
	touch $(PKG_BUILD_DIR)/installed.txt
endef

$(eval $(call BuildPackage,tpm2.0-tools))
  



