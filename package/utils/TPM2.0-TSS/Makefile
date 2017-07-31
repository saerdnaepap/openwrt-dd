#
# Copyright to be added
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=TPM2.0-TSS
PKG_VERSION:=64b11df
PKG_RELEASE:=1

PKG_MD5SUM:=38d83b0367bc6d6a708779998a6ea387
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=@GITHUB/01org/TPM2.0-TSS
PKG_CAT:=bzcat

PKG_FIXUP:=autoreconf
#PKG_BUILD_DEPENDS:=util-linux
#PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/TPM2.0-TSS
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TPM 2.0 trusted software stack by Intel
  URL:=https://github.com/01org/TPM2.0-TSS
endef

define Package/TPM2.0-TSS/description
  Software stack for trusted platform module
  version 2.0 provided by Intel.
endef

define Build/Prepare
	$(PKG_UNPACK)
	touch $(PKG_BUILD_DIR)/testtpm.txt
	cp ax_pthread.m4 $(PKG_BUILD_DIR)/m4
	(cd $(PKG_BUILD_DIR) && ./bootstrap)
endef


$(eval $(call BuildPackage,TPM2.0-TSS))
  



