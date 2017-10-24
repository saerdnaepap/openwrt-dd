#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=openssl_tpm_engine
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://git.code.sf.net/p/trousers/openssl_tpm_engine
PKG_SOURCE_VERSION:=bbc2b1
PKG_SOURCE_DATE:=2012-09-26

PKG_FIXUP:=autoreconf

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/openssl_tpm_engine
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=openssl engine for tpm 2.0 support
  URL:=https://git.code.sf.net/p/trousers/openssl_tpm_engine
  DEPENDS:=+libopenssl +ibmtpm20tss
endef

define Package/openssl_tpm_engine/description
  openssl engine support for tpm 2.0 to be able to generate e.g.
  csr with private keys in the tpm.
endef

define Build/Prepare
	$(Build/Prepare/Default)
	(cd $(PKG_BUILD_DIR) && chmod +x bootstrap.sh && ./bootstrap.sh)
endef

define Build/Configure
	$(call Build/Configure/Default, ) 
endef

define Package/openssl_tpm_engine/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/* $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib/engines #our openssl version searches for engines in /usr/lib/engines per default
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/openssl/engines/libtpm2.so* $(1)/usr/lib/engines
endef

$(eval $(call BuildPackage,openssl_tpm_engine))
  



