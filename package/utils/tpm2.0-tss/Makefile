#
# Copyright to be added
#
#
#
#
 
include $(TOPDIR)/rules.mk

PKG_NAME:=tpm2.0-tss
PKG_VERSION:=92f7adc
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=https://github.com/01org/TPM2.0-TSS
PKG_MD5SUM:=91d7a90f18a17dd40603e3966d63b9f6

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/tpm2.0-tss
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=TPM 2.0 trusted software stack by Intel
  URL:=https://github.com/01org/TPM2.0-TSS
  DEPENDS:=+libc +libpthread
endef

define Package/tpm2.0-tss/description
  Software stack for trusted platform module
  version 2.0 provided by Intel.
endef

define Build/Prepare
	$(Build/Prepare/Default)
	cp ax_pthread.m4 $(PKG_BUILD_DIR)/m4
	(cd $(PKG_BUILD_DIR) && ./bootstrap)
endef

#MAKE_FLAGS += all

#define Build/Configure
#	$(Build/Configure/Default)
#	cp ax_pthread.m4 $(PKG_BUILD_DIR)/m4
#	(cd $(PKG_BUILD_DIR) && ./bootstrap)
#	(cd $(PKG_BUILD_DIR) && CONFIG_SITE=$(pwd)/lib/default_config.site ./configure)
#	touch $(PKG_BUILD_DIR)/configured.txt
#endef

#define Build/Compile
#	touch compiletest.txt
#	(cd $(PKG_BUILD_DIR) && make)
#endef

#define Build/Install
#	(cd $(PKG_BUILD_DIR) && make install)
#endef

define Package/tpm2.0-tss/install
	touch $(PKG_BUILD_DIR)/installed.txt
endef

$(eval $(call BuildPackage,tpm2.0-tss))
  



