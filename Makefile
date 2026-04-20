TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TOOL_NAME = trackerscan
trackerscan_FILES = src/main.m src/TDClassScanner.m src/LSApplicationProxy+AltList.m
trackerscan_CFLAGS = -fobjc-arc
trackerscan_CODESIGN_FLAGS = -Ssrc/entitlements.plist
trackerscan_INSTALL_PATH = /usr/local/bin
trackerscan_FRAMEWORKS = Foundation
trackerscan_PRIVATE_FRAMEWORKS = MobileCoreServices

include $(THEOS_MAKE_PATH)/tool.mk

after-stage::
	install -d $(THEOS_STAGING_DIR)/usr/share/trackerscan
	install -m 644 src/signatures.json $(THEOS_STAGING_DIR)/usr/share/trackerscan/
