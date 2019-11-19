NAME    := freeipa
SRC_EXT := gz
SOURCE  = https://releases.pagure.org/$(NAME)/$(NAME)-$(VERSION).tar.$(SRC_EXT)
DL_VERSION = 4.6.3
DSOURCE = https://releases.pagure.org/$(NAME)/$(NAME)-$(DL_VERSION).tar.$(SRC_EXT)
PATCHES = 0001-release-4-6-3.4-gfe5d037.patch
PATCHES += 0002-backport-tumbleweed.patch
PATCHES += enable-certmonger.patch
PATCHES += suse_disable_ntp_keys_by_default.patch

include packaging/Makefile_packaging.mk

$(NAME)-$(VERSION).tar.$(SRC_EXT): $(SPEC) $(CALLING_MAKEFILE)
	rm -f ./$(NAME)-*.tar.{gz,bz*,xz}
	curl -f -L -o $@ '$(DSOURCE)'
