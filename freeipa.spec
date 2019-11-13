#
# spec file for package freeipa
#
# Copyright (c) 2017 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#
%bcond_without only_client
%if %{with only_client}
    %global enable_server_option --disable-server
%else
    %global enable_server_option --enable-server
%endif
# while we only build the client this works. for building the server we still need python2
# then we will need to change the BR for sssd-config to python3-sssd-config
%define skip_python2 1
# 1.15.1-7: certauth (http://krbdev.mit.edu/rt/Ticket/Display.html?id=8561)
%global krb5_version           1.15.1
# 0.7.16: https://github.com/drkjam/netaddr/issues/71
%global python_netaddr_version 0.7.16
# Require 4.6.0-4 which brings RC4 for FIPS + trust fixes to priv. separation
%global samba_version          4.6.0
%global samba_build_version    4.2.1
%global selinux_policy_version 3.13.1
%global slapi_nis_version      0.56.1

%if 0%{?suse_version}
%define ipaplatform suse
%endif
%if 0%{?is_opensuse}
%define ipaplatform opensuse
%endif
%if 0%{?rhel}
%define ipaplatform rhel
%endif
    

%define krb5_base_version %(LC_ALL=C rpm -q --qf '%%{VERSION}' krb5-devel | grep -Eo '^[^.]+\.[^.]+')

%global plugin_dir %{_libdir}/dirsrv/plugins
%global etc_systemd_dir %{_sysconfdir}/systemd/system
%global gettext_domain ipa

%global MY_VERSION 4.6.3


#Suse has a python_module macro, mockbuild on fedora does not have.
%{!?python_module: %define python_module() python3-%*}

Name:           freeipa
Version:        %{MY_VERSION}+git10.87d5e59e6
Release:        4.52%{?dist}
License:        GPL-3.0+
Summary:        The Identity, Policy and Audit system
Url:            https://www.freeipa.org/
Group:          Productivity/Networking/LDAP/Servers
Source:         https://releases.pagure.org/freeipa/freeipa-%{VERSION}.tar.gz
Patch0001:      0001-release-4-6-3-4-gfe5d037.patch
Patch0002:      0002-backport-tumbleweed.patch
Patch0003:      enable-certmonger.patch
Patch0004:      suse_disable_ntp_keys_by_default.patch

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
# autogen.sh
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  gettext
BuildRequires:  gettext-devel
BuildRequires:  diffstat
#
BuildRequires:  pkgconfig(ini_config)
BuildRequires:  pkgconfig(krb5) >= %{krb5_version}
BuildRequires:  pkgconfig(libsasl2)
BuildRequires:  pkgconfig(nspr)
BuildRequires:  pkgconfig(nss)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(popt)
BuildRequires:  pkgconfig(sss_nss_idmap)
#
BuildRequires:  %{python_module devel}
BuildRequires:  %{python_module setuptools}
# all
BuildRequires:  %{python_module six}
# ipaclient
BuildRequires:  %{python_module cryptography}
BuildRequires:  %{python_module qrcode}
# ipaclient/csrgen
Recommends:     %{python_module jinja2}
# ipaclient/otptoken_yubikey
Recommends:     %{python_module python-yubico}
Recommends:     %{python_module pyusb}
# ipalib
BuildRequires:  %{python_module netaddr}
BuildRequires:  %{python_module pyasn1}
BuildRequires:  %{python_module pyasn1-modules}
# ipaplatform
BuildRequires:  %{python_module cffi}
# ipapython
BuildRequires:  %{python_module dnspython}
BuildRequires:  %{python_module gssapi}
BuildRequires:  %{python_module netifaces}
BuildRequires:  %{python_module ldap}
BuildRequires:  %{python_module dbus-python}
BuildRequires:  %{python_module gssapi}
BuildRequires:  %{python_module sssd-config}
BuildRequires:  %{python_module nss}
#
%if 0%{?suse_version}
BuildRequires:  openldap2-devel
%else
BuildRequires:  openldap-devel
%endif
# for sssd_pac
BuildRequires:  sssd-ad
BuildRequires:  sssd-ipa
BuildRequires:  suse-release
BuildRequires:  xmlrpc-c-devel >= 1.27.4

%description
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).

%package client
Group:          Productivity/Networking/LDAP/Servers
Requires:       %{name}-common = %{version}
Requires:       %{name}-client-common = %{version}
# all
Requires:       python3-six
Requires:       certmonger
Requires:       keyutils
Requires:       mozilla-nss-tools
Requires:       krb5-client
Requires:       pam_krb5
Requires:       sssd-krb5
Requires:       sudo
# ipaclient
Requires:       python3-cryptography
Requires:       python3-qrcode
# ipaclient/csrgen
Recommends:     python3-jinja2
# ipaclient/otptoken_yubikey
Recommends:     python3-python-yubico
Recommends:     python3-pyusb
# ipalib
Requires:       python3-netaddr
Requires:       python3-pyasn1
Requires:       python3-pyasn1-modules
# ipaplatform
Requires:       python3-cffi
# ipapython
Requires:       python3-dnspython
Requires:       python3-gssapi
Requires:       python3-netifaces
Requires:       python3-ldap
#Requires:       python3-enum34
Requires:       python3-dbus-python
Requires:       python3-gssapi
Requires:       python3-sssd-config
Requires:       python3-nss
Requires:       sssd-ipa
#
Summary:        Freeipa Client
%description client
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).

%package common
Group:          Productivity/Networking/LDAP/Servers
#
Summary:        Freeipa Common files
%description common
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).

This package holds the common files

%package client-common
Group:          Productivity/Networking/LDAP/Servers
#
Summary:        Freeipa Common files
%description client-common
IPA is an integrated solution to provide centrally managed Identity (users,
hosts, services), Authentication (SSO, 2FA), and Authorization
(host access control, SELinux user roles, services). The solution provides
features for further integration with Linux based clients (SUDO, automount)
and integration with Active Directory based infrastructures (Trusts).

This package holds the common files

%prep
%setup -q -n %{name}-%{MY_VERSION}
UpdateTimestamps() {
  Level=$1
  PatchFile=$2

  # Locate the affected files:
  for f in $(diffstat $Level -l $PatchFile); do
    # Set the files to have the same timestamp as that of the patch:
    touch -c -r $PatchFile $f
  done
}

for p in %patches ; do
    %__patch -p1 -i $p
    UpdateTimestamps -p1 $p
done

%build
export JAVA_STACK_SIZE="16m"
export PATH=/usr/bin:/usr/sbin:$PATH
export PYTHON=%{__python3}
# Workaround: make sure all shebangs are pointing to Python 2
# This should be solved properly using setuptools
# and this hack should be removed.
find \
   ! -name '*.pyc' -a \
   ! -name '*.pyo' -a \
   -type f -exec grep -qsm1 '^#!.*\bpython' {} \; \
   -exec sed -i -e '1 s|^#!.*\bpython[^ ]*|#!%{__python3}|' {} \;
perl -p -i -e 's|define\(IPA_VERSION_IS_GIT_SNAPSHOT, yes\)|define(IPA_VERSION_IS_GIT_SNAPSHOT, no)|g' VERSION.m4
autoreconf -i -f
%configure --with-vendor-suffix=-%{release} --without-ipatests \
           --with-ipaplatform=%{ipaplatform} \
           %{enable_server_option}
make %{?_smp_mflags} VERBOSE=yes

%install
%make_install
find %{buildroot} -wholename '*/site-packages/*/install_files.txt' -delete
mkdir -p %{buildroot}%{_sysconfdir}/pki/ca-trust/source/

%find_lang ipa

%files common -f ipa.lang
%defattr(-,root,root)
%doc README.md Contributors.txt
%license COPYING

%files client
%defattr(-,root,root)
%doc README.md Contributors.txt
%license COPYING
%config/etc/bash_completion.d/ipa
%{_bindir}/ipa*
%{_sbindir}/ipa*
%{_mandir}/man1/ipa*.1*
%{python3_sitelib}/ipa*

%files client-common
%defattr(-,root,root,-)
%doc README.md Contributors.txt
%license COPYING
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/
%ghost %attr(0644,root,apache) %config(noreplace) %{_sysconfdir}/ipa/default.conf
%ghost %attr(0644,root,apache) %config(noreplace) %{_sysconfdir}/ipa/ca.crt
%dir %attr(0755,root,root) %{_sysconfdir}/ipa/nssdb
# old dbm format
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/cert8.db
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/key3.db
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/secmod.db
# new sql format
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/cert9.db
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/key4.db
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/pkcs11.txt
%ghost %config(noreplace) %{_sysconfdir}/ipa/nssdb/pwdfile.txt
%dir %{_sysconfdir}/pki/
%dir %{_sysconfdir}/pki/ca-trust/
%dir %{_sysconfdir}/pki/ca-trust/source/
%ghost %config(noreplace) %{_sysconfdir}/pki/ca-trust/source/ipa.p11-kit
%dir %{_localstatedir}/lib/ipa-client
%dir %{_localstatedir}/lib/ipa-client/pki
%dir %{_localstatedir}/lib/ipa-client/sysrestore
%{_mandir}/man5/default.conf.5*

%changelog
* Wed Nov 13 2019 john.malmberg@intel.com
- Backport to OpenSUSE Leap 15.1
* Wed Feb  7 2018 opensuse-packaging@opensuse.org
- Update to version 4.6.3+git10.87d5e59e6:
  * do not hardcode the kdestroy path
  * Comment out the 2 redhat specific include paths for now
  * Merge the CA handling from the RH module
  * fix path of update-ca-certificates
  * Port SUSE platform to make use of api parameter
  * Initial support for SUSE and openSUSE
  * IANA reserved IP address can not be used as a forwarder. This test checks if ipa server installation throws an error when 0.0.0.0 is specified as forwarder IP address.
  * Fixing translation problems
  * preventing ldap principal to be deleted
  * VERSION.m4: Set back to git snapshot
* Wed Feb  7 2018 mrueckert@suse.de
- Require sssd-ad for sssd_pac
- split out freeipa-client-common
* Tue Feb  6 2018 mrueckert@suse.de
- BR all the python libraries that we require in the client package
- switch most BR to pkgconfig() flavor
* Tue Feb  6 2018 mrueckert@suse.de
- switch to service
* Thu Feb  1 2018 mrueckert@suse.de
- use python3
* Thu Feb  1 2018 mrueckert@suse.de
- add requires to the package and split out the client and common
  package
* Thu Feb  1 2018 mrueckert@suse.de
- switch to patch for adding suse support
* Thu Feb  1 2018 mrueckert@suse.de
- client support seems to work
* Fri Mar 24 2017 mrueckert@suse.de
- initial package
