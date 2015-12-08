%{!?name:%define name turnserver}
%{!?version:%define version 0.5}
%{!?release:%define release 2}

Summary: The TURN server
Name:    turnserver
Version: %{version}
Release: %{release}
License: GPLv3+
Group:   Networking/Other
URL:     http://turnserver.sourceforge.net/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
One good TURN deserves another!

%prep
%setup -q

%build
autoreconf -i
./configure --prefix=$RPM_BUILD_ROOT/usr --enable-fdsetsize=4096
make

%install
rm -rf $RPM_BUILD_ROOT
make install

# init script
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
cp -p extra/turnserver.fedora.initd $RPM_BUILD_ROOT/etc/rc.d/init.d/turnserver

# conf
cp -p extra/turnserver.conf.template $RPM_BUILD_ROOT/etc/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%_initddir
%doc /usr/share/man/man1/turnserver.1.gz
%doc /usr/share/man/man5/turnserver.conf.5.gz
/etc/turnserver.conf.template
/usr/bin/turnserver
/usr/bin/test_echo_server
/usr/bin/test_turn_client

%preun
# $1 is the number of instances of this package present _after_ the action.
if [ $1 = 0 ]; then
    /sbin/service turnserver stop || :
else
    /sbin/service turnserver condrestart || :
fi

%changelog
* Thu Oct 27 2011  <kenstir@vivox.com> - 0.5-2
- condrestart the service after an upgrade; stop it after an uninstall

* Wed Oct 26 2011  <kenstir@vivox.com> - 0.5-1
- First RPM version.
