#!/var/jb/bin/sh

/var/jb/usr/libexec/firmware
/var/jb/usr/sbin/pwd_mkdb -d /var/jb/etc -p /var/jb/etc/master.passwd >/dev/null 2>&1
/var/jb/Library/dpkg/info/debianutils.postinst configure 99999
/var/jb/Library/dpkg/info/apt.postinst configure 999999
/var/jb/Library/dpkg/info/dash.postinst configure 999999
/var/jb/Library/dpkg/info/zsh.postinst configure 999999
/var/jb/Library/dpkg/info/bash.postinst configure 999999
/var/jb/Library/dpkg/info/vi.postinst configure 999999

# OpenSSH service registration is load-bearing for Bring-Up (P16 replacement).
# Fail closed if extrainst is missing or launchctl load fails.
if [ ! -x /var/jb/Library/dpkg/info/openssh-server.extrainst_ ]; then
    echo "prep_bootstrap: openssh-server.extrainst_ missing or not executable" >&2
    exit 1
fi
/var/jb/Library/dpkg/info/openssh-server.extrainst_ install || {
    echo "prep_bootstrap: openssh-server.extrainst_ install failed" >&2
    exit 1
}

/var/jb/usr/sbin/pwd_mkdb -d /var/jb/etc -p /var/jb/etc/master.passwd

/var/jb/usr/sbin/pw -V /var/jb/etc usermod mobile -s /var/jb/usr/bin/zsh
/var/jb/usr/sbin/pw -V /var/jb/etc usermod root -s /var/jb/usr/bin/zsh

if [ -z "$NO_PASSWORD_PROMPT" ]; then
    PASSWORDS=""
    PASSWORD1=""
    PASSWORD2=""
    while [ -z "$PASSWORD1" ] || [ ! "$PASSWORD1" = "$PASSWORD2" ]; do
            PASSWORDS="$(/var/jb/usr/bin/uialert -b "In order to use command line tools like \"sudo\" after jailbreaking, you will need to set a terminal passcode. (This cannot be empty)" --secure "Password" --secure "Repeat Password" -p "Set" "Set Password")"
            PASSWORD1="$(printf "%s\n" "$PASSWORDS" | /var/jb/usr/bin/sed -n '1 p')"
            PASSWORD2="$(printf "%s\n" "$PASSWORDS" | /var/jb/usr/bin/sed -n '2 p')"
    done
    printf "%s\n" "$PASSWORD1" | /var/jb/usr/sbin/pw -V /var/jb/etc usermod 501 -h 0
fi

# R23: ensure SSH homes exist (strap tar has empty dirs; appletvos extract lacked them).
/var/jb/usr/bin/mkdir -p /var/jb/var/mobile /var/jb/var/root
/var/jb/usr/bin/mkdir -p /var/jb/var/mobile/Library/Preferences
/var/jb/usr/bin/chown -R 501:501 /var/jb/var/mobile
/var/jb/usr/bin/chown 0:0 /var/jb/var/root
/var/jb/usr/bin/rm -f /var/jb/prep_bootstrap.sh
