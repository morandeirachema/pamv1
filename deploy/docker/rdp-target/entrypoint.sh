#!/bin/sh
# Start the xrdp session manager and daemon in the foreground. Kept simple and
# idempotent so `docker compose restart` works. Demo only — see the Dockerfile.
set -e

# Clear stale pid/socket state from a previous run.
rm -f /var/run/xrdp/xrdp.pid /var/run/xrdp/xrdp-sesman.pid 2>/dev/null || true
mkdir -p /var/run/dbus /var/run/xrdp

# XFCE needs a system D-Bus with a machine-id.
[ -s /var/lib/dbus/machine-id ] || dbus-uuidgen --ensure
rm -f /var/run/dbus/pid
dbus-daemon --system --fork

# xrdp generates its self-signed RSA keys / cert on first start; the demo runs
# pam-server with PAM_GUACD_IGNORE_CERT=true so guacd accepts that cert.
/usr/sbin/xrdp-sesman
exec /usr/sbin/xrdp --nodaemon
