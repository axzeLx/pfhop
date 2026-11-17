#!/usr/bin/env bash
# pfhop installer for Rocky Linux / RHEL 9-10. Safe to re-run (idempotent):
# existing config, certificate, database and nginx allow-list are kept.
#
# Usage: sudo ./install.sh [--server-name pfhop.example.com] [--allow "10.0.0.0/8 192.168.0.0/16"]
#
#   --server-name  DNS name of the panel (default: hostname -f)
#   --allow        networks allowed to open the panel (default: Postfix mynetworks)

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_NAME="$(hostname -f)"
ALLOW=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server-name) SERVER_NAME="$2"; shift 2 ;;
        --allow) ALLOW="$2"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
command -v postconf >/dev/null || { echo "Postfix is not installed" >&2; exit 1; }

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

step "Installing packages"
# Only install what is missing - never upgrade packages that are already present.
missing=()
for pkg in nginx python3 openssl sudo; do rpm -q "$pkg" &>/dev/null || missing+=("$pkg"); done
if [[ ${#missing[@]} -gt 0 ]]; then
    dnf -y -q install "${missing[@]}"
else
    echo "all packages present"
fi

step "Creating system user 'pfhop'"
id pfhop &>/dev/null || useradd --system --home-dir /var/lib/pfhop --shell /sbin/nologin pfhop
install -d -o pfhop -g pfhop -m 0750 /var/lib/pfhop

step "Python virtualenv"
[[ -x "$APP_DIR/venv/bin/python" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

step "Root helper + sudoers"
install -d -m 0755 /usr/libexec/pfhop
install -o root -g root -m 0755 "$APP_DIR/helper/pfhop-helper" /usr/libexec/pfhop/pfhop-helper
install -o root -g root -m 0440 "$APP_DIR/deploy/sudoers.d/pfhop" /etc/sudoers.d/pfhop.tmp
visudo -cf /etc/sudoers.d/pfhop.tmp >/dev/null
mv -f /etc/sudoers.d/pfhop.tmp /etc/sudoers.d/pfhop

step "Configuration (/etc/pfhop/pfhop.conf)"
install -d -o root -g pfhop -m 0750 /etc/pfhop
if [[ ! -f /etc/pfhop/pfhop.conf ]]; then
    secret="$(openssl rand -hex 32)"
    sed "s/^secret_key = .*/secret_key = \"$secret\"/" "$APP_DIR/pfhop.conf.example" > /etc/pfhop/pfhop.conf
    echo "created /etc/pfhop/pfhop.conf"
else
    echo "keeping existing /etc/pfhop/pfhop.conf"
fi
chown root:pfhop /etc/pfhop/pfhop.conf
chmod 0640 /etc/pfhop/pfhop.conf

step "TLS certificate (self-signed) for $SERVER_NAME"
install -d -o root -g root -m 0700 /etc/pfhop/tls
if [[ ! -f /etc/pfhop/tls/pfhop.crt ]]; then
    openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -keyout /etc/pfhop/tls/pfhop.key -out /etc/pfhop/tls/pfhop.crt \
        -subj "/CN=$SERVER_NAME" \
        -addext "subjectAltName=DNS:$SERVER_NAME" 2>/dev/null
    chmod 0600 /etc/pfhop/tls/pfhop.key
    echo "created /etc/pfhop/tls/pfhop.crt (valid 10 years)"
else
    echo "keeping existing certificate"
fi

step "nginx"
if [[ ! -f /etc/nginx/pfhop-allow.conf ]]; then
    [[ -n "$ALLOW" ]] || ALLOW="$(postconf -h mynetworks | tr ',' ' ')"
    {
        echo "# Networks allowed to open pfhop. Edit, then: systemctl reload nginx"
        for net in $ALLOW; do
            [[ "$net" == \[* ]] && continue   # skip [ipv6] notation
            echo "allow $net;"
        done
        echo "deny all;"
    } > /etc/nginx/pfhop-allow.conf
    echo "created /etc/nginx/pfhop-allow.conf"
else
    echo "keeping existing /etc/nginx/pfhop-allow.conf"
fi
sed "s/@SERVER_NAME@/$SERVER_NAME/g" "$APP_DIR/deploy/nginx/pfhop.conf" > /etc/nginx/conf.d/pfhop.conf
nginx -t -q
if command -v getenforce >/dev/null && [[ "$(getenforce)" == "Enforcing" ]]; then
    setsebool -P httpd_can_network_connect 1
fi
systemctl enable -q nginx
systemctl reload-or-restart nginx

step "Firewall"
if systemctl is-active -q firewalld; then
    for svc in http https; do
        firewall-cmd -q --query-service=$svc || firewall-cmd -q --permanent --add-service=$svc
    done
    firewall-cmd -q --reload
fi

step "Command line wrapper (/usr/local/bin/pfhop)"
cat > /usr/local/bin/pfhop <<EOF
#!/bin/sh
# pfhop CLI wrapper - runs as the pfhop user with the system config.
export PFHOP_CONFIG=/etc/pfhop/pfhop.conf LANG=C.UTF-8
cd "$APP_DIR" || exit 1
if [ "\$(id -u)" = 0 ]; then
    exec runuser -u pfhop -- "$APP_DIR/venv/bin/python" -m pfhop "\$@"
fi
exec "$APP_DIR/venv/bin/python" -m pfhop "\$@"
EOF
chmod 0755 /usr/local/bin/pfhop

step "pfhop services (web + mail log collector)"
for unit in pfhop.service pfhop-collector.service pfhop-backup.service pfhop-backup.timer; do
    sed "s#@APP_DIR@#$APP_DIR#g" "$APP_DIR/deploy/systemd/$unit" > "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable -q --now pfhop-backup.timer
for unit in pfhop pfhop-collector; do
    systemctl enable -q "$unit"
    systemctl restart "$unit"
done
sleep 2
for unit in pfhop pfhop-collector; do
    systemctl is-active -q "$unit" || { journalctl -u "$unit" -n 30 --no-pager; exit 1; }
done

users="$(/usr/local/bin/pfhop users 2>/dev/null | wc -l)"

echo
echo "pfhop is running: https://$SERVER_NAME/"
if [[ "$users" == "0" ]]; then
    echo
    echo "Create the first admin account:"
    echo "  pfhop useradd admin --role admin"
fi
