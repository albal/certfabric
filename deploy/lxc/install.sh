#!/usr/bin/env bash
# Install or upgrade CertFabric inside a Debian 12 Proxmox LXC container.
#
# On the Proxmox host, for example:
#   pct create 120 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
#     --hostname certfabric --memory 512 --cores 1 --rootfs local-lvm:4 \
#     --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1 --features nesting=1
#   pct start 120
#   pct push 120 install.sh /root/install.sh && pct exec 120 -- bash /root/install.sh
#
# Re-running the script upgrades in place and keeps the database and secret key.
set -euo pipefail

REPO="${CERTFABRIC_REPO:-https://github.com/albal/certfabric.git}"
REF="${CERTFABRIC_REF:-main}"
ACME_SH_VERSION="${ACME_SH_VERSION:-3.1.1}"
NODE_VERSION="${NODE_VERSION:-26.13.0}"
PYTHON_VERSION="${PYTHON_VERSION:-3.15}"
UV_VERSION="${UV_VERSION:-0.13.6}"
APP=/opt/certfabric
DATA=/var/lib/certfabric
CONF=/etc/certfabric

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

echo "==> Installing packages"
apt-get update -qq
apt-get install -y -qq git curl openssl ca-certificates libatomic1 >/dev/null

id certfabric >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin certfabric
install -d -o certfabric -g certfabric -m 0750 "$DATA"
install -d -o root -g certfabric -m 0750 "$CONF"
install -d -m 0755 "$APP" /opt/certfabric-plugins

echo "==> Fetching CertFabric ($REF)"
if [[ -d "$APP/src/.git" ]]; then
  git -C "$APP/src" fetch -q origin "$REF" && git -C "$APP/src" checkout -q FETCH_HEAD
else
  git clone -q --branch "$REF" "$REPO" "$APP/src"
fi

# Debian's Python and Node.js are too old, so CertFabric keeps its own copies under $APP.
# The service runs with ProtectHome, so Python cannot live in uv's default place under /root.
export UV_INSTALL_DIR="$APP/uv" UV_PYTHON_INSTALL_DIR="$APP/python" UV_NO_MODIFY_PATH=1
if [[ "$("$APP/uv/uv" --version 2>/dev/null)" != "uv $UV_VERSION "* ]]; then
  echo "==> Installing uv $UV_VERSION"
  curl -fsSL "https://astral.sh/uv/$UV_VERSION/install.sh" | sh >/dev/null
fi

if [[ "$("$APP/node/bin/node" --version 2>/dev/null)" != "v$NODE_VERSION" ]]; then
  echo "==> Installing Node.js $NODE_VERSION"
  case "$(uname -m)" in
    x86_64) node_arch=x64 ;;
    aarch64) node_arch=arm64 ;;
    *) echo "No Node.js build for $(uname -m)" >&2; exit 1 ;;
  esac
  rm -rf "$APP/node" && mkdir "$APP/node"
  curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$node_arch.tar.gz" \
    | tar -xz --strip-components=1 -C "$APP/node"
fi

echo "==> Building the dashboard"
(cd "$APP/src/frontend" && export PATH="$APP/node/bin:$PATH" && npm ci --no-audit --no-fund --silent && npm run build --silent)
rm -rf "$APP/src/certfabric/static" && cp -r "$APP/src/frontend/dist" "$APP/src/certfabric/static"

echo "==> Installing the application"
"$APP/uv/uv" python install --quiet "$PYTHON_VERSION"
# An upgrade may find a venv built on an older Python, which cannot be reused.
if [[ "$("$APP/venv/bin/python" --version 2>/dev/null)" != "Python $PYTHON_VERSION"* ]]; then
  "$APP/uv/uv" venv --quiet --clear --python "$PYTHON_VERSION" "$APP/venv"
fi
"$APP/uv/uv" pip install --quiet --python "$APP/venv/bin/python" "$APP/src"

echo "==> Installing acme.sh $ACME_SH_VERSION"
if [[ ! -x /opt/acme.sh/acme.sh ]] || ! grep -q "VER=$ACME_SH_VERSION" /opt/acme.sh/acme.sh; then
  rm -rf /opt/acme.sh
  curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz" | tar -xz -C /opt
  mv "/opt/acme.sh-${ACME_SH_VERSION}" /opt/acme.sh
fi

if [[ ! -f "$CONF/secret.key" ]]; then
  echo "==> Generating the secret key ($CONF/secret.key) - BACK IT UP"
  "$APP/venv/bin/certfabric" generate-key > "$CONF/secret.key"
fi
chown certfabric:certfabric "$CONF/secret.key"
chmod 0400 "$CONF/secret.key"

cat > "$CONF/certfabric.env" <<ENV
CERTFABRIC_SECRET_KEY_FILE=$CONF/secret.key
CERTFABRIC_DB_PATH=$DATA/certfabric.db
CERTFABRIC_ACME_SH=/opt/acme.sh/acme.sh
CERTFABRIC_PLUGINS_DIR=/opt/certfabric-plugins
ENV

cat > /etc/systemd/system/certfabric.service <<UNIT
[Unit]
Description=CertFabric certificate lifecycle manager
After=network-online.target
Wants=network-online.target

[Service]
User=certfabric
Group=certfabric
EnvironmentFile=$CONF/certfabric.env
ExecStart=$APP/venv/bin/certfabric serve --host 0.0.0.0 --port 8080
Restart=on-failure
MemoryMax=512M
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now certfabric >/dev/null
systemctl restart certfabric

echo "==> CertFabric is running on http://$(hostname -I | awk '{print $1}'):8080"
echo "    Back up $CONF/secret.key: without it the stored secrets cannot be decrypted."
