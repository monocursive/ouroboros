#!/bin/sh
# Run with sudo after native measurements. Credentials are not stored here.
set -eu
bench_user="$1"
bench_root="$2"
export DEBIAN_FRONTEND=noninteractive
test "$(dpkg --print-architecture)" = arm64
test "$(. /etc/os-release; echo "$VERSION_CODENAME")" = trixie
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker-ouro-benchmark.asc
chmod 0644 /etc/apt/keyrings/docker-ouro-benchmark.asc
cat > /etc/apt/sources.list.d/docker-ouro-benchmark.sources <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: arm64
Signed-By: /etc/apt/keyrings/docker-ouro-benchmark.asc
EOF
apt-get update
docker_pin='5:29.1.3-1~debian.13~trixie'
apt-get install -y --no-install-recommends "docker-ce=$docker_pin" "docker-ce-cli=$docker_pin" containerd.io docker-buildx-plugin
usermod -aG docker "$bench_user"
systemctl enable --now docker
mkdir -p "$bench_root/downloads"
deb="$bench_root/downloads/openshell_0.1.3-1_arm64.deb"
curl -fsSL https://github.com/NVIDIA/OpenShell/releases/download/v0.1.3/openshell_0.1.3-1_arm64.deb -o "$deb"
printf '%s  %s\n' '9ba7075bd293529ce780cf3993bccbab8fa201d8eabc43194a13c60a1ac5f76a' "$deb" | sha256sum -c -
apt-get install -y "$deb"
docker --version
openshell --version
