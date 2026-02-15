 #!/bin/bash
#================================================================
# VPN Multi-Layer Ultimate Enterprise Installer (نسخه ۹.۴)
# با منوی مدیریت کامل، مصرف نیم‌بها، انقضا، آمار لحظه‌ای
# و تخصیص پورت تصادفی به هر کلاینت (غیر تکراری)
#================================================================
set -euo pipefail
IFS=$'\n\t'

# رنگ‌ها
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}" >&2; }
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }
print_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }

#================================================================
# بررسی دسترسی root
#================================================================
[[ $EUID -ne 0 ]] && print_error "این اسکریپت باید با دسترسی root اجرا شود" && exit 1

#================================================================
# متغیرهای سراسری
#================================================================
SCRIPT_DIR="/opt/vpn-multilayer"
CLIENTS_DIR="$SCRIPT_DIR/clients"
KEYS_DIR="$SCRIPT_DIR/keys"
SSL_DIR="/etc/ssl/private"
ACCT_DIR="$SCRIPT_DIR/accounting"
DB_FILE="$SCRIPT_DIR/clients.db"              # پایگاه داده ساده (متن)
DB_LOCK="$DB_FILE.lock"
IPSET_SRC="vpn_clients_src"
IPSET_DST="vpn_clients_dst"
IPSET_BLOCK="vpn_blocked"
IPSET_SRC6="vpn_clients_src6"
IPSET_DST6="vpn_clients_dst6"
IPSET_BLOCK6="vpn_blocked6"
USED_PORTS_FILE="$SCRIPT_DIR/used_ports.txt"
LOG_FILE="$SCRIPT_DIR/vpn.log"
WG_INTERFACE="wg0"
mkdir -p "$SCRIPT_DIR" "$CLIENTS_DIR" "$KEYS_DIR" "$SSL_DIR" "$ACCT_DIR"
touch "$USED_PORTS_FILE" "$LOG_FILE"

# تشخیص نقش سرور (بر اساس فایل کانفیگ)
ROLE_FILE="$SCRIPT_DIR/role.conf"
if [[ -f "$ROLE_FILE" ]]; then
    source "$ROLE_FILE"
else
    ROLE="unknown"
fi

# متغیرهای پیکربندی (در نصب مقدار می‌گیرند)
SERVER_IP=""
INTERFACE=""
WG_UDP_PORT="51820"
HY2PORT="4433"
DOMAIN=""
EMAIL=""
HY2PASS=""
REMOTE_IP=""

#================================================================
# توابع کمکی
#================================================================
validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 -a "$port" -le 65535 ] && return 0
    return 1
}

validate_domain() {
    local domain=$1
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] && return 0
    return 1
}

validate_client_name() {
    local name=$1
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && return 0
    return 1
}

get_public_ip() {
    local ip=""
    ip=$(ip route get 1 | awk '{print $NF;exit}' 2>/dev/null || true)
    if [[ -z "$ip" ]]; then
        ip=$(curl -4 -s --max-time 5 ifconfig.co 2>/dev/null || true)
    fi
    if [[ -z "$ip" ]]; then
        ip=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || true)
    fi
    if [[ -z "$ip" ]]; then
        print_error "تشخیص IP عمومی ممکن نیست. لطفاً به صورت دستی وارد کنید."
        exit 1
    fi
    echo "$ip"
}

install_common_packages() {
    print_info "در حال به‌روزرسانی و نصب پکیج‌های پایه..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y wireguard qrencode socat curl wget iptables iproute2 fail2ban certbot openssl netcat dialog logrotate
    else
        print_error "این اسکریپت فقط بر روی توزیع‌های مبتنی بر دبیان/اوبونتو قابل اجراست."
        exit 1
    fi
}

setup_ip_forwarding() {
    print_info "فعال‌سازی IP forwarding..."
    cat > /etc/sysctl.d/99-vpn.conf << EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-vpn.conf
}

install_hysteria() {
    if ! command -v hysteria &> /dev/null; then
        print_info "در حال نصب Hysteria2..."
        local version=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep tag_name | cut -d '"' -f 4)
        local arch=$(uname -m)
        case $arch in
            x86_64) arch="amd64" ;;
            aarch64) arch="arm64" ;;
            *) print_error "معماری $arch پشتیبانی نمی‌شود."; exit 1 ;;
        esac
        local url="https://github.com/apernet/hysteria/releases/download/$version/hysteria-linux-$arch"
        wget -qO /tmp/hysteria "$url"
        chmod +x /tmp/hysteria
        mv /tmp/hysteria /usr/local/bin/hysteria
        print_success "Hysteria2 نصب شد."
    fi
}

get_ssl_cert() {
    local domain="$1"
    local email="$2"
    local cert_path="$SSL_DIR/vpn.crt"
    local key_path="$SSL_DIR/vpn.key"
    local nginx_active=0 apache_active=0

    systemctl is-active --quiet nginx && nginx_active=1
    systemctl is-active --quiet apache2 && apache_active=1
    systemctl stop nginx apache2 2>/dev/null || true

    if [[ -n "$domain" && "$domain" != "vpn.example.com" ]] && validate_domain "$domain" && [[ -n "$email" ]]; then
        print_info "تلاش برای دریافت گواهی Let's Encrypt برای $domain ..."
        if certbot certonly --standalone --non-interactive --agree-tos --email "$email" --domains "$domain" \
                --cert-path "$cert_path" --key-path "$key_path" &>/dev/null; then
            print_success "گواهی Let's Encrypt دریافت شد."
            [[ $nginx_active -eq 1 ]] && systemctl start nginx
            [[ $apache_active -eq 1 ]] && systemctl start apache2
            return
        else
            print_warn "دریافت گواهی ناموفق بود. ساختن گواهی self-signed..."
        fi
    else
        print_warn "دامنه یا ایمیل معتبر وارد نشده، گواهی self-signed ساخته می‌شود."
    fi

    openssl req -x509 -newkey rsa:4096 -keyout "$key_path" -out "$cert_path" -days 730 -nodes -subj "/CN=${domain:-vpn.local}" &>/dev/null
    chmod 600 "$key_path" "$cert_path"
    print_success "گواهی self-signed ساخته شد."

    [[ $nginx_active -eq 1 ]] && systemctl start nginx
    [[ $apache_active -eq 1 ]] && systemctl start apache2
}

#================================================================
# توابع مدیریت پورت تصادفی برای کلاینت‌ها (با قفل فایل)
#================================================================
generate_random_port() {
    local min=10000
    local max=60000
    local port
    while true; do
        port=$((RANDOM % (max - min + 1) + min))
        if ! grep -q "^$port$" "$USED_PORTS_FILE" 2>/dev/null && ! ss -tuln | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
    done
}

reserve_client_port() {
    local port="$1"
    (
        flock -x 200
        echo "$port" >> "$USED_PORTS_FILE"
        sort -u -o "$USED_PORTS_FILE" "$USED_PORTS_FILE"
    ) 200>"$USED_PORTS_FILE.lock"
}

release_client_port() {
    local port="$1"
    (
        flock -x 200
        sed -i "/^$port$/d" "$USED_PORTS_FILE"
    ) 200>"$USED_PORTS_FILE.lock"
}

cleanup_orphaned_ports() {
    (
        flock -x 200
        local tmp_file=$(mktemp)
        while read -r port; do
            if grep -q ":$port$" "$DB_FILE" 2>/dev/null; then
                echo "$port" >> "$tmp_file"
            fi
        done < "$USED_PORTS_FILE"
        mv "$tmp_file" "$USED_PORTS_FILE"
    ) 200>"$USED_PORTS_FILE.lock"
}

#================================================================
# سیستم مدیریت مصرف با ipset (IPv4 و IPv6)
#================================================================
init_accounting() {
    # IPv4
    ipset create $IPSET_SRC hash:ip counters 2>/dev/null || true
    ipset create $IPSET_DST hash:ip counters 2>/dev/null || true
    ipset create $IPSET_BLOCK hash:ip 2>/dev/null || true

    iptables -N VPN_ACCT 2>/dev/null || true
    iptables -F VPN_ACCT 2>/dev/null || true
    iptables -N VPN_BLOCK 2>/dev/null || true
    iptables -F VPN_BLOCK 2>/dev/null || true

    iptables -D FORWARD -j VPN_BLOCK 2>/dev/null || true
    iptables -I FORWARD -j VPN_BLOCK
    iptables -D FORWARD -j VPN_ACCT 2>/dev/null || true
    iptables -A FORWARD -j VPN_ACCT

    iptables -A VPN_BLOCK -m set --match-set $IPSET_BLOCK src -j DROP
    iptables -A VPN_BLOCK -m set --match-set $IPSET_BLOCK dst -j DROP
    iptables -A VPN_ACCT -m set --match-set $IPSET_SRC src -j ACCEPT
    iptables -A VPN_ACCT -m set --match-set $IPSET_DST dst -j ACCEPT

    # IPv6
    ipset create $IPSET_SRC6 hash:ip family inet6 counters 2>/dev/null || true
    ipset create $IPSET_DST6 hash:ip family inet6 counters 2>/dev/null || true
    ipset create $IPSET_BLOCK6 hash:ip family inet6 2>/dev/null || true

    ip6tables -N VPN_ACCT 2>/dev/null || true
    ip6tables -F VPN_ACCT 2>/dev/null || true
    ip6tables -N VPN_BLOCK 2>/dev/null || true
    ip6tables -F VPN_BLOCK 2>/dev/null || true

    ip6tables -D FORWARD -j VPN_BLOCK 2>/dev/null || true
    ip6tables -I FORWARD -j VPN_BLOCK
    ip6tables -D FORWARD -j VPN_ACCT 2>/dev/null || true
    ip6tables -A FORWARD -j VPN_ACCT

    ip6tables -A VPN_BLOCK -m set --match-set $IPSET_BLOCK6 src -j DROP
    ip6tables -A VPN_BLOCK -m set --match-set $IPSET_BLOCK6 dst -j DROP
    ip6tables -A VPN_ACCT -m set --match-set $IPSET_SRC6 src -j ACCEPT
    ip6tables -A VPN_ACCT -m set --match-set $IPSET_DST6 dst -j ACCEPT

    # ذخیره و بازیابی خودکار ipset
    cat > /etc/systemd/system/ipset-persistent.service << 'EOF'
[Unit]
Description=Restore ipset rules
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/vpn-acct-restore
ExecStop=/usr/local/bin/vpn-acct-save
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ipset-persistent.service

    cat > /usr/local/bin/vpn-acct-save << 'EOF'
#!/bin/bash
ipset save > /etc/ipset.rules
EOF
    chmod +x /usr/local/bin/vpn-acct-save

    cat > /usr/local/bin/vpn-acct-restore << 'EOF'
#!/bin/bash
if [[ -f /etc/ipset.rules ]]; then
    ipset restore < /etc/ipset.rules
fi
EOF
    chmod +x /usr/local/bin/vpn-acct-restore

    /usr/local/bin/vpn-acct-restore
    print_success "سیستم شمارش و مسدودسازی برای IPv4 و IPv6 راه‌اندازی شد."
}

add_client_to_ipset() {
    local client_ip="$1"
    # IPv4
    ipset add $IPSET_SRC $client_ip 2>/dev/null || true
    ipset add $IPSET_DST $client_ip 2>/dev/null || true
    ipset del $IPSET_BLOCK $client_ip 2>/dev/null || true
    # IPv6 (اگر آدرس IPv6 داشته باشیم، اما کلاینت‌ها فقط IPv4 دارند. در صورت نیاز اضافه می‌شود)
    if [[ "$client_ip" == *:* ]]; then
        ipset add $IPSET_SRC6 $client_ip 2>/dev/null || true
        ipset add $IPSET_DST6 $client_ip 2>/dev/null || true
        ipset del $IPSET_BLOCK6 $client_ip 2>/dev/null || true
    fi
}

remove_client_from_ipset() {
    local client_ip="$1"
    ipset del $IPSET_SRC $client_ip 2>/dev/null || true
    ipset del $IPSET_DST $client_ip 2>/dev/null || true
    if [[ "$client_ip" == *:* ]]; then
        ipset del $IPSET_SRC6 $client_ip 2>/dev/null || true
        ipset del $IPSET_DST6 $client_ip 2>/dev/null || true
    fi
}

block_client_ip() {
    local client_ip="$1"
    ipset add $IPSET_BLOCK $client_ip 2>/dev/null || true
    if [[ "$client_ip" == *:* ]]; then
        ipset add $IPSET_BLOCK6 $client_ip 2>/dev/null || true
    fi
    remove_client_from_ipset "$client_ip"
}

# دریافت ترافیک تفکیک‌شده: خروجی "rx_bytes tx_bytes" (مجموع IPv4+IPv6)
get_client_traffic() {
    local ip="$1"
    local rx=0 tx=0
    # IPv4
    local line_src=$(ipset save $IPSET_SRC 2>/dev/null | grep "^add $IPSET_SRC $ip ")
    local line_dst=$(ipset save $IPSET_DST 2>/dev/null | grep "^add $IPSET_DST $ip ")
    if [[ -n "$line_src" ]]; then
        tx=$((tx + $(echo "$line_src" | awk '{for(i=1;i<NF;i++) if($i=="bytes") print $(i+1)}')))
    fi
    if [[ -n "$line_dst" ]]; then
        rx=$((rx + $(echo "$line_dst" | awk '{for(i=1;i<NF;i++) if($i=="bytes") print $(i+1)}')))
    fi
    # IPv6 (اگر آدرس IPv6 باشد)
    if [[ "$ip" == *:* ]]; then
        line_src=$(ipset save $IPSET_SRC6 2>/dev/null | grep "^add $IPSET_SRC6 $ip ")
        line_dst=$(ipset save $IPSET_DST6 2>/dev/null | grep "^add $IPSET_DST6 $ip ")
        if [[ -n "$line_src" ]]; then
            tx=$((tx + $(echo "$line_src" | awk '{for(i=1;i<NF;i++) if($i=="bytes") print $(i+1)}')))
        fi
        if [[ -n "$line_dst" ]]; then
            rx=$((rx + $(echo "$line_dst" | awk '{for(i=1;i<NF;i++) if($i=="bytes") print $(i+1)}')))
        fi
    fi
    echo "$rx $tx"
}

#================================================================
# توابع کار با دیتابیس (با قفل)
#================================================================
with_db_lock() {
    local func="$1"
    shift
    (
        flock -x 200
        $func "$@"
    ) 200>"$DB_LOCK"
}

save_client_to_db() {
    local name="$1" expiry="$2" ip="$3" vol_limit="$4" port="$5"
    local created="$(date +%s)"
    echo "$name:$expiry:$ip:$vol_limit:$created:$port" >> "$DB_FILE"
}

update_client_in_db() {
    local name="$1" expiry="$2" ip="$3" vol_limit="$4" port="$5"
    awk -v name="$name" -F: '$1 != name' "$DB_FILE" > "$DB_FILE.tmp"
    echo "$name:$expiry:$ip:$vol_limit:$(date +%s):$port" >> "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
}

delete_client_from_db() {
    local name="$1"
    local port=$(get_client_port "$name")
    [[ -n "$port" ]] && release_client_port "$port"
    awk -v name="$name" -F: '$1 != name' "$DB_FILE" > "$DB_FILE.tmp"
    mv "$DB_FILE.tmp" "$DB_FILE"
}

get_client_ip() {
    awk -F: -v n="$1" '$1==n {print $3}' "$DB_FILE" | head -1
}

get_client_expiry() {
    awk -F: -v n="$1" '$1==n {print $2}' "$DB_FILE" | head -1
}

get_client_vol_limit() {
    awk -F: -v n="$1" '$1==n {print $4}' "$DB_FILE" | head -1
}

get_client_created() {
    awk -F: -v n="$1" '$1==n {print $5}' "$DB_FILE" | head -1
}

get_client_port() {
    awk -F: -v n="$1" '$1==n {print $6}' "$DB_FILE" | head -1
}

get_client_pubkey() {
    local name="$1"
    local conf="$CLIENTS_DIR/$name/wg.conf"
    if [[ -f "$conf" ]]; then
        awk -F'= ' '/^PublicKey/ {print $2}' "$conf" | head -1
    fi
}

find_free_ip() {
    local subnet="10.0.0"
    local used_ips=$(awk -F: '{print $3}' "$DB_FILE" 2>/dev/null | sort -t. -k4 -n)
    for i in $(seq 2 254); do
        local candidate="$subnet.$i"
        if ! echo "$used_ips" | grep -q -F "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    print_error "فضای آدرس تمام شده است."
    return 1
}

#================================================================
# توابع بررسی وضعیت و اعمال محدودیت
#================================================================
is_client_active() {
    local name="$1"
    local ip=$(get_client_ip "$name")
    [[ -z "$ip" ]] && return 1
    local expiry=$(get_client_expiry "$name")
    local vol_limit=$(get_client_vol_limit "$name")
    local now=$(date +%s)
    if [[ $expiry -ne 0 && $now -gt $expiry ]]; then
        return 1
    fi
    if [[ $vol_limit -ne 0 ]]; then
        local traffic=($(get_client_traffic "$ip"))
        local rx_bytes=${traffic[0]}
        local tx_bytes=${traffic[1]}
        local min_bytes=$(( rx_bytes < tx_bytes ? rx_bytes : tx_bytes ))
        if [[ $min_bytes -ge $vol_limit ]]; then
            return 1
        fi
    fi
    return 0
}

enforce_client() {
    local name="$1"
    if ! is_client_active "$name"; then
        local ip=$(get_client_ip "$name")
        local pubkey=$(get_client_pubkey "$name")
        block_client_ip "$ip"
        if [[ -n "$pubkey" ]]; then
            wg set "$WG_INTERFACE" peer "$pubkey" remove 2>/dev/null || true
        fi
        log_action "کلاینت $name غیرفعال شد (انقضا یا اتمام حجم)"
        return 1
    else
        local ip=$(get_client_ip "$name")
        add_client_to_ipset "$ip"
        return 0
    fi
}

# برای سازگاری با کدهای قبلی
check_client_access() {
    enforce_client "$1"
}

show_client_usage() {
    local name="$1"
    local ip=$(get_client_ip "$name")
    if [[ -z "$ip" ]]; then
        print_error "کلاینت یافت نشد."
        return 1
    fi
    local expiry=$(get_client_expiry "$name")
    local vol_limit=$(get_client_vol_limit "$name")
    local created=$(get_client_created "$name")
    local port=$(get_client_port "$name")
    local traffic=($(get_client_traffic "$ip"))
    local rx_bytes=${traffic[0]}
    local tx_bytes=${traffic[1]}
    local min_bytes=$(( rx_bytes < tx_bytes ? rx_bytes : tx_bytes ))
    local now=$(date +%s)

    echo "----------------------------------------"
    print_info "نام کلاینت: $name"
    print_info "IP: $ip"
    print_info "پورت اختصاصی: ${port:-ندارد}"
    print_info "تاریخ ایجاد: $(date -d @$created)"
    print_info "انقضا: $(if [[ $expiry -eq 0 ]]; then echo "نامحدود"; else date -d @$expiry; fi)"
    if [[ $expiry -ne 0 && $now -gt $expiry ]]; then
        print_warn "⚠️  منقضی شده!"
    fi
    if [[ $vol_limit -eq 0 ]]; then
        print_info "حجم مجاز: نامحدود"
    else
        print_info "حجم مجاز: $(numfmt --to=iec $vol_limit) (نیم‌بها: $(numfmt --to=iec $min_bytes) از $(numfmt --to=iec $vol_limit))"
        if [[ $min_bytes -ge $vol_limit ]]; then
            print_warn "⚠️  حجم مصرف‌شده (نیم‌بها) از حد مجاز گذشته!"
        fi
    fi
    print_info "مصرف دانلود (Rx): $(numfmt --to=iec $rx_bytes)"
    print_info "مصرف آپلود (Tx): $(numfmt --to=iec $tx_bytes)"
    echo "----------------------------------------"
}

#================================================================
# توابع لاگ‌گیری و logrotate
#================================================================
log_action() {
    local msg="$1"
    # مخفی کردن رمز در لاگ
    msg=$(echo "$msg" | sed "s/$HY2PASS/****/g")
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE"
}

setup_logrotate() {
    cat > /etc/logrotate.d/vpn << EOF
$LOG_FILE {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
    print_success "تنظیمات logrotate برای $LOG_FILE اعمال شد."
}

#================================================================
# توابع مدیریت فایروال
#================================================================
open_firewall_ports() {
    local ports=("$@")
    if command -v ufw &>/dev/null && ufw status | grep -q active; then
        for port in "${ports[@]}"; do
            ufw allow "$port" 2>/dev/null && print_info "پورت $port در UFW باز شد."
        done
    elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port="$port" 2>/dev/null
            firewall-cmd --reload 2>/dev/null
            print_info "پورت $port در firewalld باز شد."
        done
    else
        for port in "${ports[@]}"; do
            if [[ $port == *"/"* ]]; then
                proto="${port#*/}"
                portnum="${port%/*}"
            else
                proto="udp"
                portnum="$port"
            fi
            iptables -C INPUT -p "$proto" --dport "$portnum" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p "$proto" --dport "$portnum" -j ACCEPT
            ip6tables -C INPUT -p "$proto" --dport "$portnum" -j ACCEPT 2>/dev/null || \
                ip6tables -I INPUT -p "$proto" --dport "$portnum" -j ACCEPT 2>/dev/null || true
        done
        print_info "قوانین iptables برای پورت‌ها اضافه شد."
    fi
}

#================================================================
# نصب تایمر systemd برای اجرای خودکار بررسی محدودیت‌ها
#================================================================
setup_enforce_timer() {
    cat > /etc/systemd/system/vpn-enforce.service << 'EOF'
[Unit]
Description=VPN Enforce Limits

[Service]
Type=oneshot
ExecStart=/opt/vpn-multilayer/vpn-manager.sh enforce
EOF

    cat > /etc/systemd/system/vpn-enforce.timer << 'EOF'
[Unit]
Description=Run VPN enforce every 5 minutes

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable vpn-enforce.timer
    systemctl start vpn-enforce.timer
    print_success "تایمر اجرای خودکار بررسی محدودیت‌ها (هر ۵ دقیقه) راه‌اندازی شد."
}

#================================================================
# توابع نصب بر اساس نقش
#================================================================
setup_external_server() {
    print_info "===== پیکربندی سرور خارجی ====="
    get_ssl_cert "$DOMAIN" "$EMAIL"
    HY2PASS=${HY2PASS:-$(openssl rand -hex 16)}
    mkdir -p /etc/hysteria
    cat > /etc/hysteria/config.yaml << EOF
listen: :$HY2PORT
tls:
  cert: $SSL_DIR/vpn.crt
  key: $SSL_DIR/vpn.key
auth:
  type: password
  password: $HY2PASS
bandwidth:
  up: 1 gbps
  down: 1 gbps
outbounds:
  - name: internet
    type: direct
EOF
    chmod 600 /etc/hysteria/config.yaml

    cat > /etc/systemd/system/hysteria.service << EOF
[Unit]
Description=Hysteria2 Tunnel Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=always
RestartSec=3
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/hysteria
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria
    systemctl start hysteria

    if systemctl is-active --quiet hysteria; then
        print_success "Hysteria2 روی پورت $HY2PORT راه‌اندازی شد."
    else
        print_error "خطا در راه‌اندازی Hysteria2. لطفاً لاگ‌ها را بررسی کنید."
    fi

    open_firewall_ports "$HY2PORT/udp"

    EXTERNAL_IP=$(get_public_ip)
    {
        echo "HY2PASS=$HY2PASS"
        echo "EXTERNAL_IP=$EXTERNAL_IP"
        echo "HY2PORT=$HY2PORT"
    } > "$SCRIPT_DIR/external_server.info"
    chmod 600 "$SCRIPT_DIR/external_server.info"
    print_warn "پسورد Hysteria را برای سرور داخلی ذخیره کنید: $HY2PASS"
    echo "ROLE=external" > "$ROLE_FILE"
    log_action "سرور خارجی نصب شد با HY2PASS=$HY2PASS"
}

setup_internal_server() {
    print_info "===== پیکربندی سرور داخلی ====="
    if [[ -z "$HY2PASS" ]]; then
        print_error "در حالت internal باید پسورد Hysteria را وارد کنید."
        exit 1
    fi
    WG_PRIV=$(wg genkey)
    WG_PUB=$(echo "$WG_PRIV" | wg pubkey)
    echo "$WG_PUB" > "$KEYS_DIR/wg_public.key"
    echo "$WG_PRIV" > "$KEYS_DIR/wg_private.key"
    chmod 600 "$KEYS_DIR/wg_private.key"

    INTERFACE=${INTERFACE:-$(ip route | grep default | awk '{print $5}' | head -1)}
    if [[ -z "$INTERFACE" ]]; then
        print_error "نتوانستیم اینترفیس شبکه را تشخیص دهیم. لطفاً با --interface وارد کنید"
        exit 1
    fi

    cat > /etc/wireguard/${WG_INTERFACE}.conf << EOF
[Interface]
PrivateKey = $WG_PRIV
Address = 10.0.0.1/24, fd00::1/64
ListenPort = $WG_UDP_PORT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT
EOF
    chmod 600 /etc/wireguard/${WG_INTERFACE}.conf
    systemctl enable wg-quick@${WG_INTERFACE}
    systemctl start wg-quick@${WG_INTERFACE}

    if systemctl is-active --quiet wg-quick@${WG_INTERFACE}; then
        print_success "WireGuard روی پورت $WG_UDP_PORT راه‌اندازی شد."
    else
        print_error "خطا در راه‌اندازی WireGuard."
    fi

    open_firewall_ports "$WG_UDP_PORT/udp"

    mkdir -p /etc/hysteria
    cat > /etc/hysteria/client.yaml << EOF
server: $REMOTE_IP:$HY2PORT
auth: $HY2PASS
tls:
  insecure: true
bandwidth:
  up: 100 mbps
  down: 100 mbps
tun:
  name: hytun
  mtu: 1500
  routes:
    - 0.0.0.0/0
EOF
    chmod 600 /etc/hysteria/client.yaml

    cat > /etc/systemd/system/hysteria-client.service << EOF
[Unit]
Description=Hysteria2 Tunnel Client
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria client -c /etc/hysteria/client.yaml
Restart=always
RestartSec=3
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/hysteria
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-client
    systemctl start hysteria-client

    if systemctl is-active --quiet hysteria-client; then
        print_success "سرویس Hysteria client راه‌اندازی شد."
    else
        print_error "خطا در راه‌اندازی Hysteria client."
    fi
    
    echo "ROLE=internal" > "$ROLE_FILE"
    echo "SERVER_IP=$(get_public_ip)" > "$SCRIPT_DIR/internal_server.info"
    log_action "سرور داخلی نصب شد با HY2PASS=$HY2PASS"
}

#================================================================
# توابع مدیریت کلاینت
#================================================================
add_client() {
    local name="$1" volume_gb="$2" days="$3"
    if [[ -z "$name" || -z "$volume_gb" || -z "$days" ]]; then
        print_error "استفاده: add-client <name> <volume_gb> <days>"
        return 1
    fi
    if ! validate_client_name "$name"; then
        print_error "نام کلاینت باید فقط شامل حروف، اعداد، خط تیره و زیرخط باشد."
        return 1
    fi
    if [[ -d "$CLIENTS_DIR/$name" ]]; then
        print_error "کلاینتی با این نام قبلاً وجود دارد."
        return 1
    fi

    local client_priv=$(wg genkey)
    local client_pub=$(echo "$client_priv" | wg pubkey)
    local client_ip
    client_ip=$(with_db_lock find_free_ip) || return 1
    
    local client_dir="$CLIENTS_DIR/$name"
    mkdir -p "$client_dir"
    
    local expiry=0
    if [[ $days -gt 0 ]]; then
        expiry=$(date -d "+$days days" +%s)
    fi
    local vol_limit_bytes=0
    if [[ $volume_gb -gt 0 ]]; then
        vol_limit_bytes=$((volume_gb * 1024 * 1024 * 1024))
    fi

    local client_port=$(generate_random_port)
    reserve_client_port "$client_port"

    if [[ "$ROLE" == "internal" ]]; then
        local wg_pub=$(cat "$KEYS_DIR/wg_public.key")
        local server_ip=$(cat "$SCRIPT_DIR/internal_server.info" | grep SERVER_IP | cut -d= -f2)
        cat > "$client_dir/wg.conf" << EOF
[Interface]
PrivateKey = $client_priv
Address = $client_ip/32
ListenPort = $client_port
DNS = 1.1.1.1
[Peer]
PublicKey = $wg_pub
Endpoint = $server_ip:$WG_UDP_PORT
AllowedIPs = 0.0.0.0/0, ::/0
EOF
    else
        print_error "افزودن کلاینت فقط روی سرور داخلی ممکن است."
        release_client_port "$client_port"
        return 1
    fi
    
    chmod 600 "$client_dir/wg.conf"
    qrencode -o "$client_dir/wg.png" < "$client_dir/wg.conf"
    
    if ! wg set "$WG_INTERFACE" peer "$client_pub" allowed-ips "${client_ip}/32"; then
        log_action "خطا در اضافه کردن peer $name به WireGuard"
        print_error "خطا در اضافه کردن peer به WireGuard"
        release_client_port "$client_port"
        rm -rf "$client_dir"
        return 1
    fi
    wg-quick save "$WG_INTERFACE"
    
    with_db_lock save_client_to_db "$name" "$expiry" "$client_ip" "$vol_limit_bytes" "$client_port"
    add_client_to_ipset "$client_ip"
    
    log_action "کلاینت $name با حجم $volume_gb GB و مدت $days روز اضافه شد (IP: $client_ip, پورت: $client_port)"
    print_success "کلاینت '$name' ساخته شد."
}

edit_client() {
    local name="$1" new_volume_gb="$2" new_days="$3" new_ip="$4"
    if [[ -z "$name" || -z "$new_volume_gb" || -z "$new_days" ]]; then
        print_error "استفاده: edit-client <name> <new_volume_gb> <new_days> [new_ip]"
        return 1
    fi
    local old_ip=$(get_client_ip "$name")
    local port=$(get_client_port "$name")
    if [[ -z "$old_ip" ]]; then
        print_error "کلاینت یافت نشد."
        return 1
    fi

    # ذخیره وضعیت قبلی برای rollback
    local old_expiry=$(get_client_expiry "$name")
    local old_vol_limit=$(get_client_vol_limit "$name")
    local old_pubkey=$(get_client_pubkey "$name")

    local new_expiry=0
    if [[ $new_days -gt 0 ]]; then
        new_expiry=$(date -d "+$new_days days" +%s)
    fi
    local new_vol_limit=0
    if [[ $new_volume_gb -gt 0 ]]; then
        new_vol_limit=$((new_volume_gb * 1024 * 1024 * 1024))
    fi

    local target_ip="$old_ip"
    if [[ -n "$new_ip" && "$new_ip" != "$old_ip" ]]; then
        if grep -q ":$new_ip:" "$DB_FILE" 2>/dev/null; then
            print_error "آی‌پی $new_ip در حال استفاده است."
            return 1
        fi
        target_ip="$new_ip"
        # به‌روزرسانی peer در WireGuard
        if [[ -n "$old_pubkey" ]]; then
            wg set "$WG_INTERFACE" peer "$old_pubkey" remove || true
            if ! wg set "$WG_INTERFACE" peer "$old_pubkey" allowed-ips "${target_ip}/32"; then
                print_error "خطا در به‌روزرسانی peer. عملیات لغو شد."
                # برگرداندن peer قبلی
                wg set "$WG_INTERFACE" peer "$old_pubkey" allowed-ips "${old_ip}/32" || true
                return 1
            fi
            wg-quick save "$WG_INTERFACE"
        fi
        # به‌روزرسانی ipset
        remove_client_from_ipset "$old_ip"
        add_client_to_ipset "$target_ip"
        block_client_ip "$old_ip"
    fi

    # به‌روزرسانی دیتابیس
    with_db_lock update_client_in_db "$name" "$new_expiry" "$target_ip" "$new_vol_limit" "$port"

    if ! enforce_client "$name"; then
        print_warn "کلاینت پس از ویرایش غیرفعال شد (محدودیت‌ها)."
    fi

    log_action "کلاینت $name ویرایش شد: حجم=$new_volume_gb GB, روز=$new_days, IP=$target_ip"
    print_success "کلاینت '$name' به‌روزرسانی شد."
}

remove_client() {
    local name="$1"
    local ip=$(get_client_ip "$name")
    if [[ -z "$ip" ]]; then
        print_error "کلاینت یافت نشد."
        return 1
    fi
    local pubkey=$(get_client_pubkey "$name")
    if [[ -n "$pubkey" ]]; then
        wg set "$WG_INTERFACE" peer "$pubkey" remove || true
        wg-quick save "$WG_INTERFACE"
    fi
    remove_client_from_ipset "$ip"
    block_client_ip "$ip"
    with_db_lock delete_client_from_db "$name"
    rm -rf "$CLIENTS_DIR/$name"
    log_action "کلاینت $name حذف شد (IP: $ip)"
    print_success "کلاینت '$name' حذف شد."
}

list_clients() {
    if [[ ! -f "$DB_FILE" ]]; then
        print_info "هیچ کلاینتی یافت نشد."
        return
    fi
    printf "%-15s %-15s %-10s %-10s %-10s %-15s\n" "نام" "IP" "پورت" "حجم(GB)" "روزمانده" "وضعیت"
    while IFS=: read -r name expiry ip vol_limit created port; do
        local now=$(date +%s)
        local status="${GREEN}✅ فعال${NC}"
        if ! is_client_active "$name"; then
            status="${RED}❌ غیرفعال${NC}"
        fi
        local days_left="∞"
        if [[ $expiry -ne 0 ]]; then
            days_left=$(( (expiry - now) / 86400 ))
        fi
        local vol_gb=$(( vol_limit / 1024 / 1024 / 1024 ))
        [[ $vol_limit -eq 0 ]] && vol_gb="∞"
        printf "%-15s %-15s %-10s %-10s %-10s %b\n" "$name" "$ip" "$port" "$vol_gb" "$days_left" "$status"
    done < "$DB_FILE"
    echo -e "${NC}"
}

enforce_limits() {
    if [[ ! -f "$DB_FILE" ]]; then
        return
    fi
    local count=0
    while IFS=: read -r name expiry ip vol_limit created port; do
        if ! enforce_client "$name"; then
            ((count++))
        fi
    done < "$DB_FILE"
    cleanup_orphaned_ports
    print_info "بررسی خودکار انجام شد. $count کلاینت غیرفعال شدند."
}

#================================================================
# منوی اصلی با dialog
#================================================================
show_menu() {
    local choice
    while true; do
        choice=$(dialog --clear --backtitle "VPN Multi-Layer Manager" \
                --title "منوی مدیریت" \
                --menu "نقش فعلی: $ROLE\nلطفاً گزینه مورد نظر را انتخاب کنید:" 20 60 14 \
                "1" "نصب و پیکربندی (نقش)" \
                "2" "افزودن کلاینت جدید" \
                "3" "لیست کلاینت‌ها" \
                "4" "نمایش مصرف کلاینت" \
                "5" "ویرایش کلاینت" \
                "6" "حذف کلاینت" \
                "7" "بررسی و اعمال انقضا/حجم (دستی)" \
                "8" "پشتیبان‌گیری" \
                "9" "بازیابی از پشتیبان" \
                "10" "مشاهده آمار کل" \
                "11" "راه‌اندازی مجدد سرویس‌ها" \
                "12" "ویرایش تنظیمات" \
                "13" "پاکسازی پورت‌های یتیم" \
                "0" "خروج" 3>&1 1>&2 2>&3)
        
        case $choice in
            1) install_menu ;;
            2) add_client_menu ;;
            3) list_clients_menu ;;
            4) show_client_usage_menu ;;
            5) edit_client_menu ;;
            6) remove_client_menu ;;
            7) enforce_limits && dialog --msgbox "بررسی دستی انجام شد." 6 40 ;;
            8) backup_menu ;;
            9) restore_menu ;;
            10) show_stats ;;
            11) restart_services ;;
            12) edit_config ;;
            13) cleanup_orphaned_ports && dialog --msgbox "پورت‌های یتیم پاکسازی شدند." 6 40 ;;
            0) break ;;
            *) break ;;
        esac
    done
    clear
}

install_menu() {
    local role
    role=$(dialog --clear --title "نصب و پیکربندی" \
            --menu "نقش سرور را انتخاب کنید:" 15 50 3 \
            "internal" "سرور داخلی (ایران)" \
            "external" "سرور خارجی (خارج)" \
            "back" "بازگشت" 3>&1 1>&2 2>&3)
    [[ "$role" == "back" ]] && return
    
    if [[ "$role" == "external" ]]; then
        exec 3>&1
        values=$(dialog --ok-label "تأیید" --cancel-label "انصراف" \
                --form "پیکربندی سرور خارجی" 15 60 0 \
                "دامنه (اختیاری):" 1 1 "$DOMAIN" 1 25 50 0 \
                "ایمیل (برای Let's Encrypt):" 2 1 "$EMAIL" 2 25 50 0 \
                "پورت Hysteria2:" 3 1 "$HY2PORT" 3 25 10 0 \
                "پورت WireGuard UDP (اختیاری):" 4 1 "$WG_UDP_PORT" 4 25 10 0 \
                "اینترفیس شبکه:" 5 1 "$INTERFACE" 5 25 20 0 2>&1 1>&3)
        exec 3>&-
        if [[ -n "$values" ]]; then
            mapfile -t arr <<< "$values"
            DOMAIN="${arr[0]}"
            EMAIL="${arr[1]}"
            HY2PORT="${arr[2]}"
            WG_UDP_PORT="${arr[3]}"
            INTERFACE="${arr[4]}"
            install_common_packages
            install_hysteria
            setup_ip_forwarding
            setup_external_server
            init_accounting
            setup_enforce_timer
            setup_logrotate
            dialog --msgbox "سرور خارجی با موفقیت نصب شد.\nپسورد Hysteria: $HY2PASS" 8 50
        fi
    elif [[ "$role" == "internal" ]]; then
        exec 3>&1
        values=$(dialog --ok-label "تأیید" --cancel-label "انصراف" \
                --form "پیکربندی سرور داخلی" 15 70 0 \
                "آدرس IP سرور خارجی:" 1 1 "$REMOTE_IP" 1 30 30 0 \
                "پسورد Hysteria (از سرور خارجی):" 2 1 "$HY2PASS" 2 30 30 0 \
                "پورت Hysteria2 سرور خارجی:" 3 1 "$HY2PORT" 3 30 10 0 \
                "پورت WireGuard UDP (برای کاربران):" 4 1 "$WG_UDP_PORT" 4 30 10 0 \
                "اینترفیس شبکه (خروجی به اینترنت):" 5 1 "$INTERFACE" 5 30 20 0 2>&1 1>&3)
        exec 3>&-
        if [[ -n "$values" ]]; then
            mapfile -t arr <<< "$values"
            REMOTE_IP="${arr[0]}"
            HY2PASS="${arr[1]}"
            HY2PORT="${arr[2]}"
            WG_UDP_PORT="${arr[3]}"
            INTERFACE="${arr[4]}"
            install_common_packages
            install_hysteria
            setup_ip_forwarding
            setup_internal_server
            init_accounting
            setup_enforce_timer
            setup_logrotate
            dialog --msgbox "سرور داخلی با موفقیت نصب شد." 6 40
        fi
    fi
}

add_client_menu() {
    exec 3>&1
    values=$(dialog --ok-label "ایجاد" --cancel-label "انصراف" \
            --form "افزودن کلاینت جدید" 10 50 0 \
            "نام کلاینت:" 1 1 "" 1 15 20 0 \
            "حجم (گیگابایت، 0=∞):" 2 1 "0" 2 15 10 0 \
            "مدت اعتبار (روز، 0=∞):" 3 1 "0" 3 15 10 0 2>&1 1>&3)
    exec 3>&-
    if [[ -n "$values" ]]; then
        mapfile -t arr <<< "$values"
        name="${arr[0]}"
        vol="${arr[1]}"
        days="${arr[2]}"
        add_client "$name" "$vol" "$days"
        dialog --msgbox "کلاینت $name ساخته شد.\nفایل کانفیگ در $CLIENTS_DIR/$name" 8 50
    fi
}

edit_client_menu() {
    exec 3>&1
    values=$(dialog --ok-label "ویرایش" --cancel-label "انصراف" \
            --form "ویرایش کلاینت" 12 60 0 \
            "نام کلاینت:" 1 1 "" 1 20 20 0 \
            "حجم جدید (گیگابایت، 0=∞):" 2 1 "0" 2 20 10 0 \
            "مدت اعتبار جدید (روز، 0=∞):" 3 1 "0" 3 20 10 0 \
            "آی‌پی جدید (اختیاری، خالی = بدون تغییر):" 4 1 "" 4 20 15 0 2>&1 1>&3)
    exec 3>&-
    if [[ -n "$values" ]]; then
        mapfile -t arr <<< "$values"
        name="${arr[0]}"
        vol="${arr[1]}"
        days="${arr[2]}"
        new_ip="${arr[3]}"
        edit_client "$name" "$vol" "$days" "$new_ip"
        dialog --msgbox "کلاینت $name ویرایش شد." 6 40
    fi
}

list_clients_menu() {
    local temp=$(mktemp)
    if [[ ! -f "$DB_FILE" ]]; then
        dialog --msgbox "هیچ کلاینتی وجود ندارد." 6 40
        rm -f "$temp"
        return
    fi
    {
        echo "نام | IP | پورت | حجم(GB) | روزمانده | وضعیت"
        while IFS=: read -r name expiry ip vol_limit created port; do
            local now=$(date +%s)
            local status="✅ فعال"
            if ! is_client_active "$name"; then
                status="❌ غیرفعال"
            fi
            local days_left="∞"
            if [[ $expiry -ne 0 ]]; then
                days_left=$(( (expiry - now) / 86400 ))
            fi
            local vol_gb=$(( vol_limit / 1024 / 1024 / 1024 ))
            [[ $vol_limit -eq 0 ]] && vol_gb="∞"
            echo "$name | $ip | $port | $vol_gb | $days_left | $status"
        done < "$DB_FILE"
    } | column -t -s '|' > "$temp"
    dialog --textbox "$temp" 20 70
    rm -f "$temp"
}

show_client_usage_menu() {
    local name
    exec 3>&1
    name=$(dialog --inputbox "نام کلاینت را وارد کنید:" 8 40 2>&1 1>&3)
    exec 3>&-
    if [[ -n "$name" ]]; then
        local temp=$(mktemp)
        show_client_usage "$name" > "$temp" 2>&1
        dialog --textbox "$temp" 15 60
        rm -f "$temp"
    fi
}

remove_client_menu() {
    local name
    exec 3>&1
    name=$(dialog --inputbox "نام کلاینت برای حذف:" 8 40 2>&1 1>&3)
    exec 3>&-
    if [[ -n "$name" ]]; then
        remove_client "$name"
        dialog --msgbox "کلاینت $name حذف شد." 6 40
    fi
}

backup_menu() {
    local backup_file="/tmp/vpn-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$backup_file" -C "$SCRIPT_DIR" . 2>/dev/null
    dialog --msgbox "پشتیبان در $backup_file ایجاد شد." 6 50
}

restore_menu() {
    local file
    exec 3>&1
    file=$(dialog --stdout --title "انتخاب فایل پشتیبان" --fselect /tmp/ 14 48)
    exec 3>&-
    if [[ -f "$file" ]]; then
        tar -xzf "$file" -C "$SCRIPT_DIR"
        dialog --msgbox "بازیابی انجام شد. ممکن است نیاز به راه‌اندازی مجدد سرویس‌ها باشد." 7 50
    fi
}

show_stats() {
    local total_clients=0
    local active_clients=0
    local total_rx=0 total_tx=0
    if [[ -f "$DB_FILE" ]]; then
        total_clients=$(wc -l < "$DB_FILE")
        while IFS=: read -r name expiry ip vol_limit created port; do
            if is_client_active "$name"; then
                ((active_clients++))
            fi
            traffic=($(get_client_traffic "$ip"))
            total_rx=$((total_rx + traffic[0]))
            total_tx=$((total_tx + traffic[1]))
        done < "$DB_FILE"
    fi
    dialog --msgbox "آمار کلی:\nکل کلاینت‌ها: $total_clients\nفعال: $active_clients\nکل دانلود: $(numfmt --to=iec $total_rx)\nکل آپلود: $(numfmt --to=iec $total_tx)" 12 50
}

restart_services() {
    systemctl restart wg-quick@${WG_INTERFACE} hysteria-client hysteria 2>/dev/null || true
    dialog --msgbox "سرویس‌ها راه‌اندازی مجدد شدند." 6 40
}

edit_config() {
    dialog --msgbox "ویرایش دستی فایل‌های کانفیگ:\n$SCRIPT_DIR/" 8 50
}

#================================================================
# راه‌انداز hys
#================================================================
create_launcher() {
    cat > /usr/local/bin/hys << 'EOF'
#!/bin/bash
exec /opt/vpn-multilayer/vpn-manager.sh menu
EOF
    chmod +x /usr/local/bin/hys
    print_success "لانچر hys در /usr/local/bin ایجاد شد."
}

#================================================================
# پردازش خط فرمان
#================================================================
main() {
    local cmd="${1:-}"
    case "$cmd" in
        install)
            ;;
        add-client)
            shift
            add_client "$1" "$2" "$3"
            ;;
        edit-client)
            shift
            edit_client "$1" "$2" "$3" "$4"
            ;;
        remove-client)
            shift
            remove_client "$1"
            ;;
        list)
            list_clients
            ;;
        usage)
            shift
            show_client_usage "$1"
            ;;
        enforce)
            enforce_limits
            ;;
        menu)
            show_menu
            ;;
        *)
            if [[ "$ROLE" == "unknown" ]]; then
                echo "برای شروع، ابتدا نصب را اجرا کنید: $0 menu"
            else
                show_menu
            fi
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'rm -f /tmp/*.tmp 2>/dev/null' EXIT
    if [[ ! -f /usr/local/bin/hys ]]; then
        create_launcher
    fi
    main "$@"
fi
