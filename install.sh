#!/usr/bin/env bash
# ============================================================
# 钓鱼邮件智能分析系统 - 一键安装脚本
# 支持 Debian/Ubuntu（apt）与 CentOS/RHEL/Rocky/Alma（yum/dnf）
# 用法：sudo bash install.sh
# ============================================================
set -e

INSTALL_DIR="/opt/phishing-email-analysis-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 颜色输出
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; }

# 默认配置
DB_NAME="phishing_agent"
DB_USER="phishing"
DB_PASS=""
REDIS_PASS=""

# ------------------------------------------------------------
# 检查 root 权限
# ------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    err "请使用 root 权限运行：sudo bash install.sh"
    exit 1
fi

# ------------------------------------------------------------
# 检测操作系统与包管理器
# ------------------------------------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
    else
        OS_ID="unknown"
    fi
    case "$OS_ID" in
        ubuntu|debian|linuxmint|kali)
            PKG="apt"
            ;;
        centos|rhel|fedora|rocky|almalinux|ol|openEuler|anolis)
            if command -v dnf >/dev/null 2>&1; then
                PKG="dnf"
            else
                PKG="yum"
            fi
            ;;
        *)
            warn "未识别的操作系统：$OS_ID，将尝试自动判断"
            if command -v apt-get >/dev/null 2>&1; then PKG="apt"
            elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
            elif command -v yum >/dev/null 2>&1; then PKG="yum"
            else PKG="unknown"; fi
            ;;
    esac
    info "检测到操作系统：$OS_ID（包管理器：$PKG）"
}

# ------------------------------------------------------------
# 交互式收集配置
# ------------------------------------------------------------
collect_config() {
    echo ""
    echo "=============================================="
    echo "  钓鱼邮件智能分析系统 - 安装配置"
    echo "=============================================="

    # 支持通过环境变量非交互传入密码（便于自动化部署）
    if [ -n "${DB_PASSWORD:-}" ]; then
        DB_PASS="$DB_PASSWORD"
        info "使用环境变量 DB_PASSWORD 中的数据库密码"
    else
        read -rp "请输入应用数据库密码（用户 ${DB_USER}，留空则自动生成）: " DB_PASS || true
        if [ -z "$DB_PASS" ]; then
            DB_PASS="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
            info "已自动生成数据库密码：${DB_PASS}（请牢记）"
        fi
    fi

    if [ -n "${REDIS_PASSWORD:-}" ]; then
        REDIS_PASS="$REDIS_PASSWORD"
        info "使用环境变量 REDIS_PASSWORD 中的 Redis 密码"
    else
        read -rp "请输入 Redis 密码（留空表示 Redis 不设密码，仅本机访问）: " REDIS_PASS || true
    fi
    echo ""
}

# ------------------------------------------------------------
# 安装系统依赖
# ------------------------------------------------------------
install_packages() {
    info "正在安装系统依赖（Python3 / MariaDB / Redis / Nginx）..."
    case "$PKG" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y python3 python3-venv python3-pip \
                mariadb-server redis-server nginx \
                build-essential libssl-dev libffi-dev
            ;;
        yum)
            yum install -y epel-release || true
            yum install -y python3 python3-pip mariadb-server redis nginx \
                gcc openssl-devel libffi-devel
            ;;
        dnf)
            dnf install -y epel-release || true
            dnf install -y python3 python3-pip mariadb-server redis nginx \
                gcc openssl-devel libffi-devel
            ;;
        *)
            err "不支持自动安装依赖，请手动安装 Python3 / MariaDB / Redis / Nginx 后重试"
            exit 1
            ;;
    esac
    info "系统依赖安装完成"
}

# ------------------------------------------------------------
# 启动并启用数据库与 Redis 服务
# ------------------------------------------------------------
start_services() {
    info "正在启动数据库与 Redis 服务..."

    # 启动数据库（兼容 mariadb / mysql / mysqld 服务名）
    if systemctl list-unit-files 2>/dev/null | grep -qE '^mariadb\.service'; then
        systemctl enable --now mariadb >/dev/null 2>&1 || true
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^mysql\.service'; then
        systemctl enable --now mysql >/dev/null 2>&1 || true
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^mysqld\.service'; then
        systemctl enable --now mysqld >/dev/null 2>&1 || true
    else
        warn "未检测到数据库服务，跳过启动"
    fi

    # 启动 Redis（兼容 redis-server / redis 服务名）
    if systemctl list-unit-files 2>/dev/null | grep -qE '^redis-server\.service'; then
        systemctl enable --now redis-server >/dev/null 2>&1 || true
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^redis\.service'; then
        systemctl enable --now redis >/dev/null 2>&1 || true
    else
        warn "未检测到 Redis 服务，跳过启动"
    fi

    # 等待数据库就绪
    sleep 3
}

# ------------------------------------------------------------
# 数据库 root 执行（跨发行版兼容）
# ------------------------------------------------------------
mysql_root_exec() {
    local sql="$1"

    # 方式一：Debian/Ubuntu 的 unix_socket 免密（sudo mysql）
    if command -v sudo >/dev/null 2>&1 && sudo -n mysql -e "SELECT 1" >/dev/null 2>&1; then
        echo "$sql" | sudo mysql
        return 0
    fi

    # 方式二：空密码 root
    if mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
        echo "$sql" | mysql -u root
        return 0
    fi

    # 方式三：交互输入 root 密码
    local root_pass=""
    read -rsp "自动建库需要数据库 root 密码，请输入（留空跳过自动建库）: " root_pass || true
    echo ""
    if [ -n "$root_pass" ]; then
        echo "$sql" | mysql -u root -p"$root_pass"
        return 0
    fi
    return 1
}

# ------------------------------------------------------------
# 创建数据库与用户
# ------------------------------------------------------------
setup_database() {
    info "正在创建数据库 ${DB_NAME} 与用户 ${DB_USER}..."

    # 转义密码中的单引号
    local pass_esc
    pass_esc="$(printf '%s' "$DB_PASS" | sed "s/'/\\\\'/g")"

    local sql="
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${pass_esc}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${pass_esc}';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${pass_esc}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${pass_esc}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
"
    if mysql_root_exec "$sql"; then
        info "数据库与用户创建成功"
    else
        warn "自动建库失败，请手动创建数据库 ${DB_NAME} 并授权给用户 ${DB_USER}"
    fi
}

# ------------------------------------------------------------
# 配置 Redis 密码（可选）
# ------------------------------------------------------------
setup_redis() {
    if [ -z "$REDIS_PASS" ]; then
        info "Redis 使用无密码模式（仅本机访问）"
        return
    fi

    local conf=""
    for f in /etc/redis/redis.conf /etc/redis.conf; do
        [ -f "$f" ] && conf="$f" && break
    done
    if [ -n "$conf" ]; then
        sed -i "s/^#\?[[:space:]]*requirepass.*/requirepass ${REDIS_PASS}/" "$conf"
        systemctl restart redis-server >/dev/null 2>&1 || systemctl restart redis >/dev/null 2>&1 || true
        info "Redis 密码已配置"
    else
        warn "未找到 Redis 配置文件，请手动设置 requirepass"
    fi
}

# ------------------------------------------------------------
# 复制源码到安装目录
# ------------------------------------------------------------
copy_source() {
    info "正在复制项目文件到 ${INSTALL_DIR}..."
    install -d "$INSTALL_DIR"

    if command -v rsync >/dev/null 2>&1; then
        rsync -a \
            --exclude 'venv' --exclude '.venv' --exclude '.git' \
            --exclude '__pycache__' --exclude 'build' --exclude 'dist' \
            --exclude '*.pyc' --exclude '*.exe' --exclude '*.spec' \
            --exclude 'log' --exclude 'logs' --exclude '.env' \
            "$SCRIPT_DIR/" "$INSTALL_DIR/"
    else
        cp -a "$SCRIPT_DIR/." "$INSTALL_DIR/"
        rm -rf "$INSTALL_DIR/venv" "$INSTALL_DIR/.venv" "$INSTALL_DIR/.git" \
               "$INSTALL_DIR/build" "$INSTALL_DIR/dist" "$INSTALL_DIR/log" "$INSTALL_DIR/logs"
        find "$INSTALL_DIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
        find "$INSTALL_DIR" -name '*.pyc' -delete 2>/dev/null || true
    fi
    info "项目文件复制完成"
}

# ------------------------------------------------------------
# 创建 Python 虚拟环境并安装依赖
# ------------------------------------------------------------
setup_python() {
    info "正在创建 Python 虚拟环境并安装依赖..."
    python3 -m venv "$INSTALL_DIR/venv"

    # 默认使用国内 PyPI 镜像（海外环境可设置 PIP_INDEX_URL=https://pypi.org/simple 覆盖）
    PIP_INDEX="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"

    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip -i "$PIP_INDEX" >/dev/null
    "$INSTALL_DIR/venv/bin/pip" install -i "$PIP_INDEX" -r "$INSTALL_DIR/requirements.txt"
    info "Python 依赖安装完成"
}

# ------------------------------------------------------------
# 生成 .env 环境变量文件
# ------------------------------------------------------------
write_env() {
    info "正在生成 .env 配置文件..."
    cat > "$INSTALL_DIR/.env" <<EOF
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=${DB_USER}
MYSQL_PASSWORD=${DB_PASS}
MYSQL_DATABASE=${DB_NAME}
MYSQL_CHARSET=utf8mb4
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASS}
REDIS_DB=0
EOF
    chmod 600 "$INSTALL_DIR/.env"
    info ".env 配置文件已生成"
}

# ------------------------------------------------------------
# 配置 systemd 服务
# ------------------------------------------------------------
setup_service() {
    info "正在配置 systemd 服务..."
    cp "$INSTALL_DIR/deploy/phishing-agent.service" /etc/systemd/system/phishing-agent.service
    sed -i "s|/opt/phishing-email-analysis-system|$INSTALL_DIR|g" /etc/systemd/system/phishing-agent.service
    systemctl daemon-reload
    systemctl enable --now phishing-agent
    info "systemd 服务已配置并启动"
}

# ------------------------------------------------------------
# 配置 Nginx 反向代理
# ------------------------------------------------------------
setup_nginx() {
    info "正在配置 Nginx 反向代理..."
    # 禁用默认站点，避免 80 端口冲突
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

    cp "$INSTALL_DIR/deploy/nginx.conf" /etc/nginx/conf.d/phishing-agent.conf
    nginx -t >/dev/null 2>&1 && systemctl enable --now nginx && systemctl reload nginx || true
    info "Nginx 反向代理已配置（80 端口 -> 8080）"
}

# ------------------------------------------------------------
# 主流程
# ------------------------------------------------------------
main() {
    detect_os
    collect_config
    install_packages
    start_services
    setup_database
    setup_redis
    copy_source
    setup_python
    write_env
    setup_service
    setup_nginx

    echo ""
    echo "=============================================="
    echo -e "${GREEN}  安装完成！${NC}"
    echo "=============================================="
    echo "  访问地址：http://<服务器IP>"
    echo "  默认管理员账号：admin"
    echo "  默认管理员密码：admin"
    echo "  （首次登录后请立即修改默认密码）"
    echo ""
    echo "  数据库名：${DB_NAME}"
    echo "  数据库用户：${DB_USER}"
    echo "  数据库密码：${DB_PASS}"
    [ -n "$REDIS_PASS" ] && echo "  Redis 密码：${REDIS_PASS}"
    echo ""
    echo "  常用命令："
    echo "    查看服务状态：systemctl status phishing-agent"
    echo "    查看应用日志：journalctl -u phishing-agent -f"
    echo "    重启服务：systemctl restart phishing-agent"
    echo "=============================================="
}

main "$@"
