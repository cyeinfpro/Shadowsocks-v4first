#!/bin/bash

#=====================================================
#   Xray 多入站、多出站管理脚本（含卸载 Xray 选项）
#   - Shadowsocks 默认端口 28001, Socks5 入站默认 55555
#   - 添加入站时检查端口冲突
#   - 添加入站时可选 IPv4 优先
#   - 代理链出站：仅对指定 inbound（删除原出站规则后添加新的）
#   - 删除 代理链出站 时，自动还原 IPv4 优先
#   - 在删除各项时，列出现有资源供用户选择数字，而非手动输入 tag
#=====================================================

set -euo pipefail
IFS=$'\n\t'

# 全局变量
CONFIG_JSON="/usr/local/etc/xray/config.json"
TMP_CONFIG=$(mktemp)
LOG_FILE="/var/log/xray_manager.log"
DISTRO=""
LANGUAGE=${LANG:-"zh"} # 支持通过环境变量设置语言

# 颜色定义
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

# 日志函数
log() {
    local message="$1"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $message" | tee -a "$LOG_FILE"
}

# 清理临时文件
cleanup() {
    rm -f "$TMP_CONFIG"
}
trap cleanup EXIT

# 检查是否以 root 运行
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log "${RED}错误:${NC} 请以 root 用户运行此脚本。"
        exit 1
    fi
}

# 检测发行版
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
    else
        DISTRO=$(uname -s)
    fi
    log "检测到的发行版：$DISTRO"
}

# 安装依赖
install_dependencies() {
    log "安装依赖：jq, curl, iproute2..."
    case "$DISTRO" in
        ubuntu|debian)
            apt-get update && apt-get install -y jq curl iproute2
            ;;
        centos|rhel)
            yum install -y epel-release
            yum install -y jq curl iproute
            ;;
        arch)
            pacman -Sy --noconfirm jq curl iproute2
            ;;
        *)
            log "${RED}错误:${NC} 不支持的发行版：$DISTRO"
            exit 1
            ;;
    esac
}

# 生成随机密码
generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

# 初始化 config.json
init_config() {
    mkdir -p "$(dirname "$CONFIG_JSON")"
    if [[ ! -f "$CONFIG_JSON" ]]; then
        log "初始化配置文件：$CONFIG_JSON"
        cat <<EOF > "$CONFIG_JSON"
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [],
  "outbounds": [],
  "dns": {
    "servers": [
      "8.8.8.8",
      "1.1.1.1"
    ]
  }
}
EOF
        secure_config
    fi
}

# 设置配置文件权限
secure_config() {
    chmod 600 "$CONFIG_JSON"
    chown root:root "$CONFIG_JSON"
    log "已设置配置文件权限为600，所有者为root。"
}

# 安装 Xray
install_xray_if_needed() {
    if ! command -v xray >/dev/null 2>&1; then
        log "安装 Xray..."
        bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
        systemctl enable xray
        log "Xray 安装完成。"
    else
        log "Xray 已安装。"
    fi
}

# 检测端口是否冲突
port_conflict_check() {
    local port=$1
    jq -r '.inbounds[].port // empty' "$CONFIG_JSON" | grep -qw "$port"
}

# 设置或重置 IPv4 优先
set_ipv4_priority() {
    local enable_ipv4="$1"
    if [[ "$enable_ipv4" == "true" ]]; then
        jq '.outbounds = [
            {
                "tag": "IP4",
                "protocol": "freedom",
                "settings": { "domainStrategy": "UseIPv4" }
            },
            {
                "tag": "IP6",
                "protocol": "freedom",
                "settings": { "domainStrategy": "UseIPv6" }
            }
        ]' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

        jq '.routing = {
            "domainStrategy":"IPIfNonMatch",
            "rules":[
                {
                    "type":"field",
                    "outboundTag":"IP4",
                    "network":"tcp,udp"
                },
                {
                    "type":"field",
                    "ip":["::/0"],
                    "outboundTag":"IP6"
                }
            ]
        }' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

        log "已启用 IPv4 优先。"
    else
        jq '.outbounds = [{"protocol":"freedom","settings":{}}] | del(.routing)' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"
        log "已禁用 IPv4 优先。"
    fi
}

# 验证 Xray 配置
validate_config() {
    if ! xray -test -c "$CONFIG_JSON"; then
        log "${RED}错误:${NC} Xray 配置文件无效。"
        restore_config
        return 1
    fi
    return 0
}

# 重启 Xray
restart_xray() {
    systemctl restart xray
    log "已重启 Xray 服务。"
}

# 备份配置
backup_config() {
    local timestamp
    timestamp=$(date '+%Y%m%d_%H%M%S')
    cp "$CONFIG_JSON" "${CONFIG_JSON}.bak_${timestamp}"
    log "已备份当前配置到 ${CONFIG_JSON}.bak_${timestamp}"
}

# 恢复配置
restore_config() {
    local backup_file
    backup_file=$(ls "${CONFIG_JSON}.bak_"* 2>/dev/null | sort | tail -n1)
    if [[ -f "$backup_file" ]]; then
        cp "$backup_file" "$CONFIG_JSON"
        log "已从备份恢复配置：$backup_file"
    else
        log "${RED}错误:${NC} 未找到可用的备份文件，无法恢复。"
    fi
}

# 通用添加 inbound 函数
add_inbound() {
    local protocol=$1
    local port=$2
    local tag=$3
    local settings=$4

    jq --arg inbound_tag "$tag" --argjson port "$port" --argjson settings "$settings" '
        .inbounds += [{
            "tag": $inbound_tag,
            "port": $port,
            "listen": "0.0.0.0",
            "protocol": $protocol,
            "settings": $settings,
            "sniffing": {
                "enabled": true,
                "destOverride": ["http","tls"]
            }
        }]
    ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"
}

# 通用删除 inbound 函数
remove_inbound() {
    local tag=$1
    jq --arg tag "$tag" 'del(.inbounds[] | select(.tag == $tag))' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"
}

# 自动选择可用端口
find_available_port() {
    local start_port=$1
    local end_port=$2
    for (( port=start_port; port<=end_port; port++ )); do
        if ! port_conflict_check "$port" && ! ss -lnt | grep -qw ":$port "; then
            echo "$port"
            return
        fi
    done
    echo ""
}

# Shadowsocks 入站管理
add_shadowsocks_inbound() {
    local supported_methods=("aes-256-gcm" "aes-128-gcm" "chacha20-ietf-poly1305" "xchacha20-ietf-poly1305" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305" "aes-256-cfb" "aes-128-cfb" "aes-256-ctr" "rc4-md5")

    while true; do
        read -rp "请输入 Shadowsocks 入站端口（默认 28001，输入 0 返回上一级）： " port_input
        if [[ "$port_input" == "0" ]]; then
            return
        fi
        if [[ -z "$port_input" ]]; then
            port=$(find_available_port 20000 30000)
            if [[ -z "$port" ]]; then
                log "${RED}错误:${NC} 未找到可用端口，请手动输入。"
                continue
            fi
            log "自动分配端口：$port"
        else
            port="$port_input"
            if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port <= 0 || port > 65535 )); then
                log "${RED}错误:${NC} 端口号无效。"
                continue
            fi
            if port_conflict_check "$port"; then
                log "${RED}错误:${NC} 端口冲突！当前Xray已使用端口$port。"
                continue
            fi
        fi

        read -rp "请输入 Shadowsocks 密码（留空生成随机密码，输入 0 返回上一级）： " password
        if [[ "$password" == "0" ]]; then
            return
        fi
        password=${password:-$(generate_password)}

        echo "请选择 Shadowsocks 加密方式："
        for i in "${!supported_methods[@]}"; do
            echo "$((i+1)). ${supported_methods[$i]}"
        done
        echo "0. 返回上一级"

        local method_choice method
        while true; do
            read -rp "请输入选项（0-${#supported_methods[@]}，默认1）： " method_choice
            method_choice=${method_choice:-1}
            if [[ "$method_choice" == "0" ]]; then
                return
            fi
            if ! [[ "$method_choice" =~ ^[0-9]+$ ]] || (( method_choice < 1 || method_choice > ${#supported_methods[@]} )); then
                log "${RED}错误:${NC} 请输入有效选项。"
                continue
            fi
            method="${supported_methods[$((method_choice-1))]}"
            break
        done

        read -rp "是否启用 IPv4 优先？(y/n，默认 y)： " ipv4_choice
        ipv4_choice=${ipv4_choice:-y}
        if [[ "$ipv4_choice" =~ ^[Yy]$ ]]; then
            set_ipv4_priority "true"
        else
            set_ipv4_priority "false"
        fi

        local inbound_tag="ss-inbound-$port"

        # 准备设置
        local settings
        settings=$(jq -n --arg method "$method" --arg password "$password" '
            {
                "method": $method,
                "password": $password,
                "network": "tcp,udp"
            }
        ')

        # 备份配置
        backup_config

        # 添加入站
        add_inbound "shadowsocks" "$port" "$inbound_tag" "$settings"

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "已添加 Shadowsocks 入站：port=$port, password=***, method=$method, tag=$inbound_tag"
        return
    done
}

remove_shadowsocks_inbound() {
    local ss_inbounds
    ss_inbounds=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .tag' "$CONFIG_JSON")

    if [[ -z "$ss_inbounds" ]]; then
        log "当前没有任何 Shadowsocks 入站。"
        return
    fi

    IFS=$'\n' read -rd '' -a ss_array <<< "$ss_inbounds"
    echo "---------- Shadowsocks 入站列表 ----------"
    for i in "${!ss_array[@]}"; do
        echo "$((i+1)). ${ss_array[$i]}"
    done
    echo "0. 返回上一级"
    echo "-----------------------------------------"

    while true; do
        read -rp "请选择要删除的 Shadowsocks 入站（数字）： " choice
        if [[ "$choice" == "0" ]]; then
            return
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#ss_array[@]} )); then
            log "${RED}错误:${NC} 无效选项。"
            continue
        fi

        local del_tag="${ss_array[$((choice-1))]}"
        # 备份配置
        backup_config

        # 删除入站
        remove_inbound "$del_tag"

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "Shadowsocks 入站 [$del_tag] 已删除。"
        return
    done
}

# Socks5 入站管理
add_socks_inbound() {
    while true; do
        read -rp "请输入 Socks5 入站端口（默认 55555，输入 0 返回）： " port_input
        if [[ "$port_input" == "0" ]]; then
            return
        fi
        if [[ -z "$port_input" ]]; then
            port=$(find_available_port 30000 40000)
            if [[ -z "$port" ]]; then
                log "${RED}错误:${NC} 未找到可用端口，请手动输入。"
                continue
            fi
            log "自动分配端口：$port"
        else
            port="$port_input"
            if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port <= 0 || port > 65535 )); then
                log "${RED}错误:${NC} 端口号无效。"
                continue
            fi
            if port_conflict_check "$port"; then
                log "${RED}错误:${NC} 端口冲突！当前Xray已使用端口$port。"
                continue
            fi
        fi

        read -rp "是否启用 IPv4 优先？(y/n，默认 y)： " ipv4_choice
        ipv4_choice=${ipv4_choice:-y}
        if [[ "$ipv4_choice" =~ ^[Yy]$ ]]; then
            set_ipv4_priority "true"
        else
            set_ipv4_priority "false"
        fi

        local inbound_tag="socks-inbound-$port"
        read -rp "是否需要用户名密码认证？(y/n，默认 n)： " auth_choice
        auth_choice=${auth_choice:-n}

        local auth_config
        if [[ "$auth_choice" =~ ^[Yy]$ ]]; then
            read -rp "请输入用户名：" s5_user
            read -srp "请输入密码：" s5_pass
            echo
            auth_config=$(jq -n --arg user "$s5_user" --arg pass "$s5_pass" '
                {
                    "auth": "password",
                    "accounts": [{ "user": $user, "pass": $pass }],
                    "udp": true
                }
            ')
        else
            auth_config='{"auth":"noauth","udp":true}'
        fi

        # 备份配置
        backup_config

        # 添加入站
        jq --arg inbound_tag "$inbound_tag" --argjson port "$port" --argjson auth_settings "$auth_config" '
            .inbounds += [{
                "tag": $inbound_tag,
                "port": $port,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "settings": $auth_settings,
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http","tls"]
                }
            }]
        ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "已添加 Socks5 入站：port=$port, tag=$inbound_tag"
        return
    done
}

remove_socks_inbound() {
    local s5_inbounds
    s5_inbounds=$(jq -r '.inbounds[] | select(.protocol=="socks") | .tag' "$CONFIG_JSON")

    if [[ -z "$s5_inbounds" ]]; then
        log "当前没有任何 Socks5 入站。"
        return
    fi

    IFS=$'\n' read -rd '' -a s5_array <<< "$s5_inbounds"
    echo "---------- Socks5 入站列表 ----------"
    for i in "${!s5_array[@]}"; do
        echo "$((i+1)). ${s5_array[$i]}"
    done
    echo "0. 返回上一级"
    echo "-------------------------------------"

    while true; do
        read -rp "请选择要删除的 Socks5 入站（数字）： " choice
        if [[ "$choice" == "0" ]]; then
            return
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#s5_array[@]} )); then
            log "${RED}错误:${NC} 无效选项。"
            continue
        fi

        local del_tag="${s5_array[$((choice-1))]}"
        # 备份配置
        backup_config

        # 删除入站
        remove_inbound "$del_tag"

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "Socks5 入站 [$del_tag] 已删除。"
        return
    done
}

# 代理链出站管理
add_socks_outbound() {
    while true; do
        read -rp "为新代理链出站指定一个 tag（例：my-s5-out，输入0返回）： " out_tag
        if [[ "$out_tag" == "0" ]]; then
            return
        fi
        if [[ -z "$out_tag" ]]; then
            log "${RED}错误:${NC} tag 不能为空。"
            continue
        fi

        read -rp "外部 S5 服务器地址（IP/域名）： " s5_addr
        if [[ -z "$s5_addr" ]]; then
            log "${RED}错误:${NC} 地址不能为空。"
            continue
        fi
        read -rp "外部 S5 服务器端口（默认1080）： " s5_port
        s5_port=${s5_port:-1080}
        if ! [[ "$s5_port" =~ ^[0-9]+$ ]] || (( s5_port <= 0 || s5_port > 65535 )); then
            log "${RED}错误:${NC} 端口无效。"
            continue
        fi

        read -rp "是否需要用户名密码认证？(y/n，默认 n)： " s5_auth_choice
        s5_auth_choice=${s5_auth_choice:-n}
        local s5_auth=''
        if [[ "$s5_auth_choice" =~ ^[Yy]$ ]]; then
            read -rp "S5 用户名：" s5_user
            read -srp "S5 密码：" s5_pass
            echo
            s5_auth=$(jq -n --arg user "$s5_user" --arg pass "$s5_pass" '{user:$user,pass:$pass}')
        fi

        # 备份配置
        backup_config

        if [[ -n "$s5_auth" ]]; then
            jq --arg out_tag "$out_tag" --arg s5_addr "$s5_addr" --argjson s5_port "$s5_port" --argjson s5_auth "$s5_auth" '
                .outbounds += [{
                    "tag": $out_tag,
                    "protocol": "socks",
                    "settings": {
                        "servers": [{
                            "address": $s5_addr,
                            "port": $s5_port,
                            "users": [$s5_auth]
                        }]
                    }
                }]
            ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"
        else
            jq --arg out_tag "$out_tag" --arg s5_addr "$s5_addr" --argjson s5_port "$s5_port" '
                .outbounds += [{
                    "tag": $out_tag,
                    "protocol": "socks",
                    "settings": {
                        "servers": [{
                            "address": $s5_addr,
                            "port": $s5_port
                        }]
                    }
                }]
            ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"
        fi

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        # 选择要路由的 inbound
        local inbound_tags
        inbound_tags=$(jq -r '.inbounds[].tag // empty' "$CONFIG_JSON")
        if [[ -z "$inbound_tags" ]]; then
            log "当前没有任何 inbound，无法路由。"
            echo "如果之后添加 inbound，再自行编辑 routing。"
        else
            echo "========== 请选择要路由到该代理链出站的 inbound =========="
            IFS=$'\n' read -rd '' -a inbound_array <<< "$inbound_tags"

            for i in "${!inbound_array[@]}"; do
                echo "$((i+1)). ${inbound_array[$i]}"
            done
            echo "0. 不设置路由（以后手动改）"
            echo "--------------------------------------------"
            read -rp "请输入要路由的 inbound 序号(可用逗号分隔多个): " selected_indexes

            if [[ "$selected_indexes" != "0" ]]; then
                IFS=',' read -ra idx_arr <<< "$selected_indexes"
                for idx in "${idx_arr[@]}"; do
                    idx=$(echo "$idx" | xargs)
                    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
                        log "${RED}错误:${NC} 无效序号: $idx"
                        continue
                    fi
                    ((idx--))
                    if (( idx < 0 || idx >= ${#inbound_array[@]} )); then
                        log "${RED}错误:${NC} 序号越界: $((idx+1))"
                        continue
                    fi
                    local inbound_tag="${inbound_array[$idx]}"

                    # 删除已有相关规则
                    jq --arg inbound_tag "$inbound_tag" '
                        .routing.rules |= map(select(.inboundTag | index($inbound_tag) | not))
                    ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

                    # 添加新的路由规则
                    jq --arg inbound_tag "$inbound_tag" --arg out_tag "$out_tag" '
                        .routing.rules += [{
                            "type": "field",
                            "inboundTag": [$inbound_tag],
                            "outboundTag": $out_tag
                        }]
                    ' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

                    log "已为 inbound [$inbound_tag] 添加路由到 outbound [$out_tag]。"
                done
            fi
        fi

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "已添加 代理链出站(tag=$out_tag)，地址：$s5_addr:$s5_port。"
        return
    done
}

remove_socks_outbound() {
    local outbound_list
    outbound_list=$(jq -r '.outbounds[] | select(.protocol=="socks") | .tag' "$CONFIG_JSON")

    if [[ -z "$outbound_list" ]]; then
        log "当前没有任何 代理链出站。"
        return
    fi

    IFS=$'\n' read -rd '' -a s5_out_array <<< "$outbound_list"
    echo "------- 代理链出站列表 -------"
    for i in "${!s5_out_array[@]}"; do
        echo "$((i+1)). ${s5_out_array[$i]}"
    done
    echo "0. 返回上一级"
    echo "-----------------------------"

    while true; do
        read -rp "请选择要删除的 代理链出站（数字）： " choice
        if [[ "$choice" == "0" ]]; then
            return
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#s5_out_array[@]} )); then
            log "${RED}错误:${NC} 无效选项。"
            continue
        fi

        local del_tag="${s5_out_array[$((choice-1))]}"
        # 备份配置
        backup_config

        # 删除 outbound
        jq --arg del_tag "$del_tag" 'del(.outbounds[] | select(.tag == $del_tag))' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

        # 删除对应的 routing 规则
        jq --arg del_tag "$del_tag" 'del(.routing.rules[]? | select(.outboundTag == $del_tag))' "$CONFIG_JSON" > "$TMP_CONFIG" && mv "$TMP_CONFIG" "$CONFIG_JSON"

        # 还原 IPv4 优先
        set_ipv4_priority "true"

        # 读取更新后的配置
        CONFIG_CONTENT=$(<"$CONFIG_JSON")

        if ! validate_config; then
            log "${RED}错误:${NC} 配置验证失败，已恢复备份。"
            return
        fi

        restart_xray
        log "代理链出站 [$del_tag] 已删除，并已恢复 IPv4 优先。"
        return
    done
}

# 网络优化
optimize_network() {
    echo "即将进行网络优化，会修改 /etc/sysctl.conf 文件。"
    read -rp "确认进行？(y/n，默认n)： " choice
    choice=${choice:-n}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        backup_config
        local timestamp
        timestamp=$(date '+%Y%m%d_%H%M%S')
        cp /etc/sysctl.conf /etc/sysctl.conf.bak_${timestamp}
        log "已备份 /etc/sysctl.conf 至 /etc/sysctl.conf.bak_${timestamp}。"

        # 定义优化参数
        read -r -d '' sysctl_params <<EOF
# 网络优化参数
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.tcp_frto=0
net.ipv4.tcp_mtu_probing=0
net.ipv4.tcp_rfc1337=0
net.ipv4.tcp_sack=1
net.ipv4.tcp_fack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=-2
net.ipv4.tcp_moderate_rcvbuf=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=8192 262144 536870912
net.ipv4.tcp_wmem=4096 16384 536870912
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

        # 移除旧参数
        sed -i '/^# 网络优化参数$/,/^net\.ipv4\.tcp_congestion_control=bbr$/d' /etc/sysctl.conf

        # 添加新参数
        echo "$sysctl_params" >> /etc/sysctl.conf
        log "已添加网络优化参数到 /etc/sysctl.conf。"

        # 应用更改
        sysctl -p && sysctl --system
        log "网络优化已完成。"
    else
        log "已取消操作。"
    fi
}

# 显示配置信息
show_config_info() {
    echo "---------- Xray 服务状态 ----------"
    systemctl status xray --no-pager
    echo "----------------------------------"

    echo "正在获取本机 IP..."
    local ipv4 ipv6
    ipv4=$(curl -s4 ip.sb || echo "未检测到")
    ipv6=$(curl -s6 ip.sb || echo "未检测到")
    echo "IPv4: ${ipv4:-"未检测到"}"
    echo "IPv6: ${ipv6:-"未检测到"}"

    echo "========== 已配置的 INBOUND 列表 =========="
    jq -r '.inbounds[] | "tag: \(.tag), protocol: \(.protocol), port: \(.port)"' "$CONFIG_JSON"
    echo "========== 已配置的 OUTBOUND 列表 ========="
    jq -r '.outbounds[] | "tag: \(.tag), protocol: \(.protocol)"' "$CONFIG_JSON"
    echo "=========================================="
}

# 管理 Xray 服务
manage_xray_service() {
    while true; do
        echo "---------- 管理 Xray 服务 ----------"
        echo "1. 设定每天自动重启"
        echo "2. 立即重启"
        echo "0. 返回上一级"
        read -rp "请输入选项: " opt
        case "$opt" in
            1)
                read -rp "请输入每天自动重启的小时（0-23，输入 0 返回）： " hr
                if [[ "$hr" == "0" ]]; then
                    continue
                fi
                if ! [[ "$hr" =~ ^[0-9]+$ ]] || (( hr < 0 || hr > 23 )); then
                    log "${RED}错误:${NC} 请输入有效的小时（0-23）。"
                    continue
                fi
                # 移除已有的重启任务
                crontab -l 2>/dev/null | grep -v 'systemctl restart xray' | crontab -
                # 添加新的重启任务
                (crontab -l 2>/dev/null; echo "0 $hr * * * systemctl restart xray") | crontab -
                log "已设置每天 $hr 点自动重启 Xray。"
                ;;
            2)
                restart_xray
                log "Xray 服务已立即重启。"
                ;;
            0)
                break
                ;;
            *)
                log "${RED}错误:${NC} 无效选项。"
                ;;
        esac
    done
}

# 卸载 Xray
uninstall_xray() {
    echo "即将卸载 Xray 并删除所有配置及日志。确定要继续吗？(y/n，默认n)"
    read -r confirm
    confirm=${confirm:-n}
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log "已取消卸载。"
        return
    fi

    systemctl stop xray
    systemctl disable xray
    crontab -l 2>/dev/null | grep -v 'systemctl restart xray' | crontab -
    rm -rf /usr/local/etc/xray
    rm -f /usr/local/bin/xray
    rm -f /etc/systemd/system/xray.service
    systemctl daemon-reload || true
    rm -rf /var/log/xray
    log "Xray 已全部卸载并删除配置信息。"
}

# 主菜单
main_menu() {
    local exit_script=false
    while [[ "$exit_script" == false ]]; do
        echo "=============== 主菜单 ==============="
        echo "1. Shadowsocks 入站管理（添加/删除）"
        echo "2. Socks5 入站管理（添加/删除）"
        echo "3. 代理链 出站管理（添加/删除）"  
        echo "4. 网络优化"
        echo "5. 显示 Xray 配置信息"
        echo "6. 管理 Xray 服务"
        echo "7. 卸载 Xray 并删除所有配置"
        echo "0. 退出"
        read -rp "请选择操作(0-7)： " main_choice

        case "$main_choice" in
            1)
                while true; do
                    echo "------ Shadowsocks 入站管理 ------"
                    echo "1. 添加 Shadowsocks 入站"
                    echo "2. 删除 Shadowsocks 入站"
                    echo "0. 返回主菜单"
                    read -rp "请选择操作: " ss_action
                    case "$ss_action" in
                        1) add_shadowsocks_inbound ;;
                        2) remove_shadowsocks_inbound ;;
                        0) break ;;
                        *) log "${RED}错误:${NC} 无效选项。";;
                    esac
                done
                ;;
            2)
                while true; do
                    echo "------ Socks5 入站管理 ------"
                    echo "1. 添加 Socks5 入站"
                    echo "2. 删除 Socks5 入站"
                    echo "0. 返回主菜单"
                    read -rp "请选择操作: " s5_in_action
                    case "$s5_in_action" in
                        1) add_socks_inbound ;;
                        2) remove_socks_inbound ;;
                        0) break ;;
                        *) log "${RED}错误:${NC} 无效选项。";;
                    esac
                done
                ;;
            3)
                while true; do
                    echo "------ 代理链出站管理 ------"
                    echo "1. 添加 代理链出站"
                    echo "2. 删除 代理链出站"
                    echo "0. 返回主菜单"
                    read -rp "请选择操作: " s5_out_action
                    case "$s5_out_action" in
                        1) add_socks_outbound ;;
                        2) remove_socks_outbound ;;
                        0) break ;;
                        *) log "${RED}错误:${NC} 无效选项。" ;;
                    esac
                done
                ;;
            4)
                optimize_network
                ;;
            5)
                show_config_info
                ;;
            6)
                manage_xray_service
                ;;
            7)
                uninstall_xray
                ;;
            0)
                log "退出脚本。"
                exit_script=true
                ;;
            *)
                log "${RED}错误:${NC} 无效选项，请重新选择。"
                ;;
        esac
    done
}

# 主流程
main() {
    check_root
    detect_distro
    install_dependencies
    init_config
    install_xray_if_needed
    main_menu
}

main
