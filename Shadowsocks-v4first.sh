#!/bin/bash

# 检查是否以 root 身份运行
if [ "$EUID" -ne 0 ]; then
    echo "请以 root 用户运行此脚本。"
    exit 1
fi

apt-get update
apt-get install -y jq curl

# 配置文件路径
config_json="/usr/local/etc/xray/config.json"
ss_config="/usr/local/etc/xray/ss_config"
socks_config="/usr/local/etc/xray/socks_config"

# Shadowsocks 支持的加密方式列表
supported_methods=("aes-256-gcm" "aes-128-gcm" "chacha20-ietf-poly1305" "xchacha20-ietf-poly1305" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305" "aes-256-cfb" "aes-128-cfb" "aes-256-ctr" "rc4-md5")

# 生成随机强密码函数
generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

# 初始化配置文件
init_config() {
    # 确保配置目录存在
    mkdir -p $(dirname "$config_json")

    if [ ! -f "$config_json" ]; then
        cat <<EOF > "$config_json"
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
    fi
}

# 添加或更新 Shadowsocks 入站配置
update_ss_inbound() {
    # 确保配置目录存在
    mkdir -p $(dirname "$config_json")

    # 移除已有的 Shadowsocks 入站配置
    jq 'del(.inbounds[] | select(.protocol == "shadowsocks"))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

    # 添加新的 Shadowsocks 入站配置
    jq '.inbounds += [{
        "port": '"$1"',
        "protocol": "shadowsocks",
        "settings": {
            "method": "'"$2"'",
            "password": "'"$3"'",
            "network": "tcp,udp"
        },
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls"]
        }
    }]' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
}

# 添加或更新 SOCKS5 入站配置
update_socks_inbound() {
    # 确保配置目录存在
    mkdir -p $(dirname "$config_json")

    # 移除已有的 SOCKS5 入站配置
    jq 'del(.inbounds[] | select(.protocol == "socks"))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

    # 设置认证配置
    if [ "$4" == "password" ]; then
        auth_config='{
            "auth": "password",
            "accounts": [{
                "user": "'"$2"'",
                "pass": "'"$3"'"
            }],
            "udp": true
        }'
    else
        auth_config='{
            "auth": "noauth",
            "udp": true
        }'
    fi

    # 添加新的 SOCKS5 入站配置
    jq --argjson auth_settings "$auth_config" '.inbounds += [{
        "port": '"$1"',
        "listen": "0.0.0.0",
        "protocol": "socks",
        "settings": $auth_settings,
        "sniffing": {
            "enabled": true,
            "destOverride": ["http", "tls"]
        }
    }]' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
}

# 更新出站和路由配置
update_outbound_routing() {
    # 确保配置目录存在
    mkdir -p $(dirname "$config_json")

    if [ "$1" == "true" ]; then
        # 配置启用 IPv4 优先的 outbounds 和 routing
        jq '.outbounds = [
            {
                "tag": "IP4",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIPv4"
                }
            },
            {
                "tag": "IP6",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIPv6"
                }
            }
        ]' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        jq '.routing = {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "IP4",
                    "network": "tcp,udp"
                },
                {
                    "type": "field",
                    "ip": ["::/0"],
                    "outboundTag": "IP6"
                }
            ]
        }' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
    else
        # 配置默认的 outbound，并删除 routing
        jq '.outbounds = [{
            "protocol": "freedom",
            "settings": {}
        }] | del(.routing)' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
    fi
}

# 执行网络优化
optimize_network() {
    # 备份当前的 sysctl 配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    # 移除已有的优化参数
    sed -i '/net\.ipv4\.tcp_no_metrics_save/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_ecn/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_frto/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_rfc1337/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_sack/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_fack/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_window_scaling/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_adv_win_scale/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_moderate_rcvbuf/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_rmem/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_wmem/d' /etc/sysctl.conf
    sed -i '/net\.core\.rmem_max/d' /etc/sysctl.conf
    sed -i '/net\.core\.wmem_max/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_notsent_lowat/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.udp_rmem_min/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.udp_wmem_min/d' /etc/sysctl.conf
    sed -i '/net\.core\.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net\.ipv4\.tcp_collapse_max_bytes/d' /etc/sysctl.conf

    # 添加新的优化参数
    cat >> /etc/sysctl.conf << EOF
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
net.ipv4.tcp_collapse_max_bytes=6291456
net.ipv4.tcp_notsent_lowat=131072
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

    # 使配置生效
    sysctl -p && sysctl --system

    echo "网络优化已完成。"
}

# 显示代理配置信息
display_proxy_info() {


    echo "服务运行状态："
    systemctl status xray --no-pager

    echo "正在获取本机 IP 地址..."
    ipv4=$(curl -s4 ip.sb)
    ipv6=$(curl -s6 ip.sb)

    echo "---------------------------------"
    echo "本机 IPv4 地址： ${ipv4:-"未检测到 IPv4 地址"}"
    echo "本机 IPv6 地址： ${ipv6:-"未检测到 IPv6 地址"}"
    echo "---------------------------------"

    if [ -f "$ss_config" ]; then
        echo "Shadowsocks 配置信息："
        source "$ss_config"
        echo "服务端口： $port"
        echo "密码： $password"
        echo "加密方式： $method"
        echo "启用 IPv4 优先： $ipv4_only"
        echo "---------------------------------"
    else
        echo "未检测到 Shadowsocks 配置。"
    fi

    if [ -f "$socks_config" ]; then
        echo "SOCKS5 配置信息："
        source "$socks_config"
        echo "服务端口： $port"
        if [ -n "$username" ]; then
            echo "用户名： $username"
            echo "密码： $password"
        else
            echo "认证： 无需认证"
        fi
        echo "启用 IPv4 优先： $ipv4_only"
        echo "---------------------------------"
    else
        echo "未检测到 SOCKS5 配置。"
    fi

}

exit_script=false
while [ "$exit_script" = false ]; do
    # 提示用户选择操作
    echo "请选择操作："
    echo "1. 安装 Shadowsocks "
    echo "2. 修改 Shadowsocks 配置"
    echo "3. 安装 SOCKS5 "
    echo "4. 修改 SOCKS5 配置"
    echo "5. 卸载已安装代理"
    echo "6. 修改 IPv4 优先设置"
    echo "7. 进行网络优化"
    echo "8. 显示代理的配置信息"
    echo "0. 退出"
    read -rp "请输入选项（0-8）： " action

    case "$action" in
        1)
            # 安装 Shadowsocks
            init_config

            # 提示用户输入 Shadowsocks 配置
            while true; do
                read -rp "请输入 Shadowsocks 服务端口（默认 28001，输入 0 返回上一级）： " port
                if [ "$port" = "0" ]; then
                    break
                fi
                port=${port:-28001}

                # 验证端口号是否为有效的数字
                if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
                    echo "错误：请输入有效的端口号（1-65535）。"
                    continue
                fi

                read -rp "请输入 Shadowsocks 密码（留空生成随机密码，输入 0 返回上一级）： " password
                if [ "$password" = "0" ]; then
                    break
                fi
                password=${password:-$(generate_password)}

                # 选择加密方式
                while true; do
                    echo "请选择 Shadowsocks 加密方式："
                    for i in "${!supported_methods[@]}"; do
                        echo "$((i+1)). ${supported_methods[$i]}"
                    done
                    echo "0. 返回上一级"
                    read -rp "请输入选项（0-${#supported_methods[@]}，默认 1）： " method_choice
                    method_choice=${method_choice:-1}
                    if [ "$method_choice" = "0" ]; then
                        break 2
                    fi
                    if ! [[ "$method_choice" =~ ^[0-9]+$ ]] || [ "$method_choice" -lt 1 ] || [ "$method_choice" -gt "${#supported_methods[@]}" ]; then
                        echo "错误：请输入有效的选项。"
                        continue
                    fi
                    method="${supported_methods[$((method_choice-1))]}"
                    break
                done

                # 提示用户选择是否启用 IPv4 优先
                read -rp "是否启用 IPv4 优先进行连接？(y/n，默认 y，输入 0 返回上一级)： " ipv4_choice
                if [ "$ipv4_choice" = "0" ]; then
                    break
                fi
                ipv4_choice=${ipv4_choice:-y}
                if [[ "$ipv4_choice" =~ ^[Yy]$ ]]; then
                    ipv4_setting="true"
                else
                    ipv4_setting="false"
                fi

                # 安装 Xray
                if ! command -v xray >/dev/null 2>&1; then
                    echo "正在安装 Xray..."
                    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
                fi

                # 配置 Xray Shadowsocks
                update_ss_inbound "$port" "$method" "$password"
                update_outbound_routing "$ipv4_setting"

                # 设置日志目录权限
                mkdir -p /var/log/xray
                chown nobody:nogroup /var/log/xray

                # 验证配置文件是否有效
                if ! xray -test -c "$config_json"; then
                    echo "错误：Xray 配置文件无效。请检查配置。"
                    break
                fi

                # 启动并启用 Xray 服务
                systemctl restart xray
                systemctl enable xray

                # 保存用户的配置
                echo "port=$port" > "$ss_config"
                echo "password=$password" >> "$ss_config"
                echo "method=$method" >> "$ss_config"
                echo "ipv4_only=$ipv4_setting" >> "$ss_config"

                # 显示服务信息
                echo "Xray Shadowsocks 已成功安装和配置！"
                echo "---------------------------------"
                echo "服务端口： $port"
                echo "密码： $password"
                echo "加密方式： $method"
                echo "启用 IPv4 优先： $ipv4_setting"
                echo "---------------------------------"
                echo "服务运行状态："
                systemctl status xray --no-pager
                break
            done
            ;;
        2)
            # 修改 Shadowsocks 配置
            if [ ! -f "$ss_config" ]; then
                echo "错误：未找到 Shadowsocks 配置文件。请先安装 Shadowsocks。"
                continue
            fi

            init_config
            source "$ss_config"

            while true; do
                # 提示用户输入新的配置
                read -rp "请输入新的 Shadowsocks 服务端口（当前 $port，直接回车保持不变，输入 0 返回上一级）： " new_port
                if [ "$new_port" = "0" ]; then
                    break
                fi
                new_port=${new_port:-$port}

                # 验证端口号是否为有效的数字
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -le 0 ] || [ "$new_port" -gt 65535 ]; then
                    echo "错误：请输入有效的端口号（1-65535）。"
                    continue
                fi

                read -rp "请输入新的 Shadowsocks 密码（直接回车保持不变，输入 0 返回上一级）： " new_password
                if [ "$new_password" = "0" ]; then
                    break
                fi
                new_password=${new_password:-$password}

                # 选择新的加密方式
                while true; do
                    echo "请选择新的 Shadowsocks 加密方式（当前 $method）："
                    for i in "${!supported_methods[@]}"; do
                        echo "$((i+1)). ${supported_methods[$i]}"
                    done
                    echo "0. 返回上一级"
                    echo "直接回车保持不变"
                    read -rp "请输入选项（0-${#supported_methods[@]}）： " method_choice
                    if [ "$method_choice" = "0" ]; then
                        break 2
                    elif [ -z "$method_choice" ]; then
                        new_method="$method"
                        break
                    fi
                    if ! [[ "$method_choice" =~ ^[0-9]+$ ]] || [ "$method_choice" -lt 1 ] || [ "$method_choice" -gt "${#supported_methods[@]}" ]; then
                        echo "错误：请输入有效的选项。"
                        continue
                    fi
                    new_method="${supported_methods[$((method_choice-1))]}"
                    break
                done

                # 更新 Shadowsocks 配置
                update_ss_inbound "$new_port" "$new_method" "$new_password"

                # 更新保存的配置
                echo "port=$new_port" > "$ss_config"
                echo "password=$new_password" >> "$ss_config"
                echo "method=$new_method" >> "$ss_config"
                echo "ipv4_only=$ipv4_only" >> "$ss_config"

                # 验证配置文件是否有效
                if ! xray -test -c "$config_json"; then
                    echo "错误：Xray 配置文件无效。请检查配置。"
                    break
                fi

                # 重启 Xray 服务
                systemctl restart xray

                # 显示新的服务信息
                echo "Shadowsocks 配置已更新！"
                echo "---------------------------------"
                echo "服务端口： $new_port"
                echo "密码： $new_password"
                echo "加密方式： $new_method"
                echo "启用 IPv4 优先： $ipv4_only"
                echo "---------------------------------"
                echo "服务运行状态："
                systemctl status xray --no-pager
                break
            done
            ;;
        3)
            # 安装 SOCKS5
            init_config

            while true; do
                read -rp "请输入 SOCKS5 服务端口（默认 55555，输入 0 返回上一级）： " port
                if [ "$port" = "0" ]; then
                    break
                fi
                port=${port:-55555}

                # 验证端口号是否为有效的数字
                if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
                    echo "错误：请输入有效的端口号（1-65535）。"
                    continue
                fi

                # 提示用户输入用户名和密码
                read -rp "请输入 SOCKS5 用户名（留空则不设置认证，输入 0 返回上一级）： " username
                if [ "$username" = "0" ]; then
                    break
                fi
                if [ -n "$username" ]; then
                    read -rp "请输入 SOCKS5 密码（输入 0 返回上一级）： " password
                    if [ "$password" = "0" ]; then
                        break
                    fi
                    auth_setting="password"
                else
                    auth_setting="noauth"
                fi

                # 提示用户选择是否启用 IPv4 优先
                read -rp "是否启用 IPv4 优先进行连接？(y/n，默认 y，输入 0 返回上一级)： " ipv4_choice
                if [ "$ipv4_choice" = "0" ]; then
                    break
                fi
                ipv4_choice=${ipv4_choice:-y}
                if [[ "$ipv4_choice" =~ ^[Yy]$ ]]; then
                    ipv4_setting="true"
                else
                    ipv4_setting="false"
                fi

                # 安装 Xray（如果未安装）
                if ! command -v xray >/dev/null 2>&1; then
                    echo "正在安装 Xray..."
                    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
                fi

                # 配置 Xray SOCKS5
                update_socks_inbound "$port" "$username" "$password" "$auth_setting"
                update_outbound_routing "$ipv4_setting"

                # 设置日志目录权限
                mkdir -p /var/log/xray
                chown nobody:nogroup /var/log/xray

                # 验证配置文件是否有效
                if ! xray -test -c "$config_json"; then
                    echo "错误：Xray 配置文件无效。请检查配置。"
                    break
                fi

                # 启动并启用 Xray 服务
                systemctl restart xray
                systemctl enable xray

                # 保存 SOCKS5 配置
                echo "port=$port" > "$socks_config"
                echo "username=$username" >> "$socks_config"
                echo "password=$password" >> "$socks_config"
                echo "auth_setting=$auth_setting" >> "$socks_config"
                echo "ipv4_only=$ipv4_setting" >> "$socks_config"

                # 显示服务信息
                echo "Xray SOCKS5 已成功安装和配置！"
                echo "---------------------------------"
                echo "服务端口： $port"
                if [ -n "$username" ]; then
                    echo "用户名： $username"
                    echo "密码： $password"
                else
                    echo "认证： 无需认证"
                fi
                echo "启用 IPv4 优先： $ipv4_setting"
                echo "---------------------------------"
                echo "服务运行状态："
                systemctl status xray --no-pager
                break
            done
            ;;
        4)
            # 修改 SOCKS5 配置
            if [ ! -f "$socks_config" ]; then
                echo "错误：未找到 SOCKS5 配置文件。请先安装 SOCKS5。"
                continue
            fi

            init_config
            source "$socks_config"

            while true; do
                # 提示用户输入新的配置
                read -rp "请输入新的 SOCKS5 服务端口（当前 $port，直接回车保持不变，输入 0 返回上一级）： " new_port
                if [ "$new_port" = "0" ]; then
                    break
                fi
                new_port=${new_port:-$port}

                # 验证端口号是否为有效的数字
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -le 0 ] || [ "$new_port" -gt 65535 ]; then
                    echo "错误：请输入有效的端口号（1-65535）。"
                    continue
                fi

                # 提示用户输入新的用户名和密码
                read -rp "是否修改 SOCKS5 认证信息？(y/n，默认 n，输入 0 返回上一级)： " modify_auth
                if [ "$modify_auth" = "0" ]; then
                    break
                fi
                modify_auth=${modify_auth:-n}

                if [[ "$modify_auth" =~ ^[Yy]$ ]]; then
                    read -rp "请输入新的 SOCKS5 用户名（留空则不设置认证，输入 0 返回上一级）： " new_username
                    if [ "$new_username" = "0" ]; then
                        break
                    fi
                    if [ -n "$new_username" ]; then
                        read -rp "请输入新的 SOCKS5 密码（输入 0 返回上一级）： " new_password
                        if [ "$new_password" = "0" ]; then
                            break
                        fi
                        auth_setting="password"
                    else
                        auth_setting="noauth"
                    fi
                else
                    new_username=$username
                    new_password=$password
                    auth_setting=$auth_setting
                fi

                # 更新 SOCKS5 配置
                update_socks_inbound "$new_port" "$new_username" "$new_password" "$auth_setting"

                # 更新保存的配置
                echo "port=$new_port" > "$socks_config"
                echo "username=$new_username" >> "$socks_config"
                echo "password=$new_password" >> "$socks_config"
                echo "auth_setting=$auth_setting" >> "$socks_config"
                echo "ipv4_only=$ipv4_only" >> "$socks_config"

                # 验证配置文件是否有效
                if ! xray -test -c "$config_json"; then
                    echo "错误：Xray 配置文件无效。请检查配置。"
                    break
                fi

                # 重启 Xray 服务
                systemctl restart xray

                # 显示新的服务信息
                echo "SOCKS5 配置已更新！"
                echo "---------------------------------"
                echo "服务端口： $new_port"
                if [ -n "$new_username" ]; then
                    echo "用户名： $new_username"
                    echo "密码： $new_password"
                else
                    echo "认证： 无需认证"
                fi
                echo "启用 IPv4 优先： $ipv4_only"
                echo "---------------------------------"
                echo "服务运行状态："
                systemctl status xray --no-pager
                break
            done
            ;;
        5)
            # 卸载代理
            while true; do
                installed_proxies=()
                if [ -f "$ss_config" ]; then
                    installed_proxies+=("Shadowsocks")
                fi
                if [ -f "$socks_config" ]; then
                    installed_proxies+=("SOCKS5")
                fi

                if [ ${#installed_proxies[@]} -eq 0 ]; then
                    echo "未检测到已安装的代理。"
                    break
                else
                    echo "检测到以下已安装的代理："
                    for i in "${!installed_proxies[@]}"; do
                        echo "$((i+1)). ${installed_proxies[$i]}"
                    done
                    echo "$(( ${#installed_proxies[@]} + 1 )). 全部卸载"
                    echo "0. 返回上一级"
                    read -rp "请输入要卸载的代理编号： " uninstall_choice

                    if [ "$uninstall_choice" = "0" ]; then
                        break
                    fi

                    if [ "$uninstall_choice" -ge 1 ] && [ "$uninstall_choice" -le "${#installed_proxies[@]}" ]; then
                        proxy_to_uninstall="${installed_proxies[$((uninstall_choice - 1))]}"
                        if [ "$proxy_to_uninstall" == "Shadowsocks" ]; then
                            # 卸载 Shadowsocks
                            jq 'del(.inbounds[] | select(.protocol == "shadowsocks"))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
                            rm -f "$ss_config"
                            echo "Shadowsocks 已成功卸载！"
                        elif [ "$proxy_to_uninstall" == "SOCKS5" ]; then
                            # 卸载 SOCKS5
                            jq 'del(.inbounds[] | select(.protocol == "socks"))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
                            rm -f "$socks_config"
                            echo "SOCKS5 已成功卸载！"
                        fi
                    elif [ "$uninstall_choice" -eq "$(( ${#installed_proxies[@]} + 1 ))" ]; then
                        # 卸载所有代理
                        jq 'del(.inbounds[] | select(.protocol == "shadowsocks" or .protocol == "socks"))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
                        rm -f "$ss_config" "$socks_config"
                        echo "所有代理已成功卸载！"
                    else
                        echo "无效的选项。"
                        continue
                    fi

                    # 验证配置文件是否有效
                    if ! xray -test -c "$config_json"; then
                        echo "错误：Xray 配置文件无效。请检查配置。"
                        break
                    fi

                    # 重启 Xray 服务
                    systemctl restart xray

                    echo "代理卸载完成。"
                    break
                fi
            done
            ;;
        6)
            # 修改 IPv4 优先设置
            if [ ! -f "$config_json" ]; then
                echo "错误：未找到 Xray 配置文件。请先安装 Shadowsocks 或 SOCKS5。"
                continue
            fi

            while true; do
                ipv4_only=$(jq -r '.outbounds[0].settings.domainStrategy // empty' "$config_json")
                if [ "$ipv4_only" == "UseIPv4" ]; then
                    current_choice="开启"
                else
                    current_choice="关闭"
                fi

                echo "当前 IPv4 优先设置：$current_choice"
                echo "请选择新的 IPv4 优先设置："
                echo "1. 开启 IPv4 优先"
                echo "2. 关闭 IPv4 优先"
                echo "0. 返回上一级"
                read -rp "请输入选项（0-2）： " ipv4_option

                if [ "$ipv4_option" = "0" ]; then
                    break
                fi

                if [ "$ipv4_option" == "1" ]; then
                    ipv4_setting="true"
                    new_choice="开启"
                elif [ "$ipv4_option" == "2" ]; then
                    ipv4_setting="false"
                    new_choice="关闭"
                else
                    echo "无效的选项。"
                    continue
                fi

                # 更新出站和路由配置
                update_outbound_routing "$ipv4_setting"

                # 更新保存的配置（如果有）
                if [ -f "$ss_config" ]; then
                    sed -i 's/ipv4_only=\(true\|false\)/ipv4_only='"$ipv4_setting"'/' "$ss_config"
                fi
                if [ -f "$socks_config" ]; then
                    sed -i 's/ipv4_only=\(true\|false\)/ipv4_only='"$ipv4_setting"'/' "$socks_config"
                fi

                # 验证配置文件是否有效
                if ! xray -test -c "$config_json"; then
                    echo "错误：Xray 配置文件无效。请检查配置。"
                    break
                fi

                # 重启 Xray 服务
                systemctl restart xray

                echo "IPv4 优先设置已修改为：$new_choice"
                echo "服务运行状态："
                systemctl status xray --no-pager
                break
            done
            ;;
        7)
            # 进行网络优化
            while true; do
                echo "即将进行网络优化，此操作会修改 /etc/sysctl.conf 文件。"
                echo "1. 确认进行网络优化"
                echo "0. 返回上一级"
                read -rp "请输入选项（0-1）： " optimize_choice

                if [ "$optimize_choice" = "0" ]; then
                    break
                elif [ "$optimize_choice" = "1" ]; then
                    optimize_network
                    break
                else
                    echo "无效的选项。"
                fi
            done
            ;;
        8)
            # 显示已安装代理的配置信息
            display_proxy_info
            ;;
        0)
            echo "退出脚本。"
            exit_script=true
            ;;
        *)
            echo "无效选项，请重新选择。"
            ;;
    esac
done
