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

if [ "$EUID" -ne 0 ]; then
    echo "请以 root 用户运行此脚本。"
    exit 1
fi

apt-get update
apt-get install -y jq curl

config_json="/usr/local/etc/xray/config.json"

# Shadowsocks 支持的加密方式列表
supported_methods=("aes-256-gcm" "aes-128-gcm" "chacha20-ietf-poly1305" "xchacha20-ietf-poly1305" "2022-blake3-aes-256-gcm" "2022-blake3-chacha20-poly1305" "aes-256-cfb" "aes-128-cfb" "aes-256-ctr" "rc4-md5")

############################################
# 生成随机密码
############################################
generate_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

############################################
# 初始化 config.json
############################################
init_config() {
    mkdir -p "$(dirname "$config_json")"
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

############################################
# 安装 Xray（如未安装）
############################################
install_xray_if_needed() {
    if ! command -v xray >/dev/null 2>&1; then
        echo "正在安装 Xray..."
        bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
        systemctl enable xray
    fi
}

############################################
# 检测端口是否已被当前 Xray 配置的 inbound 占用
############################################
port_conflict_check() {
    local port=$1
    if [ -f "$config_json" ]; then
        local all_ports
        all_ports=$(jq -r '.inbounds[]?.port' "$config_json" 2>/dev/null)
        if [ -n "$all_ports" ]; then
            if echo "$all_ports" | grep -q -w "$port"; then
                return 1  # 表示冲突
            fi
        fi
    fi
    return 0  # 无冲突
}

############################################
# 设置(或重置)IPv4优先 (true=开启, false=关闭)
############################################
set_ipv4_priority() {
    local enable_ipv4="$1"
    if [ "$enable_ipv4" == "true" ]; then
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
        }' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
    else
        # 默认 => freedom 出站 & 清空 routing
        jq '.outbounds = [{"protocol":"freedom","settings":{}}] | del(.routing)' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
    fi
}

############################################
# Shadowsocks 入站管理
############################################
add_shadowsocks_inbound() {
    init_config
    install_xray_if_needed

    while true; do
        read -rp "请输入 Shadowsocks 入站端口（默认 28001，输入 0 返回上一级）： " port
        if [ "$port" = "0" ]; then
            break
        fi
        port=${port:-28001}

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
            echo "错误：端口号无效。"
            continue
        fi
        port_conflict_check "$port"
        if [ $? -ne 0 ]; then
            echo "端口冲突！当前 Xray 已使用端口 $port。"
            continue
        fi

        read -rp "请输入 Shadowsocks 密码（留空生成随机密码，输入 0 返回上一级）： " password
        if [ "$password" = "0" ]; then
            break
        fi
        password=${password:-$(generate_password)}

        echo "请选择 Shadowsocks 加密方式："
        for i in "${!supported_methods[@]}"; do
            echo "$((i+1)). ${supported_methods[$i]}"
        done
        echo "0. 返回上一级"
        local method method_choice
        while true; do
            read -rp "请输入选项（0-${#supported_methods[@]}，默认1）： " method_choice
            method_choice=${method_choice:-1}
            if [ "$method_choice" = "0" ]; then
                break 2
            fi
            if ! [[ "$method_choice" =~ ^[0-9]+$ ]] || [ "$method_choice" -lt 1 ] || [ "$method_choice" -gt "${#supported_methods[@]}" ]; then
                echo "错误：请输入有效选项。"
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

        jq --arg inbound_tag "$inbound_tag" --argjson port "$port" --arg method "$method" --arg password "$password" '
          .inbounds += [
            {
              "tag": $inbound_tag,
              "port": $port,
              "listen": "0.0.0.0",
              "protocol": "shadowsocks",
              "settings": {
                "method": $method,
                "password": $password,
                "network": "tcp,udp"
              },
              "sniffing": {
                "enabled": true,
                "destOverride": ["http","tls"]
              }
            }
          ]
        ' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        if ! xray -test -c "$config_json"; then
            echo "错误：Xray 配置文件无效。"
            break
        fi

        systemctl restart xray
        echo "已添加 Shadowsocks 入站：port=$port, password=$password, method=$method, tag=$inbound_tag"
        break
    done
}

remove_shadowsocks_inbound() {
    init_config
    install_xray_if_needed

    # 列出 Shadowsocks inbound 列表
    local ss_inbounds
    ss_inbounds=$(jq -r '.inbounds[] | select(.protocol=="shadowsocks") | .tag' "$config_json")
    if [ -z "$ss_inbounds" ]; then
        echo "当前没有任何 Shadowsocks 入站。"
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
        if [ "$choice" = "0" ]; then
            break
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#ss_array[@]}" ]; then
            echo "无效选项。"
            continue
        fi

        local del_tag="${ss_array[$((choice-1))]}"
        jq --arg del_tag "$del_tag" 'del(.inbounds[] | select(.tag == $del_tag))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        if ! xray -test -c "$config_json"; then
            echo "错误：更新后配置无效。"
            break
        fi

        systemctl restart xray
        echo "Shadowsocks 入站 [$del_tag] 已删除。"
        break
    done
}

############################################
# Socks5 入站管理
############################################
add_socks_inbound() {
    init_config
    install_xray_if_needed

    while true; do
        read -rp "请输入 Socks5 入站端口（默认 55555，输入 0 返回）： " port
        if [ "$port" = "0" ]; then
            break
        fi
        port=${port:-55555}

        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -le 0 ] || [ "$port" -gt 65535 ]; then
            echo "错误：端口号无效。"
            continue
        fi
        port_conflict_check "$port"
        if [ $? -ne 0 ]; then
            echo "端口冲突！当前 Xray 已使用端口 $port。"
            continue
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
            read -rp "请输入密码：" s5_pass
            auth_config=$(jq -nc --arg user "$s5_user" --arg pass "$s5_pass" '
              {
                "auth": "password",
                "accounts": [ { "user": $user, "pass": $pass } ],
                "udp": true
              }
            ')
        else
            auth_config='{"auth":"noauth","udp":true}'
        fi

        jq --argjson auth_settings "$auth_config" --arg inbound_tag "$inbound_tag" --argjson port "$port" '
          .inbounds += [
            {
              "tag": $inbound_tag,
              "port": $port,
              "listen": "0.0.0.0",
              "protocol": "socks",
              "settings": $auth_settings,
              "sniffing": {
                "enabled": true,
                "destOverride": ["http","tls"]
              }
            }
          ]
        ' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        if ! xray -test -c "$config_json"; then
            echo "错误：Xray 配置文件无效。"
            break
        fi

        systemctl restart xray
        echo "已添加 Socks5 入站：port=$port, tag=$inbound_tag"
        break
    done
}

remove_socks_inbound() {
    init_config
    install_xray_if_needed

    local s5_inbounds
    s5_inbounds=$(jq -r '.inbounds[] | select(.protocol=="socks") | .tag' "$config_json")
    if [ -z "$s5_inbounds" ]; then
        echo "当前没有任何 Socks5 入站。"
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
        if [ "$choice" = "0" ]; then
            break
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#s5_array[@]}" ]; then
            echo "无效选项。"
            continue
        fi

        local del_tag="${s5_array[$((choice-1))]}"
        jq --arg del_tag "$del_tag" 'del(.inbounds[] | select(.tag == $del_tag))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        if ! xray -test -c "$config_json"; then
            echo "错误：更新后配置无效。"
            break
        fi

        systemctl restart xray
        echo "Socks5 入站 [$del_tag] 已删除。"
        break
    done
}

############################################
# 代理链出站管理（原 Socks5 出站）
############################################
add_socks_outbound() {
    init_config
    install_xray_if_needed

    while true; do
        read -rp "为新代理链出站指定一个 tag（例：my-s5-out，输入0返回）： " out_tag
        if [ "$out_tag" = "0" ]; then
            break
        fi
        if [ -z "$out_tag" ]; then
            echo "错误：tag 不能为空。"
            continue
        fi

        read -rp "外部 S5 服务器地址（IP/域名）： " s5_addr
        if [ -z "$s5_addr" ]; then
            echo "错误：地址不能为空。"
            continue
        fi
        read -rp "外部 S5 服务器端口（默认1080）： " s5_port
        s5_port=${s5_port:-1080}
        if ! [[ "$s5_port" =~ ^[0-9]+$ ]] || [ "$s5_port" -le 0 ] || [ "$s5_port" -gt 65535 ]; then
            echo "错误：端口无效。"
            continue
        fi

        read -rp "是否需要用户名密码认证？(y/n，默认 n)： " s5_auth_choice
        s5_auth_choice=${s5_auth_choice:-n}
        local s5_auth=''
        if [[ "$s5_auth_choice" =~ ^[Yy]$ ]]; then
            read -rp "S5 用户名：" s5_user
            read -rp "S5 密码：" s5_pass
            s5_auth=$(jq -nc --arg user "$s5_user" --arg pass "$s5_pass" '{user:$user,pass:$pass}')
        fi

        # 先插入一个新的 socks outbound
        jq --arg out_tag "$out_tag" --arg s5_addr "$s5_addr" --argjson s5_port "$s5_port" --argjson s5_auth "$s5_auth" '
          .outbounds += [
            {
              "tag": $out_tag,
              "protocol": "socks",
              "settings": {
                "servers": [
                  if $s5_auth == "" then
                    {"address": $s5_addr, "port": $s5_port}
                  else
                    {"address": $s5_addr, "port": $s5_port, "users":[ $s5_auth ]}
                  end
                ]
              }
            }
          ]
        ' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        local inbound_tags
        inbound_tags=$(jq -r '.inbounds[]?.tag // empty' "$config_json")
        if [ -z "$inbound_tags" ]; then
            echo "当前没有任何 inbound，无法路由。"
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
            if [ "$selected_indexes" = "0" ]; then
                echo "不设置任何 routing rule。"
            else
                IFS=',' read -ra idx_arr <<< "$selected_indexes"
                local rule_json=""
                for idx in "${idx_arr[@]}"; do
                    idx=$(echo "$idx" | xargs)
                    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then
                        echo "无效序号: $idx"
                        continue
                    fi
                    idx=$((idx-1))
                    if [ $idx -lt 0 ] || [ $idx -ge ${#inbound_array[@]} ]; then
                        echo "序号越界: $((idx+1))"
                        continue
                    fi
                    local inbound_tag="${inbound_array[$idx]}"

                    # 先删除该 inbound_tag 之前的路由
                    jq --arg inbound_tag "$inbound_tag" '
                      if .routing.rules? then
                        .routing.rules = (.routing.rules | map(
                          select( ((.inboundTag // []) | inside([$inbound_tag])) | not )
                        ))
                      else
                        .
                      end
                    ' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

                    # 生成新的路由rule: 用单元素数组
                    local rule_entry
                    rule_entry=$(jq -nc --arg inbound_tag "$inbound_tag" --arg out_tag "$out_tag" '
                      [
                        {
                          "type": "field",
                          "inboundTag": [$inbound_tag],
                          "outboundTag": $out_tag
                        }
                      ]
                    ')

                    if [ -z "$rule_json" ]; then
                        rule_json="$rule_entry"
                    else
                        rule_json=$(jq -s '.[0] + .[1]' <(echo "$rule_json") <(echo "$rule_entry"))
                    fi
                done

                if [ -n "$rule_json" ]; then
                    if ! jq '.routing' "$config_json" | grep -q '{'; then
                        jq '.routing = {"domainStrategy":"IPOnDemand","rules":[]}' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
                    fi
                    jq --argjson newrules "$rule_json" '
                      .routing.rules += $newrules
                    ' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
                fi
            fi
        fi

        if ! xray -test -c "$config_json"; then
            echo "错误：Xray 配置无效，请检查输入。"
            break
        fi

        systemctl restart xray
        echo "已添加 代理链出站(tag=$out_tag)，地址：$s5_addr:$s5_port。"
        break
    done
}

remove_socks_outbound() {
    init_config
    install_xray_if_needed

    local outbound_list
    outbound_list=$(jq -r '.outbounds[] | select(.protocol=="socks") | .tag' "$config_json")
    if [ -z "$outbound_list" ]; then
        echo "当前没有任何 代理链出站。"
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
        if [ "$choice" = "0" ]; then
            break
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#s5_out_array[@]}" ]; then
            echo "无效选项。"
            continue
        fi

        local del_tag="${s5_out_array[$((choice-1))]}"
        # 删除对应 outbound
        jq --arg del_tag "$del_tag" 'del(.outbounds[] | select(.tag == $del_tag))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"
        # 同时删除与之对应的 routing 规则
        jq --arg del_tag "$del_tag" 'del(.routing.rules[]? | select(.outboundTag == $del_tag))' "$config_json" > tmp_config.json && mv tmp_config.json "$config_json"

        if ! xray -test -c "$config_json"; then
            echo "错误：更新后配置无效。"
            break
        fi

        # 删除代理链出站后，自动还原 IPv4 优先
        set_ipv4_priority "true"

        systemctl restart xray
        echo "代理链出站 [$del_tag] 已删除，并已恢复 IPv4 优先。"
        break
    done
}

############################################
# 网络优化
############################################
optimize_network() {
    echo "即将进行网络优化，会修改 /etc/sysctl.conf 文件。"
    read -rp "确认进行？(y/n，默认n)：" choice
    choice=${choice:-n}
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
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
        sysctl -p && sysctl --system
        echo "网络优化已完成。"
    else
        echo "已取消操作。"
    fi
}

############################################
# 显示配置信息
############################################
show_config_info() {
    echo "---------- Xray 服务状态 ----------"
    systemctl status xray --no-pager
    echo "----------------------------------"

    echo "正在获取本机 IP..."
    local ipv4 ipv6
    ipv4=$(curl -s4 ip.sb)
    ipv6=$(curl -s6 ip.sb)
    echo "IPv4: ${ipv4:-"未检测到"}"
    echo "IPv6: ${ipv6:-"未检测到"}"

    echo "========== 已配置的 INBOUND 列表 =========="
    jq -r '.inbounds[] | "tag: \(.tag), protocol: \(.protocol), port: \(.port)"' "$config_json"
    echo "========== 已配置的 OUTBOUND 列表 ========="
    jq -r '.outbounds[] | "tag: \(.tag), protocol: \(.protocol)"' "$config_json"
    echo "=========================================="
}

############################################
# 管理 Xray 服务
############################################
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
        if [ "$hr" = "0" ]; then
            continue
        fi
        if ! [[ "$hr" =~ ^[0-9]+$ ]] || [ "$hr" -lt 0 ] || [ "$hr" -gt 23 ]; then
            echo "错误：请输入有效的小时（0-23）。"
            continue
        fi
        (crontab -l 2>/dev/null | grep -v 'systemctl restart xray') | crontab -
        (crontab -l 2>/dev/null; echo "0 $hr * * * systemctl restart xray") | crontab -
        echo "已设置每天 $hr 点自动重启 Xray。"
        ;;
      2)
        systemctl restart xray
        echo "Xray 服务已立即重启。"
        ;;
      0)
        break
        ;;
      *)
        echo "无效选项。"
        ;;
    esac
  done
}

############################################
# 卸载 Xray
############################################
uninstall_xray() {
    echo "即将卸载 Xray 并删除所有配置及日志。确定要继续吗？(y/n，默认n)"
    read -r confirm
    confirm=${confirm:-n}
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "已取消卸载。"
        return
    fi

    systemctl stop xray
    systemctl disable xray
    (crontab -l 2>/dev/null | grep -v 'systemctl restart xray') | crontab -
    rm -rf /usr/local/etc/xray
    if [ -f /usr/local/bin/xray ]; then
        rm -f /usr/local/bin/xray
    fi
    if [ -f /etc/systemd/system/xray.service ]; then
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload
    fi
    rm -rf /var/log/xray
    echo "Xray 已全部卸载并删除配置信息。"
}

############################################
# 主菜单
############################################
exit_script=false
while [ "$exit_script" = false ]; do
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
                    *) echo "无效选项。";;
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
                    *) echo "无效选项。";;
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
                    *) echo "无效选项。" ;;
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
            echo "退出脚本。"
            exit_script=true
            ;;
        *)
            echo "无效选项，请重新选择。"
            ;;
    esac
done
