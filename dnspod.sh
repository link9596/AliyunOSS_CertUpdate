#!/bin/bash

# 严格对齐 Cloudflare Worker 中的签名逻辑
# 环境变量：DP_SecretId, DP_SecretKey

set -e

command -v curl >/dev/null || { echo "需要 curl"; exit 1; }
command -v openssl >/dev/null || { echo "需要 openssl"; exit 1; }

if [ -z "$DP_SecretId" ] || [ -z "$DP_SecretKey" ]; then
    echo "错误：请设置环境变量 DP_SecretId 和 DP_SecretKey" >&2
    exit 1
fi

# ---------- 工具函数 ----------
# SHA256 十六进制
sha256_hex() {
    printf "%s" "$1" | openssl dgst -sha256 -hex | awk '{print $2}'
}

# HMAC-SHA256，返回十六进制
# 参数: key (普通字符串或hex), msg, is_hex (0/1)
hmac_hex() {
    local key="$1"
    local msg="$2"
    local is_hex="$3"
    if [ "$is_hex" = "1" ]; then
        printf "%s" "$msg" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$key" -hex 2>/dev/null | awk '{print $2}'
    else
        printf "%s" "$msg" | openssl dgst -sha256 -mac hmac -macopt key:"$key" -hex 2>/dev/null | awk '{print $2}'
    fi
}

# 腾讯云 TC3 签名（完全按照 Worker 代码）
tc3_sign() {
    local secret_key="$1"
    local date="$2"
    local service="$3"
    local string_to_sign="$4"

    # 派生密钥
    local secret_date_hex=$(hmac_hex "TC3$secret_key" "$date" 0)
    local secret_service_hex=$(hmac_hex "$secret_date_hex" "$service" 1)
    local secret_signing_hex=$(hmac_hex "$secret_service_hex" "tc3_request" 1)

    # 最终签名
    local signature=$(hmac_hex "$secret_signing_hex" "$string_to_sign" 1)
    echo "$signature"
}

# 调用 API
call_dnspod() {
    local action="$1"
    local payload="$2"
    local secret_id="$DP_SecretId"
    local secret_key="$DP_SecretKey"
    local host="dnspod.tencentcloudapi.com"
    local service="dnspod"
    local version="2021-03-23"
    local algorithm="TC3-HMAC-SHA256"
    local timestamp=$(date -u +%s)
    local date=$(date -u -d @"$timestamp" +%Y-%m-%d)

    # 规范请求
    local http_method="POST"
    local canonical_uri="/"
    local canonical_querystring=""
    local content_type="application/json; charset=utf-8"
    local action_lower=$(echo "$action" | tr '[:upper:]' '[:lower:]')
    local canonical_headers="content-type:$content_type\nhost:$host\nx-tc-action:$action_lower\n"
    local signed_headers="content-type;host;x-tc-action"

    local payload_hash=$(sha256_hex "$payload")
    local canonical_request="${http_method}\n${canonical_uri}\n${canonical_querystring}\n${canonical_headers}\n${signed_headers}\n${payload_hash}"

    local hashed_canonical_request=$(sha256_hex "$canonical_request")
    local credential_scope="${date}/${service}/tc3_request"
    local string_to_sign="${algorithm}\n${timestamp}\n${credential_scope}\n${hashed_canonical_request}"

    local signature=$(tc3_sign "$secret_key" "$date" "$service" "$string_to_sign")
    local authorization="${algorithm} Credential=${secret_id}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"

    # ---------- 调试输出（会显示在 Actions 日志中） ----------
    echo "DEBUG: timestamp=$timestamp, date=$date" >&2
    echo "DEBUG: canonical_request = " >&2
    echo "$canonical_request" >&2
    echo "DEBUG: string_to_sign = " >&2
    echo "$string_to_sign" >&2
    echo "DEBUG: authorization = $authorization" >&2

    # 发送请求
    local response=$(curl -s -X POST "https://$host" \
        -H "Authorization: $authorization" \
        -H "Content-Type: $content_type" \
        -H "Host: $host" \
        -H "X-TC-Action: $action" \
        -H "X-TC-Version: $version" \
        -H "X-TC-Timestamp: $timestamp" \
        -d "$payload")

    echo "DEBUG: response = $response" >&2
    echo "$response"
}

# ---------- 主逻辑 ----------
if [ -z "$CERTBOT_DOMAIN" ] || [ -z "$CERTBOT_VALIDATION" ]; then
    echo "错误：缺少 CERTBOT_DOMAIN 或 CERTBOT_VALIDATION 环境变量" >&2
    exit 1
fi

# 解析域名（同之前）
parse_domain() {
    local full="$1"
    local domain sub
    if echo "$full" | grep -E -q "(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$"; then
        domain=$(echo "$full" | grep -oP '[^.]+(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$')
        sub=$(echo "$full" | grep -oP '.*(?=\.[^.]+(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$)')
    else
        domain=$(echo "$full" | sed -r 's/^[^.]*\.([^.]*\..*)$/\1/')
        if [ "$domain" = "$full" ]; then
            domain="$full"
            sub=""
        else
            sub=$(echo "$full" | sed -r 's/^(.*)\.[^.]*\..*$/\1/')
        fi
    fi
    echo "$domain|$sub"
}

read domain sub <<< $(echo $(parse_domain "$CERTBOT_DOMAIN") | tr '|' ' ')
if [ -z "$domain" ]; then
    domain="$CERTBOT_DOMAIN"
    sub=""
fi

if [ -z "$sub" ]; then
    rr="_acme-challenge"
else
    rr="_acme-challenge.$sub"
fi

if [ "$1" = "clean" ]; then
    # 查询并删除记录
    query_payload="{\"Domain\":\"$domain\",\"SubDomain\":\"$rr\",\"RecordType\":\"TXT\"}"
    query_resp=$(call_dnspod "DescribeRecordFilterList" "$query_payload")
    record_id=$(echo "$query_resp" | grep -o '"RecordId":[0-9]*' | head -1 | grep -o '[0-9]*')
    if [ -z "$record_id" ]; then
        echo "未找到记录，无需清理" >&2
        exit 0
    fi
    delete_payload="{\"Domain\":\"$domain\",\"RecordId\":$record_id}"
    del_resp=$(call_dnspod "DeleteRecord" "$delete_payload")
    if echo "$del_resp" | grep -q '"Error"'; then
        echo "删除记录失败: $del_resp" >&2
        exit 1
    else
        echo "成功删除 TXT 记录: $rr.$domain"
        exit 0
    fi
else
    # 添加记录
    add_payload="{\"Domain\":\"$domain\",\"SubDomain\":\"$rr\",\"RecordType\":\"TXT\",\"RecordLine\":\"默认\",\"Value\":\"$CERTBOT_VALIDATION\"}"
    resp=$(call_dnspod "CreateRecord" "$add_payload")
    if echo "$resp" | grep -q '"Error"'; then
        echo "添加记录失败: $resp" >&2
        exit 1
    else
        echo "成功添加 TXT 记录: $rr.$domain"
        sleep 60
        exit 0
    fi
fi
