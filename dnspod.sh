#!/bin/bash

# 检查依赖
command -v curl >/dev/null || { echo "需要 curl"; exit 1; }
command -v openssl >/dev/null || { echo "需要 openssl"; exit 1; }

# 检查环境变量
if [ -z "$DP_SecretId" ] || [ -z "$DP_SecretKey" ]; then
    echo "错误：请设置环境变量 DP_SecretId 和 DP_SecretKey" >&2
    exit 1
fi

# ---------- 工具函数 ----------
# 解析主域名和子域名
parse_domain() {
    local full="$1"
    local domain sub
    # 匹配双后缀
    if echo "$full" | grep -E -q "(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$"; then
        domain=$(echo "$full" | grep -oP '[^.]+(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$')
        sub=$(echo "$full" | grep -oP '.*(?=\.[^.]+(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$)')
    else
        # 对于 example.com 格式
        domain=$(echo "$full" | sed -r 's/^[^.]*\.([^.]*\..*)$/\1/')
        if [ "$domain" = "$full" ]; then
            # 本身就是主域名
            domain="$full"
            sub=""
        else
            sub=$(echo "$full" | sed -r 's/^(.*)\.[^.]*\..*$/\1/')
        fi
    fi
    echo "$domain|$sub"
}

# SHA256 哈希（十六进制小写）
sha256_hex() {
    printf "%s" "$1" | openssl dgst -sha256 -hex | awk '{print $2}'
}

# HMAC-SHA256（输出二进制）
hmac_sha256_bin() {
    local key="$1"
    local msg="$2"
    printf "%s" "$msg" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$key" -binary 2>/dev/null
}

# 腾讯云 API 签名（TC3-HMAC-SHA256）
tc3_sign() {
    local secret_key="$1"
    local date="$2"
    local service="$3"
    local string_to_sign="$4"

    # 1. 计算派生签名密钥
    # SecretDate = HMAC_SHA256("TC3" + SecretKey, Date)
    local secret_date_hex=$(printf "%s" "$date" | openssl dgst -sha256 -mac hmac -macopt key:"TC3$secret_key" -hex 2>/dev/null | awk '{print $2}')
    # SecretService = HMAC_SHA256(SecretDate, Service)
    local secret_service_hex=$(printf "%s" "$service" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_date_hex" -hex 2>/dev/null | awk '{print $2}')
    # SecretSigning = HMAC_SHA256(SecretService, "tc3_request")
    local secret_signing_hex=$(printf "%s" "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_service_hex" -hex 2>/dev/null | awk '{print $2}')

    # 2. 计算签名：HMAC_SHA256(SecretSigning, StringToSign)
    local signature=$(printf "%s" "$string_to_sign" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$secret_signing_hex" -hex 2>/dev/null | awk '{print $2}')
    echo "$signature"
}

# 发送 API 请求
call_dnspod() {
    local action="$1"
    local payload="$2"
    local secret_id="$DP_SecretId"
    local secret_key="$DP_SecretKey"
    local version="2021-03-23"
    local host="dnspod.tencentcloudapi.com"
    local service="dnspod"
    local algorithm="TC3-HMAC-SHA256"
    local timestamp=$(date -u +%s)
    local date=$(date -u -d @"$timestamp" +%Y-%m-%d)

    # 1. 拼接规范请求串 CanonicalRequest
    local http_request_method="POST"
    local canonical_uri="/"
    local canonical_querystring=""  # POST 请求固定为空[reference:3]
    local content_type="application/json"
    local canonical_headers="content-type:$content_type\nhost:$host\n"
    local signed_headers="content-type;host"

    # 请求正文的 SHA256 哈希[reference:4]
    local payload_hash=$(sha256_hex "$payload")
    local canonical_request="${http_request_method}\n${canonical_uri}\n${canonical_querystring}\n${canonical_headers}\n${signed_headers}\n${payload_hash}"

    # 2. 拼接待签名字符串 StringToSign[reference:5]
    local hashed_canonical_request=$(sha256_hex "$canonical_request")
    local credential_scope="${date}/${service}/tc3_request"
    local string_to_sign="${algorithm}\n${timestamp}\n${credential_scope}\n${hashed_canonical_request}"

    # 3. 计算签名
    local signature=$(tc3_sign "$secret_key" "$date" "$service" "$string_to_sign")

    # 4. 拼接 Authorization[reference:6]
    local authorization="${algorithm} Credential=${secret_id}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"

    # 发送请求
    curl -s -X POST "https://$host" \
        -H "Authorization: $authorization" \
        -H "Content-Type: $content_type" \
        -H "Host: $host" \
        -H "X-TC-Action: $action" \
        -H "X-TC-Version: $version" \
        -H "X-TC-Timestamp: $timestamp" \
        -d "$payload"
}

# ---------- 主逻辑 ----------
if [ -z "$CERTBOT_DOMAIN" ] || [ -z "$CERTBOT_VALIDATION" ]; then
    echo "错误：缺少 CERTBOT_DOMAIN 或 CERTBOT_VALIDATION 环境变量" >&2
    exit 1
fi

# 解析域名
read domain sub <<< $(echo $(parse_domain "$CERTBOT_DOMAIN") | tr '|' ' ')
if [ -z "$domain" ]; then
    domain="$CERTBOT_DOMAIN"
    sub=""
fi

# 构建完整的主机记录（RR）
if [ -z "$sub" ]; then
    rr="_acme-challenge"
else
    rr="_acme-challenge.$sub"
fi

if [ "$1" = "clean" ]; then
    # ---------- 删除记录 ----------
    # 先查询记录 ID
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
    # ---------- 添加记录 ----------
    add_payload="{\"Domain\":\"$domain\",\"SubDomain\":\"$rr\",\"RecordType\":\"TXT\",\"RecordLine\":\"默认\",\"Value\":\"$CERTBOT_VALIDATION\"}"
    resp=$(call_dnspod "CreateRecord" "$add_payload")
    if echo "$resp" | grep -q '"Error"'; then
        echo "添加记录失败: $resp" >&2
        exit 1
    else
        echo "成功添加 TXT 记录: $rr.$domain"
        # 等待 DNS 传播（建议 60 秒更稳妥）
        sleep 60
        exit 0
    fi
fi
