#!/bin/bash

# 检查 curl 是否可用
if ! command -v curl >/dev/null; then
    echo "错误: 需要安装 curl" 1>&2
    exit 1
fi

# 从环境变量读取腾讯云 API 密钥（需要在 GitHub Secrets 中配置）
# DP_SecretId: 腾讯云 SecretId
# DP_SecretKey: 腾讯云 SecretKey
if [ -z "$DP_SecretId" ] || [ -z "$DP_SecretKey" ]; then
    echo "错误: 请设置环境变量 DP_SecretId 和 DP_SecretKey" 1>&2
    exit 1
fi

# API 公共参数
ACTION="CreateTXTRecord"
VERSION="2021-03-23"
REGION=""
HOST="dnspod.tencentcloudapi.com"
SERVICE="dnspod"
ALGORITHM="TC3-HMAC-SHA256"
TIMESTAMP=$(date -u +%s)
DATE=$(date -u -d @$TIMESTAMP +%Y-%m-%d)

# 解析域名: 提取主域名和子域名
# 示例: 对于 "www.example.com"，DOMAIN="example.com"，SUB_DOMAIN="www"
# 对于 "example.com"，DOMAIN="example.com"，SUB_DOMAIN=""
DOMAIN=$(expr match "$CERTBOT_DOMAIN" '.*\.\(.*\..*\)')
SUB_DOMAIN=$(expr match "$CERTBOT_DOMAIN" '\(.*\)\..*\..*')

# 处理双后缀域名 (如 .com.cn, .gov.cn 等)
FLAG="(\.com\.cn|\.gov\.cn|\.net\.cn|\.org\.cn|\.ac\.cn|\.gd\.cn)$"
if echo $CERTBOT_DOMAIN | grep -E -q "$FLAG"; then
    DOMAIN=$(echo $CERTBOT_DOMAIN | grep -oP '(?<=)[^.]+('$FLAG')')
    SUB_DOMAIN=$(echo $CERTBOT_DOMAIN | grep -oP '.*(?=\.[^.]+('$FLAG'))')
fi

if [ -z "$DOMAIN" ]; then
    DOMAIN="$CERTBOT_DOMAIN"
    SUB_DOMAIN=""
fi

# 构建请求体 (JSON)
if [ -z "$SUB_DOMAIN" ]; then
    # 主域名本身: _acme-challenge 作为主机记录
    REQUEST_BODY="{\"Domain\":\"$DOMAIN\",\"SubDomain\":\"_acme-challenge\",\"RecordType\":\"TXT\",\"RecordLine\":\"默认\",\"Value\":\"$CERTBOT_VALIDATION\"}"
else
    # 子域名: _acme-challenge.xxx 作为主机记录
    REQUEST_BODY="{\"Domain\":\"$DOMAIN\",\"SubDomain\":\"_acme-challenge.$SUB_DOMAIN\",\"RecordType\":\"TXT\",\"RecordLine\":\"默认\",\"Value\":\"$CERTBOT_VALIDATION\"}"
fi

# 构建 CanonicalRequest
CANONICAL_URI="/"
CANONICAL_QUERY_STRING=""
PAYLOAD_HASH=$(printf "%s" "$REQUEST_BODY" | openssl dgst -sha256 -hex | awk '{print $2}')
CANONICAL_HEADERS="content-type:application/json\nhost:$HOST\n"
SIGNED_HEADERS="content-type;host"
CANONICAL_REQUEST="POST\n$CANONICAL_URI\n$CANONICAL_QUERY_STRING\n$CANONICAL_HEADERS\n$SIGNED_HEADERS\n$PAYLOAD_HASH"

# 构建待签名字符串
CREDENTIAL_SCOPE="$DATE/$SERVICE/tc3_request"
HASHED_CANONICAL_REQUEST=$(printf "%s" "$CANONICAL_REQUEST" | openssl dgst -sha256 -hex | awk '{print $2}')
STRING_TO_SIGN="$ALGORITHM\n$TIMESTAMP\n$CREDENTIAL_SCOPE\n$HASHED_CANONICAL_REQUEST"

# 计算签名
SECRET_DATE=$(printf "%s" "$DATE" | openssl dgst -sha256 -hmac "TC3$DP_SecretKey" -hex | awk '{print $2}')
SECRET_SERVICE=$(printf "%s" "$SERVICE" | openssl dgst -sha256 -mac hmac -macopt hexkey:$SECRET_DATE -hex | awk '{print $2}')
SECRET_SIGNING=$(printf "%s" "tc3_request" | openssl dgst -sha256 -mac hmac -macopt hexkey:$SECRET_SERVICE -hex | awk '{print $2}')
SIGNATURE=$(printf "%s" "$STRING_TO_SIGN" | openssl dgst -sha256 -mac hmac -macopt hexkey:$SECRET_SIGNING -hex | awk '{print $2}')
AUTHORIZATION_HEADER="$ALGORITHM Credential=$DP_SecretId/$CREDENTIAL_SCOPE, SignedHeaders=$SIGNED_HEADERS, Signature=$SIGNATURE"

# 发送请求
RESPONSE=$(curl -s -X POST "https://$HOST" \
    -H "Authorization: $AUTHORIZATION_HEADER" \
    -H "Content-Type: application/json" \
    -H "Host: $HOST" \
    -H "X-TC-Action: $ACTION" \
    -H "X-TC-Version: $VERSION" \
    -H "X-TC-Timestamp: $TIMESTAMP" \
    -d "$REQUEST_BODY")

# 检查是否成功
if echo "$RESPONSE" | grep -q '"Error"'; then
    echo "错误: 添加 TXT 记录失败" 1>&2
    echo "$RESPONSE" 1>&2
    exit 1
fi

echo "成功添加 TXT 记录: _acme-challenge.$SUB_DOMAIN.$DOMAIN"
/bin/sleep 30
