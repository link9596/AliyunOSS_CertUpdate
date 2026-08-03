#!/usr/bin/env python3
import os
import sys
import json
import time
import hashlib
import hmac
import requests
from datetime import datetime

# 环境变量
SECRET_ID = os.environ.get('DP_SecretId')
SECRET_KEY = os.environ.get('DP_SecretKey')
DOMAIN = os.environ.get('CERTBOT_DOMAIN')
VALIDATION = os.environ.get('CERTBOT_VALIDATION')

if not SECRET_ID or not SECRET_KEY:
    print("错误: 请设置环境变量 DP_SecretId 和 DP_SecretKey", file=sys.stderr)
    sys.exit(1)

if not DOMAIN or not VALIDATION:
    print("错误: 缺少 CERTBOT_DOMAIN 或 CERTBOT_VALIDATION", file=sys.stderr)
    sys.exit(1)

# ---------- 解析域名 ----------
def parse_domain(full):
    # 简单处理：提取主域名（最后两个或三个部分）
    parts = full.split('.')
    if len(parts) >= 3 and parts[-2] in ('com', 'gov', 'net', 'org', 'ac', 'gd') and parts[-1] == 'cn':
        # 双后缀，如 example.com.cn
        main_domain = '.'.join(parts[-3:])
        sub_domain = '.'.join(parts[:-3])
    else:
        main_domain = '.'.join(parts[-2:])
        sub_domain = '.'.join(parts[:-2])
    return main_domain, sub_domain

main_domain, sub_domain = parse_domain(DOMAIN)
if sub_domain:
    rr = f"_acme-challenge.{sub_domain}"
else:
    rr = "_acme-challenge"

# ---------- 腾讯云 TC3 签名（完全来自 Worker JS）----------
def sha256_hex(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def hmac_sha256(key, msg, is_hex=False):
    if is_hex:
        key = bytes.fromhex(key)
    else:
        key = key.encode('utf-8')
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def tc3_sign(secret_key, date, service, string_to_sign):
    # 派生签名密钥
    secret_date = hmac_sha256("TC3" + secret_key, date)
    secret_service = hmac_sha256(secret_date.hex(), service, is_hex=True)
    secret_signing = hmac_sha256(secret_service.hex(), "tc3_request", is_hex=True)
    signature = hmac_sha256(secret_signing.hex(), string_to_sign, is_hex=True)
    return signature.hex()

def call_dnspod(action, payload):
    host = "dnspod.tencentcloudapi.com"
    service = "dnspod"
    version = "2021-03-23"
    algorithm = "TC3-HMAC-SHA256"
    timestamp = int(time.time())
    date = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')

    # 构建规范请求
    http_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    content_type = "application/json; charset=utf-8"
    action_lower = action.lower()
    canonical_headers = f"content-type:{content_type}\nhost:{host}\nx-tc-action:{action_lower}\n"
    signed_headers = "content-type;host;x-tc-action"

    payload_str = json.dumps(payload, separators=(',', ':'))
    hashed_payload = sha256_hex(payload_str)
    canonical_request = f"{http_method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"

    hashed_canonical_request = sha256_hex(canonical_request)
    credential_scope = f"{date}/{service}/tc3_request"
    string_to_sign = f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

    signature = tc3_sign(SECRET_KEY, date, service, string_to_sign)
    authorization = f"{algorithm} Credential={SECRET_ID}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    headers = {
        "Authorization": authorization,
        "Content-Type": content_type,
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(timestamp),
    }
    response = requests.post(f"https://{host}", headers=headers, data=payload_str)
    return response.json()

# ---------- 主逻辑 ----------
if len(sys.argv) > 1 and sys.argv[1] == "clean":
    # 删除记录
    query_payload = {
        "Domain": main_domain,
        "SubDomain": rr,
        "RecordType": "TXT"
    }
    resp = call_dnspod("DescribeRecordFilterList", query_payload)
    if "Response" in resp and "Error" in resp["Response"]:
        print(f"查询记录失败: {resp['Response']['Error']}", file=sys.stderr)
        sys.exit(1)
    records = resp.get("Response", {}).get("RecordList", [])
    if not records:
        print("未找到记录，无需清理")
        sys.exit(0)
    record_id = records[0]["RecordId"]
    delete_payload = {
        "Domain": main_domain,
        "RecordId": record_id
    }
    del_resp = call_dnspod("DeleteRecord", delete_payload)
    if "Response" in del_resp and "Error" in del_resp["Response"]:
        print(f"删除记录失败: {del_resp['Response']['Error']}", file=sys.stderr)
        sys.exit(1)
    print(f"成功删除 TXT 记录: {rr}.{main_domain}")
    sys.exit(0)
else:
    # 添加记录
    add_payload = {
        "Domain": main_domain,
        "SubDomain": rr,
        "RecordType": "TXT",
        "RecordLine": "默认",
        "Value": VALIDATION
    }
    resp = call_dnspod("CreateRecord", add_payload)
    if "Response" in resp and "Error" in resp["Response"]:
        print(f"添加记录失败: {resp['Response']['Error']}", file=sys.stderr)
        sys.exit(1)
    print(f"成功添加 TXT 记录: {rr}.{main_domain}")
    time.sleep(60)  # 等待 DNS 传播
    sys.exit(0)
