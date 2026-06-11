"""公共工具: 域名归一化、注册域名提取、URL 解析。"""
from __future__ import annotations

from urllib.parse import urlparse

# 常见多段公共后缀, 用于把 host 归并到"注册域名"。
# 不引入 tldextract 依赖, 用一份够用的清单覆盖中国+国际常见情况。
_MULTI_SUFFIX = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "co.kr", "com.hk",
    "com.tw", "com.sg", "com.au", "co.in",
}


def normalize_host(value: str) -> str:
    """从 URL 或裸 host 中提取纯主机名(小写, 去端口/路径)。"""
    if not value:
        return ""
    v = value.strip().lower()
    if "://" not in v:
        v = "//" + v
    netloc = urlparse(v).netloc or urlparse(v).path
    host = netloc.split("@")[-1].split(":")[0].strip("/")
    # 去掉 FQDN 尾部点: "qq.com." 会让 registered_domain 得到错误归并键 "com.",
    # 并使 is_official 匹配失效(尾点变体绕过白名单)。
    return host.rstrip(".")


def clean_keywords(keywords: list[str], min_len: int = 2) -> list[str]:
    """清洗关键词列表: 去空白、特殊符号、短词。"""
    cleaned = []
    for kw in keywords:
        kw = kw.strip().strip('；;，,。、\t\r\n\'\"')
        if len(kw) >= min_len:
            cleaned.append(kw)
    return cleaned


def registered_domain(host: str) -> str:
    """提取注册域名(归并键)。例: a.b.example.com.cn -> example.com.cn。"""
    host = normalize_host(host)
    if not host or _is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _is_ip(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def is_official(host: str, official_domains: list[str]) -> bool:
    """host 是否属于官方域名(或其子域)。"""
    rd = registered_domain(host)
    h = normalize_host(host)
    for od in official_domains:
        od = normalize_host(od)
        if not od:
            continue
        if h == od or h.endswith("." + od) or rd == registered_domain(od):
            return True
    return False
