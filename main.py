import re
import argparse
import asyncio
import aiohttp
import time
from typing import List, Set
from bs4 import BeautifulSoup
import requests
import urllib.robotparser
from urllib.parse import urlparse
import sys

DEFAULT_USER_AGENT = "JP-ProxyCollector/2.0 (+https://example.local/)"
IP_PORT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})\s*[:]\s*(\d{2,5})')

def load_sources(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

def allowed_by_robots(url: str, user_agent: str = DEFAULT_USER_AGENT) -> bool:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(base + "/robots.txt")
    try:
        rp.read()
    except Exception:
        return True
    return rp.can_fetch(user_agent, url)

def fetch_html(url: str, timeout: int = 10, user_agent: str = DEFAULT_USER_AGENT) -> str | None:
    headers = {"User-Agent": user_agent}
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] fetch failed: {url} -> {e}")
        return None

def extract_proxies_from_text(text: str) -> Set[str]:
    proxies = set()
    for m in IP_PORT_RE.finditer(text):
        ip, port = m.group(1), m.group(2)
        if all(0 <= int(x) < 256 for x in ip.split('.')) and 1 <= int(port) <= 65535:
            proxies.add(f"{ip}:{port}")
    return proxies

def parse_html_for_proxies(html: str) -> Set[str]:
    proxies = set()
    soup = BeautifulSoup(html, "html.parser")
    proxies |= extract_proxies_from_text(soup.get_text(separator=' '))
    tables = soup.find_all("table")
    for table in tables:
        rows = table.find_all("tr")
        for tr in rows:
            cols = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
            if not cols:
                continue
            joined = " ".join(cols)
            proxies |= extract_proxies_from_text(joined)
    return proxies

async def probe_proxy(session: aiohttp.ClientSession, proxy: str, timeout: int) -> dict:
    """
    proxy: "ip:port"
    戻り値: {'proxy':..., 'ok': True/False, 'country': 'JP'/'US'/None, 'latency': float}
    """
    proxy_url = f"http://{proxy}"  # HTTPプロキシ
    test_url = "http://ip-api.com/json/"
    start = time.time()
    try:
        async with session.get(test_url, proxy=proxy_url, timeout=timeout) as resp:
            text = await resp.text()
            elapsed = time.time() - start
            if '"countryCode"' in text:
                import json
                try:
                    data = json.loads(text)
                    cc = data.get('countryCode', None)
                except Exception:
                    cc = None
                return {'proxy': proxy, 'ok': True, 'country': cc, 'latency': elapsed}
            return {'proxy': proxy, 'ok': True, 'country': None, 'latency': elapsed}
    except Exception:
        return {'proxy': proxy, 'ok': False, 'country': None, 'latency': None}

async def validate_proxies(proxies: List[str], concurrency: int = 50, timeout: int = 8) -> List[dict]:
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    timeout_obj = aiohttp.ClientTimeout(total=timeout+2)
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    results = []
    async with aiohttp.ClientSession(connector=connector, timeout=timeout_obj, headers=headers) as session:
        sem = asyncio.Semaphore(concurrency)
        async def sem_task(proxy):
            async with sem:
                return await probe_proxy(session, proxy, timeout)
        tasks = [asyncio.create_task(sem_task(p)) for p in proxies]
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
            print(f"[PROBE] {res['proxy']} -> ok={res['ok']} country={res['country']} latency={res['latency']}")
    return results

def main():
    parser = argparse.ArgumentParser(description="JP Proxy Collector - Super Complete Edition")
    parser.add_argument("--sources", required=True, help="ソースURLリストファイル or 単独URL")
    parser.add_argument("--out", default="proxies_all.txt", help="抽出した全プロキシ出力")
    parser.add_argument("--out-jp", default="proxies_jp.txt", help="JP判定されたプロキシ出力")
    parser.add_argument("--concurrency", type=int, default=50, help="同時検証数")
    parser.add_argument("--timeout", type=int, default=8, help="検証タイムアウト(秒)")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent")
    parser.add_argument("--min-delay", type=float, default=1.0, help="各ソース間待機秒")
    args = parser.parse_args()

    import os
    if os.path.exists(args.sources) and os.path.isfile(args.sources):
        urls = load_sources(args.sources)
    else:
        urls = [args.sources.strip()]

    print(f"[INFO] {len(urls)} sources loaded.")
    collected = set()
    for url in urls:
        print(f"[FETCH] {url}")
        if not allowed_by_robots(url, args.user_agent):
            print(f"[WARN] robots.txt によりアクセス制限の可能性: {url}")
            continue
        html = fetch_html(url, timeout=args.timeout, user_agent=args.user_agent)
        if not html:
            continue
        found = parse_html_for_proxies(html)
        print(f"[FOUND] {len(found)} proxies in {url}")
        collected |= found
        time.sleep(args.min_delay)

    print(f"[TOTAL] unique proxies collected: {len(collected)}")
    with open(args.out, "w", encoding="utf-8") as f:
        for pxy in sorted(collected):
            f.write(pxy + "\n")
    print(f"[SAVED] all -> {args.out}")

    if not collected:
        print("[INFO] 検証対象なし。終了")
        return

    proxies_list = sorted(collected)
    loop = asyncio.get_event_loop()
    results = loop.run_until_complete(validate_proxies(proxies_list, concurrency=args.concurrency, timeout=args.timeout))

    jp_proxies = [r['proxy'] for r in results if r['ok'] and r['country'] == 'JP']
    print(f"[RESULT] JP proxies: {len(jp_proxies)}")
    with open(args.out_jp, "w", encoding="utf-8") as f:
        for p in jp_proxies:
            f.write(p + "\n")
    print(f"[SAVED] JP -> {args.out_jp}")


if __name__ == "__main__":
    main()
