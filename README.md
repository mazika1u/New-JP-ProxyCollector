# New-JP-ProxyCollector
リメイク版

日本向けの公開Proxy収集・検証tool

## 特徴
- 複数のソースURLから IP:PORT を自動抽出
- HTTP/HTTPS プロキシ両対応
- aiohttp による非同期検証
- IP 国コード判定で日本限定のProxyを抽出
- 重複削除・進捗表示・ログ出力

## インストール
```bash
git clone https://github.com/mazika1u/New-JP-ProxyCollector.git
cd New-JP-ProxyCollector
pip install -r requirements.txt
python main.py --sources sources.txt --out all.txt --out-jp jp.txt --concurrency 50 --timeout 8
