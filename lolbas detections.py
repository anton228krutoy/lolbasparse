#!/usr/bin/env python3
"""
Собирает правила детектирования (Sigma / Splunk / Elastic / ...) для всех
записей LOLBAS и раскладывает их по папкам:

    lolbas_detections/
    ├── index.csv                       # общий индекс: утилита -> правило -> файл
    ├── failed.txt                      # что не удалось скачать
    ├── Binaries/
    │   └── Certutil.exe/
    │       ├── lolbas_entry.yml        # сама запись LOLBAS (команды, пути и т.д.)
    │       ├── iocs.txt                # IOC из записи
    │       ├── other_links.txt         # ссылки не на файлы (блоги, доки)
    │       ├── sigma/*.yml
    │       ├── splunk/*.yml
    │       └── elastic/*.toml
    ├── Libraries/...
    ├── OtherMSBinaries/...
    └── Scripts/...

Источник данных: официальный API https://lolbas-project.github.io/api/lolbas.json

Установка:  pip install requests pyyaml
Запуск:     python lolbas_detections.py -o lolbas_detections -w 16
"""

import argparse
import csv
import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests
import yaml

API_URL = "https://lolbas-project.github.io/api/lolbas.json"
RULE_EXTENSIONS = (".yml", ".yaml", ".toml", ".json", ".kql", ".spl", ".xml", ".txt")
HEADERS = {"User-Agent": "lolbas-detection-collector/1.0"}

_thread_local = threading.local()
_cache: dict[str, bytes | None] = {}
_cache_lock = threading.Lock()


def session() -> requests.Session:
    """Отдельная сессия на поток (requests.Session не потокобезопасна)."""
    if not hasattr(_thread_local, "s"):
        s = requests.Session()
        s.headers.update(HEADERS)
        _thread_local.s = s
    return _thread_local.s


def safe_name(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).strip() or "unnamed"


def to_raw_url(url: str) -> str | None:
    """
    github.com/<owner>/<repo>/blob/<ref>/<path>  ->  raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>
    Возвращает None, если ссылка не похожа на конкретный файл правила.
    """
    p = urlparse(url.strip())
    path = unquote(p.path)

    if p.netloc == "raw.githubusercontent.com":
        return url if path.lower().endswith(RULE_EXTENSIONS) else None

    if p.netloc in ("github.com", "www.github.com"):
        m = re.match(r"^/([^/]+)/([^/]+)/blob/(.+)$", path)
        if m and path.lower().endswith(RULE_EXTENSIONS):
            owner, repo, rest = m.groups()
            return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}"
        return None  # tree/, папки, issues и т.п.

    # Прямая ссылка на файл где-то ещё
    if path.lower().endswith(RULE_EXTENSIONS):
        return url
    return None


def download(raw_url: str, timeout: int = 30) -> bytes | None:
    """Скачивание с кешем: одно правило часто привязано к нескольким утилитам."""
    with _cache_lock:
        if raw_url in _cache:
            return _cache[raw_url]
    data = None
    try:
        r = session().get(raw_url, timeout=timeout)
        if r.status_code == 200:
            data = r.content
    except requests.RequestException:
        pass
    with _cache_lock:
        _cache[raw_url] = data
    return data


def parse_detections(entry: dict):
    """
    Detection в LOLBAS — список словарей вида {"Sigma": url}, {"Splunk": url},
    {"Elastic": url}, {"IOC": "текст"} и т.д.
    """
    rules, iocs = [], []
    for item in entry.get("Detection") or []:
        if not isinstance(item, dict):
            continue
        for kind, value in item.items():
            if not value:
                continue
            value = str(value).strip()
            if kind.upper() == "IOC" or not value.lower().startswith("http"):
                iocs.append(f"[{kind}] {value}")
            else:
                rules.append((kind, value))
    return rules, iocs


def process_entry(entry: dict, out_root: Path):
    name = entry.get("Name", "unnamed")
    category = entry.get("Category") or "Unknown"
    tool_dir = out_root / safe_name(category) / safe_name(name)
    tool_dir.mkdir(parents=True, exist_ok=True)

    # Сохраняем саму запись LOLBAS рядом с правилами
    with open(tool_dir / "lolbas_entry.yml", "w", encoding="utf-8") as f:
        yaml.safe_dump(entry, f, allow_unicode=True, sort_keys=False)

    rules, iocs = parse_detections(entry)
    if iocs:
        (tool_dir / "iocs.txt").write_text("\n".join(iocs) + "\n", encoding="utf-8")

    index_rows, failed, other_links = [], [], []
    for kind, url in rules:
        raw = to_raw_url(url)
        if raw is None:
            other_links.append(f"[{kind}] {url}")
            index_rows.append([category, name, kind, url, "", "link_only"])
            continue

        data = download(raw)
        if data is None:
            failed.append(f"{category}/{name}\t[{kind}]\t{url}")
            index_rows.append([category, name, kind, url, "", "failed"])
            continue

        kind_dir = tool_dir / safe_name(kind.lower())
        kind_dir.mkdir(exist_ok=True)
        fname = safe_name(Path(unquote(urlparse(raw).path)).name)
        target = kind_dir / fname
        # если два разных правила с одинаковым именем файла
        i = 1
        while target.exists() and target.read_bytes() != data:
            target = kind_dir / f"{Path(fname).stem}_{i}{Path(fname).suffix}"
            i += 1
        target.write_bytes(data)
        index_rows.append([category, name, kind, url,
                           str(target.relative_to(out_root)), "ok"])

    if other_links:
        (tool_dir / "other_links.txt").write_text("\n".join(other_links) + "\n",
                                                   encoding="utf-8")
    return name, index_rows, failed


def main():
    ap = argparse.ArgumentParser(description="Сбор правил детектирования LOLBAS")
    ap.add_argument("-o", "--out", default="lolbas_detections", help="папка вывода")
    ap.add_argument("-w", "--workers", type=int, default=16, help="число потоков")
    ap.add_argument("-c", "--category", action="append",
                    help="только эти категории (Binaries, Libraries, "
                         "OtherMSBinaries, Scripts); можно несколько раз")
    args = ap.parse_args()

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"[*] Загружаю {API_URL}")
    try:
        r = requests.get(API_URL, headers=HEADERS, timeout=60)
        r.raise_for_status()
        entries = r.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        sys.exit(f"[!] Не удалось получить API: {e}")

    if args.category:
        wanted = {c.lower() for c in args.category}
        entries = [e for e in entries if (e.get("Category") or "").lower() in wanted]
    print(f"[*] Записей: {len(entries)}")

    all_rows, all_failed = [], []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(process_entry, e, out_root) for e in entries]
        for n, fut in enumerate(as_completed(futures), 1):
            try:
                name, rows, failed = fut.result()
            except Exception as e:  # не роняем весь прогон из-за одной записи
                print(f"[!] Ошибка: {e}")
                continue
            ok = sum(1 for r in rows if r[-1] == "ok")
            print(f"[{n}/{len(entries)}] {name}: правил скачано {ok}, ссылок {len(rows)}")
            all_rows.extend(rows)
            all_failed.extend(failed)

    all_rows.sort(key=lambda r: (r[0], r[1].lower(), r[2]))
    with open(out_root / "index.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["category", "tool", "type", "source_url", "local_file", "status"])
        w.writerows(all_rows)

    if all_failed:
        (out_root / "failed.txt").write_text("\n".join(sorted(all_failed)) + "\n",
                                              encoding="utf-8")

    ok = sum(1 for r in all_rows if r[-1] == "ok")
    print(f"\n[+] Готово. Файлов правил: {ok}, только ссылок: "
          f"{sum(1 for r in all_rows if r[-1] == 'link_only')}, "
          f"ошибок: {len(all_failed)}")
    print(f"[+] Результат: {out_root.resolve()}")


if __name__ == "__main__":
    main()
