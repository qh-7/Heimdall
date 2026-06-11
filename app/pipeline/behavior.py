"""行为分析: Playwright 并发访问候选站, 抓取截图与特征。

每个候选:
  - 访问 https?://host, 记录最终 URL(跳转链)
  - 截图存盘
  - 检测: 密码表单 / 登录关键词 / 支付特征 / 品牌词出现
  - 计算页面 favicon hash, 与官方对比
单站失败(超时/拒连)不影响其它站, 记录 error 标记。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timezone

from app.config import Config
from app.db import engine
from app.models import Candidate
from app.pipeline.discovery.favicon import compute_icon_hash
from app.pipeline.tasklog import log_task
from app.pipeline.utils import is_official, normalize_host

_PAYMENT_PAT = re.compile(r"(支付|付款|收款|充值|银行卡|信用卡|二维码|扫码|pay|wechat\s*pay|alipay)", re.I)
_LOGIN_PAT = re.compile(r"(登录|登入|登陆|账号|帐号|密码|login|sign\s*in|password)", re.I)


def _update_candidate_db(task_id: int, cand: Candidate) -> None:
    """即时更新单个候选的截图路径和行为分析结果到 DB。"""
    try:
        from sqlmodel import Session, select
        db = Session(engine)
        existing = db.exec(
            select(Candidate).where(
                Candidate.task_id == task_id,
                Candidate.domain == cand.domain,
            )
        ).first()
        if existing:
            existing.behavior_flags = cand.behavior_flags
            existing.screenshot_path = cand.screenshot_path
            existing.final_url = cand.final_url
            existing.title = cand.title or existing.title
            existing.icon_hash = cand.icon_hash or existing.icon_hash
            existing.icon_match = cand.icon_match or existing.icon_match
            db.commit()
        db.close()
    except Exception:
        pass


def _shot_key(domain: str) -> str:
    """稳定的截图名后缀: md5(域名) 前12位。

    内置 hash() 受 PYTHONHASHSEED 影响, 每次进程随机, 会导致同一域名跨次运行文件名漂移
    (产生孤儿截图), 不同域名也可能碰撞覆盖。改用 md5 保证稳定且基本无碰撞。
    """
    return hashlib.md5(domain.encode("utf-8")).hexdigest()[:12]


async def _analyze_one(browser, cfg: Config, cand: Candidate, task, sem, shot_dir) -> None:
    flags = json.loads(cand.behavior_flags) if cand.behavior_flags else {}
    official = task.domains_list()
    brand = task.keywords_list()
    timeout = int(cfg.get("behavior.nav_timeout_ms", 5000))
    want_shot = bool(cfg.get("behavior.screenshot", True))
    ua = cfg.get("general.user_agent", "")

    host = cand.host
    # 尝试 HTTPS 和 HTTP, 优先 HTTPS
    urls_to_try = []
    if "://" in host:
        urls_to_try.append(host)
    else:
        urls_to_try.append(f"https://{host}")
        urls_to_try.append(f"http://{host}")

    async with sem:
        for url in urls_to_try:
            context = await browser.new_context(
                user_agent=ua,
                ignore_https_errors=True,
                bypass_csp=True,
            )
            page = await context.new_page()
            try:
                resp = await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
                if resp and resp.status >= 400:
                    await context.close()
                    continue  # 4xx/5xx, 尝试下一个 URL
                # 成功加载
                final_url = page.url
                cand.final_url = final_url
                final_host = normalize_host(final_url)

                flags["redirect_offsite"] = (
                    final_host != normalize_host(cand.host)
                    and not is_official(final_host, official)
                )

                title = await page.title()
                if title:
                    cand.title = cand.title or title

                html = await page.content()

                pwd_count = await page.locator("input[type='password']").count()
                flags["login_form"] = pwd_count > 0 or bool(_LOGIN_PAT.search(html))
                flags["payment"] = bool(_PAYMENT_PAT.search(html))
                flags["brand_in_content"] = any(
                    kw.lower() in html.lower() for kw in brand if kw
                )

                # 页面 favicon 对比
                try:
                    fav = await page.evaluate(
                        "() => { const l = document.querySelector(\"link[rel*='icon']\");"
                        " return l ? l.href : (location.origin + '/favicon.ico'); }"
                    )
                    if fav:
                        r = await context.request.get(fav, timeout=timeout)
                        if r.ok:
                            body = await r.body()
                            if body:
                                cand.icon_hash = cand.icon_hash or compute_icon_hash(body)
                except Exception:
                    pass

                if want_shot:
                    shot_path = shot_dir / f"cand_{cand.task_id}_{_shot_key(cand.domain)}.png"
                    await page.screenshot(path=str(shot_path), full_page=False)
                    cand.screenshot_path = shot_path.name

                flags["http_status"] = resp.status if resp else 0
                flags["reachable"] = True
                await context.close()
                break  # 成功, 不再尝试下一个 URL

            except Exception as e:
                flags["reachable"] = False
                flags["error"] = f"{type(e).__name__}"
                # 即使失败也尝试截图(可能页面部分加载)
                if want_shot and not cand.screenshot_path:
                    try:
                        shot_path = shot_dir / f"cand_{cand.task_id}_{_shot_key(cand.domain)}.png"
                        await page.screenshot(path=str(shot_path), full_page=False)
                        cand.screenshot_path = shot_path.name
                    except Exception:
                        pass
            finally:
                await context.close()

    cand.behavior_flags = json.dumps(flags, ensure_ascii=False)


async def analyze(candidates: list[Candidate], task, cfg: Config,
                  task_id: int = 0) -> list[Candidate]:
    """对候选批量做行为分析。未启用则原样返回。task_id 非零时写实时日志。"""
    if not cfg.get("behavior.enabled") or not candidates:
        return candidates

    from playwright.async_api import async_playwright

    shot_dir = cfg.abspath(cfg.get("general.screenshot_dir", "app/data/screenshots"))
    shot_dir.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(int(cfg.get("behavior.max_concurrency", 5)))
    total = len(candidates)
    done_count = [0]  # 用列表包一层, 闭包内可写

    original_analyze_one = _analyze_one

    async def _analyze_with_log(browser, cfg, cand, task, sem, shot_dir):
        await original_analyze_one(browser, cfg, cand, task, sem, shot_dir)
        done_count[0] += 1
        if task_id and done_count[0] % 5 == 0:
            log_task(task_id, f"  行为分析: {done_count[0]}/{total}")
        # ★ 即时写 DB: 截图和分析结果立即对前端可见
        if task_id:
            _update_candidate_db(task_id, cand)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            # return_exceptions=True: 单个候选的未捕获异常(如 new_context/new_page 失败)
            # 不会中断整批 gather, 保证"单站失败不影响其它站"。
            results = await asyncio.gather(*[
                _analyze_with_log(browser, cfg, c, task, sem, shot_dir) for c in candidates
            ], return_exceptions=True)
            errs = sum(1 for r in results if isinstance(r, Exception))
            if errs and task_id:
                log_task(task_id, f"  行为分析: {errs} 个候选异常被跳过")
        finally:
            await browser.close()
    return candidates
