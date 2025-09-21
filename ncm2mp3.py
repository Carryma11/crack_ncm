#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import base64
import struct
import binascii
import warnings
import mimetypes

import requests
from Crypto.Cipher import AES
import eyed3


# ------------------------------
# HTTP 下载工具
# ------------------------------

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/100.0.4896.127 Safari/537.36"
    )
})


def download_pic(url: str, save_fn: str, timeout: float = 10.0,
                 retries: int = 3, backoff: float = 2.0) -> str:
    """
    下载封面图片到 save_fn，并返回响应的 Content-Type（mime）。
    采用流式下载 + 原子写，失败会按指数退避重试。
    """
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            with SESSION.get(url, timeout=timeout, stream=True) as r:
                r.raise_for_status()
                mime = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
                tmp = save_fn + ".part"
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(64 * 1024):
                        if chunk:
                            f.write(chunk)
                os.replace(tmp, save_fn)
                return mime
        except Exception as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff ** attempt)
            else:
                raise RuntimeError(f"图片下载失败: {exc}") from exc
    raise last_exc  # 理论不可达


# ------------------------------
# MP3 写封面
# ------------------------------

def add_cover_2_mp3(mp3_fp: str, pic_fp: str, mime_type: str) -> None:
    """
    给 MP3 写入 APIC 封面。只处理 MP3；PNG/JPEG通常兼容，WEBP 常见兼容性差会跳过。
    """
    if not mp3_fp.lower().endswith(".mp3"):
        return

    if mime_type not in {"image/jpeg", "image/jpg", "image/png"}:
        warnings.warn(f"封面格式不受支持，跳过：{mime_type}")
        return

    audio = eyed3.load(mp3_fp)
    if audio is None:
        warnings.warn(f"无法加载 MP3：{mp3_fp}")
        return
    if audio.tag is None:
        audio.initTag()

    with open(pic_fp, "rb") as fh:
        audio.tag.images.set(3, fh.read(), mime_type)
    audio.tag.save()


# ------------------------------
# NCM 解密核心
# ------------------------------

def dump_ncm(input_fp: str, output_fp: str) -> str:
    """
    解密 NCM 文件为音频（mp3 或 flac），并尝试写入封面（仅 MP3）。
    返回最终写入的音频文件完整路径。
    """
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    unpad = lambda s: s[:-(s[-1] if isinstance(s[-1], int) else ord(s[-1]))]

    with open(input_fp, "rb") as f:
        header = f.read(8)
        # 'CTENFDAM'
        assert binascii.b2a_hex(header) == b"4354454e4644414d"
        f.seek(2, 1)

        # 解密 key 数据
        key_length = struct.unpack("<I", f.read(4))[0]
        key_data = bytearray(f.read(key_length))
        for i in range(len(key_data)):
            key_data[i] ^= 0x64

        key_data = unpad(AES.new(core_key, AES.MODE_ECB).decrypt(bytes(key_data)))[17:]

        # 初始化 key_box（RC4-like）
        key_box = bytearray(range(256))
        c = 0
        last = 0
        off = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last + key_data[off]) & 0xFF
            off = (off + 1) % len(key_data)
            key_box[i], key_box[c] = key_box[c], key_box[i]
            last = c

        # 读取 meta 并解密
        meta_length = struct.unpack("<I", f.read(4))[0]
        meta_data = bytearray(f.read(meta_length))
        for i in range(len(meta_data)):
            meta_data[i] ^= 0x63
        meta_data = base64.b64decode(bytes(meta_data)[22:])
        meta_raw = AES.new(meta_key, AES.MODE_ECB).decrypt(meta_data)
        meta = json.loads(unpad(meta_raw).decode("utf-8")[6:])

        # 跳过内置封面二进制（后续通过 URL 下载）
        f.read(4)  # 跳过 crc32
        f.seek(5, 1)
        img_size = struct.unpack("<I", f.read(4))[0]
        f.read(img_size)

        # 输出文件扩展名按 meta['format'] 决定
        ext = meta.get("format", "mp3").lower()
        if not output_fp.lower().endswith("." + ext):
            output_fp = os.path.splitext(output_fp)[0] + "." + ext

        # 解密音频数据
        with open(output_fp, "wb") as m:
            while True:
                chunk = bytearray(f.read(0x8000))
                if not chunk:
                    break
                n = len(chunk)
                for i in range(1, n + 1):
                    j = i & 0xFF
                    idx = (key_box[j] + key_box[(key_box[j] + j) & 0xFF]) & 0xFF
                    chunk[i - 1] ^= key_box[idx]
                m.write(chunk)

    # 下载封面并写入（最佳努力）
    cover_url = (meta.get("albumPic") or "").strip()
    if cover_url:
        # 临时文件后缀仅用于保存；真正的 MIME 以响应头为准
        tmp_ext = mimetypes.guess_extension(cover_url.split("?")[0]) or ".img"
        tmp_file = os.path.join(
            os.path.dirname(output_fp),
            f".cover_{os.path.basename(output_fp)}{tmp_ext}"
        )
        try:
            mime = download_pic(cover_url, tmp_file)
            add_cover_2_mp3(output_fp, tmp_file, mime)
        except Exception as exc:
            warnings.warn(f"封面处理失败：{exc}")
        finally:
            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except OSError:
                pass
    else:
        warnings.warn("未发现专辑封面 URL，跳过添加封面")

    return output_fp


# ------------------------------
# 单文件转换（供进程池调用）
# ------------------------------

def _convert_one(ncm_path: str, out_dir: str, max_cpu_percent: int = 80) -> bool:
    """
    转换单个 .ncm 文件。成功返回 True。
    """
    base = os.path.basename(ncm_path)
    if not base.lower().endswith(".ncm"):
        return False

    out_fp = os.path.join(out_dir, os.path.splitext(base)[0] + ".mp3")

    # 简单 CPU 限流（可选）。若 psutil 不可用则直接继续。
    try:
        import psutil
        while psutil.cpu_percent(interval=0.5) > max_cpu_percent:
            time.sleep(0.5)
    except Exception:
        pass

    try:
        dump_ncm(ncm_path, out_fp)
        return True
    except Exception as exc:
        print(f"转换失败：{ncm_path}，原因：{exc}")
        return False


# ------------------------------
# 批量入口
# ------------------------------

def main() -> None:
    import argparse
    from concurrent.futures import ProcessPoolExecutor, as_completed
    from tqdm import tqdm

    # 默认搜索路径
    default_path = r"D:\data\NeteaseCloudMusic\VipSongsDownload"

    parser = argparse.ArgumentParser(
        description="将 NetEase .ncm 批量解密为音频（自动加封面，仅 MP3）。"
    )
    parser.add_argument(
        "-p", "--path", default=default_path,
        help=f"包含 .ncm 文件的目录 (默认: {default_path})"
    )
    parser.add_argument(
        "--workers", type=int, default=0, help="进程数（默认=80% CPU 核心数）"
    )
    parser.add_argument(
        "--max-cpu", type=int, default=80, help="最大 CPU 占用阈值（%）"
    )
    args = parser.parse_args()

    root_dir = os.path.abspath(args.path)
    assert os.path.isdir(root_dir), "请输入正确的目录路径"

    output_root = os.path.join(root_dir, "output")
    os.makedirs(output_root, exist_ok=True)

    # 递归收集未转换的文件
    files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for fname in filenames:
            if not fname.lower().endswith(".ncm"):
                continue
            rel_path = os.path.relpath(dirpath, root_dir)   # 相对路径
            base = os.path.splitext(fname)[0]

            # 输出目录与输入保持相对结构
            out_dir = os.path.join(output_root, rel_path)
            os.makedirs(out_dir, exist_ok=True)

            out_mp3 = os.path.join(out_dir, base + ".mp3")
            out_flac = os.path.join(out_dir, base + ".flac")

            # 已经转换过就跳过
            if os.path.exists(out_mp3) or os.path.exists(out_flac):
                continue

            files.append((os.path.join(dirpath, fname), out_dir))

    if not files:
        print("未找到需要转换的 .ncm 文件（可能都已转换过）")
        return

    cpu_count = os.cpu_count() or 1
    max_workers = args.workers if args.workers > 0 else max(1, int(cpu_count * 0.8))

    ok = 0
    with ProcessPoolExecutor(max_workers=max_workers) as ex:
        futures = [
            ex.submit(_convert_one, ncm_path, out_dir, args.max_cpu)
            for ncm_path, out_dir in files
        ]
        with tqdm(total=len(futures), desc="Converting") as pbar:
            for fut in as_completed(futures):
                try:
                    if fut.result():
                        ok += 1
                except Exception:
                    pass
                pbar.update(1)

    print(f"完成：{ok}/{len(files)} 成功。输出目录：{output_root}")


if __name__ == "__main__":
    main()
