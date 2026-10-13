#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""将任意文件压缩并加密为全中文文本。

用法:
    python encryp.py aaa.txt
    python encryp.py aaa.txt 自定义密码

输出:
    aaa_encrypted.txt
"""

#from __future__ import annotations
from typing import Tuple
import hashlib
import hmac
import lzma
import secrets
import sys
import zlib
from pathlib import Path

DEFAULT_PASSWORD = "中文加解密"
MAGIC = b"ZHC2"
NONCE_LEN = 16
MAC_LEN = 32
PBKDF2_ROUNDS = 80_000
HAN_BITS = 10
HAN_MASK = (1 << HAN_BITS) - 1

# 1024 个现代汉语常用字（按字频取前 1024，不含生僻字）
CHARSET = (
    "的一是不了在有人这上大来和我个中地为他生要们以到国时就出说会也子学发着对作能可于成用过动主下而年分得家种里多经自现同后产方工行面"
    "那小所起去之都然理进体还定实如么物法你好性民从天化等力本长心把部义样事看业当因高十开些社前又它水其没想意三只重点与使但度由道全制"
    "明相两情外间二关活正合者形应头无量表象气文展系代加各很教新向机她内此老变原结问手日利质已最政儿见并平资比特果什建反常知第电思立提"
    "或通解身四品几位别论公给少条观回海基次被山才己期西术济认先命走真员及数话门级军统光声题入美口感战科程式指世必放打接总做东区农强造"
    "类受场五直月流决干则更色处路运任具目再治神求件管组根阶将改导眼规识革计白马金界取市设语完究党女传风信名便保育队带叫研领北较张即至"
    "许步往听调务花争线呢每边难太共交确劳据达住收候需转百南清格影书切且却志热联安极今单商料技深验增记近言整精集空连报觉车价音响办存怎"
    "病快图况例消容史非离节亲万八构族石满何广律青林克王历权素始断九际积吃态艺证众创红望须群师该复细包土持服笑德般远爱准写算火死半布随"
    "六元低称引照失养视习段字织斗团器兴乐效显斯千落示仅企似备除支标早吧周速跟七采状吗约城层专划轻拉值适英告讲维营士环古让院按型势足毛"
    "台紧片属严树画厂功注演源温某找参易飞推围列客河虽境食李黄黑念越选华角考致夫初装议首委底另江息密压孩村费局派房星突供曾排苦够像站校"
    "富谈米充阳破母球射批配纪未哪妈差刚率察舞依占呀微础益倒刻举血故互范木号尽请脸兵职留铁吸钱急独剧查皮激坐乎固害夜续京双拿府限草项述"
    "曲既春官坚令句助简杂材封护司省县模试绝洋谁继止喜优词陈鱼终施晚朝含仍脑甚汉修油衣击云送巴普征错均投波余友武责游敌叶船久否异块脚怕"
    "田策苏乡帝靠医测植啊括换逐娘罗戏善获待降冲父置左右沉酸亮良班著亚抗啦静渐概居跑旧防买挥负帮欢冷液停减男胜答析忙短烈映财背奇药承岁"
    "略穿牛室移饭坏假州缺愿练超雨慢竟呼散灵副歌虫读介培卫宗章评伤丰核预担诉惊刘景乱氧阿龙宣升爷洲判案协福货味若促希握端针屋掌检痛闻妇"
    "贵顾沙扩困哥嘴销印免烟跳香纸户板睛误探座盾灯搞祖顺婚赶季兰忽践熟矛银爸临佛犯胞讨陆补童圆归弟域索罪脱追守课顶松杀掉野训遍庭弱赛额"
    "酒绿席露卖钟旁肉央染欧怀稳伯编抓玉咱唯唱翻释控怪阵烧堂杨您诗灭夏敢退姑恶透鲜附骨审胡输宁丝姐彩睡巨迫鼓伙借耳典刺暗镜序哈菜笔汽礼"
    "摇迅险遗威沿弹私攻宝抽雪孙藏毒顿末摆趣救镇楼智园康永遇雄替危楚侵枪冰健播途损秀丽秋执束纳虑疑午粮架盛湖尚床份套毫奋扬赵混献择庄殖"
)
assert len(CHARSET) == 1024 and len(set(CHARSET)) == 1024

COMP_NONE = 0
COMP_ZLIB = 1
COMP_BZ2 = 2
COMP_LZMA = 3
COMP_DEFLATE = 4


def derive_keys(password: str) -> Tuple[bytes, bytes]:
    pw = password.encode("utf-8")
    enc_key = hashlib.pbkdf2_hmac("sha256", pw, b"zhcrypt-enc-v2", PBKDF2_ROUNDS)
    mac_key = hashlib.pbkdf2_hmac("sha256", pw, b"zhcrypt-mac-v2", PBKDF2_ROUNDS)
    return enc_key, mac_key


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def xor_bytes(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def compress_best(data: bytes) -> bytes:
    """在多种标准库压缩算法中选用最短结果；若全部膨胀则不压缩。"""
    candidates: list[tuple[int, bytes]] = [(COMP_NONE, data)]
    try:
        candidates.append((COMP_ZLIB, zlib.compress(data, 9)))
    except Exception:
        pass
    try:
        candidates.append((COMP_DEFLATE, zlib.compress(data, 9, wbits=-15)))
    except Exception:
        pass
    try:
        extreme = 9 | lzma.PRESET_EXTREME
        candidates.append(
            (COMP_LZMA, lzma.compress(data, format=lzma.FORMAT_ALONE, preset=extreme))
        )
    except Exception:
        try:
            candidates.append(
                (COMP_LZMA, lzma.compress(data, format=lzma.FORMAT_ALONE, preset=9))
            )
        except Exception:
            pass
    method, payload = min(candidates, key=lambda item: len(item[1]))
    return bytes([method]) + payload


def bytes_to_han(data: bytes) -> str:
    """每 10 比特映射一个常用汉字（1024 进制）。"""
    if not data:
        return ""
    acc = 0
    nbits = 0
    out: list[str] = []
    for byte in data:
        acc = (acc << 8) | byte
        nbits += 8
        while nbits >= HAN_BITS:
            nbits -= HAN_BITS
            out.append(CHARSET[(acc >> nbits) & HAN_MASK])
            acc &= (1 << nbits) - 1
    if nbits:
        acc <<= HAN_BITS - nbits
        out.append(CHARSET[acc & HAN_MASK])
    return "".join(out)


def wrap_as_qiyan(han: str) -> str:
    """排成七言绝句样式：每 7 字加逗号或句号，每 14 字换行。"""
    if not han:
        return ""
    parts: list[str] = []
    for i in range(0, len(han), 7):
        chunk = han[i : i + 7]
        if (i // 7) % 2 == 0:
            parts.append(chunk + "，")
        else:
            parts.append(chunk + "。\n")
    text = "".join(parts)
    if text.endswith("，"):
        text = text[:-1] + "。"
    if not text.endswith("\n"):
        text += "\n"
    return text


def encrypt_bytes(plain: bytes, password: str) -> str:
    packed = compress_best(plain)
    enc_key, mac_key = derive_keys(password)
    nonce = secrets.token_bytes(NONCE_LEN)
    cipher = xor_bytes(packed, keystream(enc_key, nonce, len(packed)))
    rest = nonce + cipher
    header = MAGIC + len(rest).to_bytes(4, "big")
    payload = header + rest
    tag = hmac.new(mac_key, payload, hashlib.sha256).digest()
    return wrap_as_qiyan(bytes_to_han(payload + tag))


def encrypted_path(src: Path) -> Path:
    return src.with_name(f"{src.stem}_encrypted{src.suffix}")


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python encryp.py <文件> [密码]")
        return 1

    src = Path(sys.argv[1])
    password = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PASSWORD

    if not src.is_file():
        print(f"错误: 找不到文件 {src}")
        return 1

    plain = src.read_bytes()
    text = encrypt_bytes(plain, password)
    dst = encrypted_path(src)
    dst.write_text(text, encoding="utf-8")
    print(f"已加密: {src} -> {dst}  （原文 {len(plain)} 字节，密文 {len(text)} 字）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
