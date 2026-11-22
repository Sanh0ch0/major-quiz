#!/usr/bin/env python3
"""새로 만든 문제(src/new/*.json)를 암호화해서 data/ 에 만든다.

사용법:  python3 tools/build.py --password "비밀번호"

입력 (src/new/, 저장소에 올리지 않음)
  fm_*.json  재무관리 OX : [[장, 정답(1=O,0=X), 지문, 해설], ...]
  ac_*.json  회계학      : mg와 같은 형식
  mg_*.json  경영학      : [["mc", 장, 문제, [보기4개], 정답인덱스(0~3), 해설] | ["ox", 장, 지문, 정답(1/0), 해설], ...]
출력 (data/)
  k.json  키 유도용 salt·반복 횟수 (비밀 아님)
  m.bin   과목·장 이름과 전체 문제 (AES-256-GCM 암호화, 파일 = iv 12바이트 + 암호문)
"""
import argparse, base64, glob, json, os, shutil, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ROOT = Path(__file__).resolve().parent.parent
NEW, OUT = ROOT / "src" / "new", ROOT / "data"
ITER = 600000
CH = {
 "mg": ["경영일반", "조직행동: 개인", "조직행동: 집단·조직", "조직이론", "인적자원관리", "전략경영", "국제경영", "마케팅 개요", "마케팅 조사", "마케팅 전략", "제품·서비스·브랜드", "가격", "유통", "촉진", "소비자 행동", "경영과학", "생산시스템과 프로세스 관리", "품질경영", "생산능력 관리", "공급사슬관리", "재고관리", "운영계획과 자원계획", "린 시스템 설계", "경영정보시스템"],
 "ac": ["개념체계와 재무제표 표시", "수익의 인식", "재고자산", "유형자산", "유형자산의 형태별 취득", "무형자산", "금융부채", "충당부채와 보고기간후사건", "종업원급여", "자본", "금융자산", "현금과 수취채권", "회계변경과 현금흐름표"],
 "fm": ["재무관리의 이해", "경제성 평가", "투자안의 평가", "포트폴리오이론", "자본자산가격결정모형", "CAPM의 발전과 응용", "주식 평가", "채권 평가와 수익률", "듀레이션과 채권투자전략", "레버리지와 자본구조이론", "자본구조이론 발전과 응용", "자본거래", "인수합병", "파생상품과 옵션가격결정", "옵션의 활용", "선물과 국제재무관리", "기타주제"],
}


def check(q, s):
    if s == "fm":
        ch, a, t, ex = q
        assert a in (0, 1) and t and ex
        return ["ox", ch, t, None, a, ex]
    if q[0] == "mc":
        _, ch, t, o, a, ex = q
        assert len(o) == 4 and 0 <= a < 4 and len(set(o)) == 4 and t and ex, q
        return ["mc", ch, t, o, a, ex]
    _, ch, t, a, ex = q
    assert a in (0, 1) and t and ex, q
    return ["ox", ch, t, None, a, ex]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--password", required=True)
    pw = ap.parse_args().password
    if len(pw) < 4:
        sys.exit("비밀번호는 4자 이상으로 해 주세요.")
    Q, seq = [], {}
    for s in ("mg", "ac", "fm"):
        for f in sorted(glob.glob(str(NEW / f"{s}_*.json"))):
            for raw in json.loads(Path(f).read_text("utf-8")):
                tp, ch, t, o, a, ex = check(raw, s)
                assert 1 <= ch <= len(CH[s]), (f, raw)
                seq[(s, ch)] = seq.get((s, ch), 0) + 1
                Q.append([f"{s}{ch:02d}{seq[(s, ch)]:03d}", s, ch, tp, t, o, a, ex])
    meta = {"v": 2, "S": {"mg": {"name": "경영학", "CH": CH["mg"]}, "ac": {"name": "회계학", "CH": CH["ac"]}, "fm": {"name": "재무관리", "CH": CH["fm"]}}, "Q": Q}
    salt = os.urandom(16)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
    iv = os.urandom(12)
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir()
    (OUT / "m.bin").write_bytes(iv + AESGCM(key).encrypt(iv, json.dumps(meta, ensure_ascii=False).encode(), None))
    (OUT / "k.json").write_text(json.dumps({"salt": base64.b64encode(salt).decode(), "it": ITER, "v": 2}))
    for s in ("mg", "ac", "fm"):
        n = [q for q in Q if q[1] == s]
        print(f"{s}: {len(n)}문제 (4지선다 {sum(q[3]=='mc' for q in n)}, OX {sum(q[3]=='ox' for q in n)})")


if __name__ == "__main__":
    main()
