#!/usr/bin/env python3
"""Шифрует HTML-страницу паролем для папки cabinet/ (GitHub Pages публичный,
поэтому в репозиторий попадает только зашифрованная версия).

  python3 tools/private_page.py encrypt  исходник.html  cabinet/<папка>/index.html  "Название"
  python3 tools/private_page.py decrypt  cabinet/<папка>/index.html  расшифровка.html

Пароль берётся из переменной окружения CABINET_PASSWORD (в git его нет).
По умолчанию все страницы используют одну соль (cabinet/salt.txt) и,
соответственно, один пароль на весь кабинет — галочка «Запомнить на этом
устройстве» открывает их разом. Если рядом с назначением (в папке
cabinet/<папка>/) лежит свой salt.txt — используется он, и тогда эта
страница требует СВОЙ отдельный пароль, отличный от общего кабинета
(создать такую соль: python3 -c "import os;print(os.urandom(16).hex())"
> cabinet/<папка>/salt.txt).
Схема: gzip → AES-256-GCM, ключ PBKDF2-SHA256 (600 000 итераций)."""
import base64, gzip, hashlib, html, os, re, sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SALT_FILE = ROOT / 'cabinet' / 'salt.txt'
ITER = 600_000


def salt_file_for(page_path):
    own = Path(page_path).resolve().parent / 'salt.txt'
    return own if own.exists() else DEFAULT_SALT_FILE


def key(password, salt_file):
    salt = bytes.fromhex(Path(salt_file).read_text().strip())
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITER, 32)


LOADER = r'''<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>CTR Leads · вход</title>
<style>
:root{--bg:#F3F5F4;--panel:#FFFFFF;--ink:#16211D;--muted:#5D6B66;--line:#D5DDD9;--acc:#2FA37A;--err:#C0392B;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0F1513;--panel:#18211E;--ink:#E6EEEA;--muted:#93A39C;--line:#2A3632;--acc:#3DBE8F;--err:#FF7B6B;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);
 font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:24px 16px}
form{width:100%;max-width:360px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:28px 24px;display:grid;gap:14px}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0}
h1{font-size:20px;margin:0;text-wrap:balance}
input[type=password]{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--ink)}
input[type=password]:focus-visible,button:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
label.rem{display:flex;gap:8px;align-items:center;color:var(--muted);font-size:13px}
button{font:inherit;font-weight:700;border:0;border-radius:999px;padding:10px 16px;background:var(--acc);color:#fff;cursor:pointer}
button[disabled]{opacity:.6;cursor:wait}
#msg{min-height:1.5em;margin:0;font-size:13px;color:var(--err)}
</style></head><body>
<form id="f" autocomplete="off">
  <p class="eyebrow">CTR Leads · закрытый раздел</p>
  <h1>__TITLE__</h1>
  <input type="password" id="pw" placeholder="Пароль" autofocus required>
  <label class="rem"><input type="checkbox" id="rem" checked> Запомнить на этом устройстве</label>
  <button id="go" type="submit">Открыть</button>
  <p id="msg" role="alert"></p>
</form>
<script id="payload" type="application/octet-stream">__PAYLOAD__</script>
<script>
(function(){
var SALT='__SALT__', ITER=__ITER__, LS='ctrleads-cabinet-key-v1';
var b64=function(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;};
var hex=function(h){var u=new Uint8Array(h.length/2);for(var i=0;i<u.length;i++)u[i]=parseInt(h.substr(i*2,2),16);return u;};
var data=b64(document.getElementById('payload').textContent.trim());
var msg=document.getElementById('msg'), go=document.getElementById('go');
function lsGet(){try{return localStorage.getItem(LS);}catch(e){return null;}}
function lsSet(v){try{v?localStorage.setItem(LS,v):localStorage.removeItem(LS);}catch(e){}}
async function open(raw,remember){
  var k=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);
  var plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:data.slice(0,12)},k,data.slice(12));
  var text=await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  if(remember){var s='';var r=new Uint8Array(raw);for(var i=0;i<r.length;i++)s+=String.fromCharCode(r[i]);lsSet(btoa(s));}
  document.open();document.write(text);document.close();
}
var saved=lsGet();
if(saved){open(b64(saved),false).catch(function(){lsSet(null);});}
document.getElementById('f').addEventListener('submit',async function(e){
  e.preventDefault();msg.textContent='';go.disabled=true;go.textContent='Открываю…';
  try{
    var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('pw').value),'PBKDF2',false,['deriveBits']);
    var bits=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:hex(SALT),iterations:ITER},base,256);
    await open(bits,document.getElementById('rem').checked);
  }catch(err){msg.textContent='Неверный пароль. Проверьте раскладку и попробуйте ещё раз.';go.disabled=false;go.textContent='Открыть';}
});
})();
</script>
</body></html>
'''


def encrypt(src, dst, title):
    pw = os.environ['CABINET_PASSWORD']
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    salt_file = salt_file_for(dst)
    data = gzip.compress(Path(src).read_bytes(), 9)
    iv = os.urandom(12)
    blob = iv + AESGCM(key(pw, salt_file)).encrypt(iv, data, None)
    out = (LOADER.replace('__TITLE__', html.escape(title))
           .replace('__SALT__', salt_file.read_text().strip())
           .replace('__ITER__', str(ITER))
           .replace('__PAYLOAD__', base64.b64encode(blob).decode()))
    Path(dst).write_text(out, encoding='utf-8')
    print(f'{dst}: {len(out)/1e6:.1f} МБ (соль: {salt_file.relative_to(ROOT)})')


def decrypt(src, dst):
    pw = os.environ['CABINET_PASSWORD']
    salt_file = salt_file_for(src)
    m = re.search(r'id="payload" type="application/octet-stream">([^<]+)<', Path(src).read_text(encoding='utf-8'))
    blob = base64.b64decode(m.group(1))
    Path(dst).write_bytes(gzip.decompress(AESGCM(key(pw, salt_file)).decrypt(blob[:12], blob[12:], None)))
    print(f'{dst}: расшифровано')


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'encrypt':
        encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == 'decrypt':
        decrypt(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
