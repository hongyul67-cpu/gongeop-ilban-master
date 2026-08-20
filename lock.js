/* =========================================================
   공업 일반 마스터 — 잠금 해제 (index.html · class.html 공용)

   정적 호스팅에서는 "화면에 비밀번호 칸"만 두면 보호가 되지 않는다.
   주소를 직접 치면 데이터 파일이 그대로 받아지기 때문이다.
   그래서 학습 데이터(bundle.enc)와 교과서 도판(enc/*.enc)을 실제로 AES-GCM 으로
   암호화해서 올리고, 여기서 WebCrypto 로 푼다. 암호가 틀리면 복호화가 실패한다.

   한 번 연 기기는 암호를 저장해 두고 다음부터 바로 들어간다.
   ========================================================= */
window.GIMLock = (function () {
  /* 저장 키를 도구마다 나누지 않고 하나로 쓴다.
     도구가 모두 hongyul67-cpu.github.io 한 곳에 있어 localStorage 가 공유되므로,
     어느 도구에서든 한 번 열면 나머지도 그 기기에서는 그냥 열린다. */
  var LS_PW = 'hong_pw_v1';
  var key = null;          // 데이터·도판이 같은 키를 쓴다
  var imgCache = {};       // 이름 → blob URL (한 번 푼 도판은 다시 풀지 않는다)
  var onOpen = null;

  function b64(s) { var b = atob(s), u = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  function $(id) { return document.getElementById(id); }

  /* nonce(12바이트) + 암호문 형태로 봉해 둔 것을 푼다 */
  function unseal(buf) {
    var u = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
  }

  function derive(pw, salt, iter) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iter, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      });
  }

  function open(pw, quiet) {
    say(quiet ? '' : '여는 중…', 'dim');
    return fetch('bundle.enc', { cache: 'no-cache' }).then(function (r) { return r.json(); })
      .then(function (blob) {
        return derive(pw, b64(blob.salt), blob.iter).then(function (k) {
          key = k;
          return unseal(b64(blob.data).buffer);
        }).then(function (gz) {
          /* gzip 해제 — 브라우저 내장 */
          var ds = new DecompressionStream('gzip');
          return new Response(new Blob([gz]).stream().pipeThrough(ds)).text();
        }).then(function (txt) {
          var o = JSON.parse(txt);
          window.UNITS = o.UNITS;
          window.DRAWN_FIGS = o.DRAWN_FIGS;
          window.LESSON_UNITS = o.LESSON_UNITS;
          window.FIGS = o.FIGS;
          try { localStorage.setItem(LS_PW, pw); } catch (e) {}
          var ov = $('gimLock'); if (ov) ov.remove();
          document.body.classList.remove('locked');
          if (onOpen) onOpen();
          return true;
        });
      })
      .catch(function () {
        key = null;
        try { localStorage.removeItem(LS_PW); } catch (e) {}
        if (!quiet) { say('암호가 맞지 않습니다.', 'bad'); shake(); }
        else { say('', 'dim'); }
        var pwEl = $('gimPw'); if (pwEl) { pwEl.value = ''; pwEl.focus(); }
        return false;
      });
  }

  /* 교과서 도판 — 필요할 때 한 장씩 받아서 푼다 */
  function img(el) {
    var name = el.getAttribute('data-enc');
    if (!name || !key) return;
    if (imgCache[name]) { el.src = imgCache[name]; return; }
    fetch('enc/' + encodeURIComponent(name) + '.enc', { cache: 'force-cache' })
      .then(function (r) { return r.arrayBuffer(); })
      .then(unseal)
      .then(function (plain) {
        var url = URL.createObjectURL(new Blob([plain]));
        imgCache[name] = url; el.src = url;
      })
      .catch(function () { el.alt = '(도판을 열지 못했습니다)'; });
  }

  /* 방금 그린 화면 안의 도판을 모두 채운다 */
  function fill(root) {
    var els = (root || document).querySelectorAll('img[data-enc]:not([src])');
    for (var i = 0; i < els.length; i++) img(els[i]);
  }

  function say(t, c) {
    var m = $('gimMsg'); if (!m) return;
    m.textContent = t;
    m.style.color = c === 'bad' ? '#ff8a8a' : (c === 'ok' ? '#7ee7a0' : '#9b8fc4');
  }
  function shake() {
    var b = $('gimBox'); if (!b) return;
    b.style.animation = 'none'; void b.offsetWidth; b.style.animation = 'gimShake .3s';
  }

  var CSS = '' +
    '#gimLock{position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;' +
    'background:radial-gradient(1200px 700px at 50% 0%,#241a44 0%,#120c22 60%,#0b0716 100%);padding:20px}' +
    '#gimBox{width:min(440px,92vw);background:#1a1030;border:1px solid #3b2a63;border-radius:20px;' +
    'padding:34px 30px;box-shadow:0 24px 70px rgba(0,0,0,.55);text-align:center}' +
    '#gimBox .ico{font-size:44px;line-height:1}' +
    '#gimBox h1{margin:12px 0 4px;font-size:23px;color:#efe9ff;font-weight:800;letter-spacing:-.3px}' +
    '#gimBox p{margin:0 0 20px;font-size:14px;color:#9b8fc4;line-height:1.6}' +
    '#gimPw{width:100%;box-sizing:border-box;padding:14px 16px;font-size:17px;text-align:center;' +
    'letter-spacing:2px;border-radius:12px;border:1px solid #4a3878;background:#120c22;color:#efe9ff;outline:none}' +
    '#gimPw:focus{border-color:#8a6dff;box-shadow:0 0 0 3px rgba(138,109,255,.22)}' +
    '#gimGo{width:100%;margin-top:12px;padding:14px;font-size:16px;font-weight:800;border:0;border-radius:12px;' +
    'background:linear-gradient(135deg,#8a6dff,#5b3fd6);color:#fff;cursor:pointer}' +
    '#gimGo:active{transform:translateY(1px)}' +
    '#gimMsg{margin-top:14px;font-size:13.5px;min-height:19px;color:#9b8fc4}' +
    '#gimBox .note{margin-top:18px;padding-top:16px;border-top:1px solid #2e2150;font-size:12px;color:#7a6ea0;line-height:1.6}' +
    '@keyframes gimShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}' +
    'body.locked{overflow:hidden}';

  var HTML = '' +
    '<div id="gimLock"><div id="gimBox">' +
    '<div class="ico">🔒</div>' +
    '<h1>공업 일반 마스터</h1>' +
    '<p>수업용 자료입니다.<br>선생님께 받은 암호를 넣어 주세요.</p>' +
    '<input id="gimPw" type="password" inputmode="text" autocomplete="current-password" placeholder="암호" aria-label="암호">' +
    '<button id="gimGo">열기</button>' +
    '<div id="gimMsg"></div>' +
    '<div class="note">한 번 열면 이 기기에서는 다음부터 바로 들어갑니다.</div>' +
    '</div></div>';

  /* cb = 암호가 풀린 뒤 실행할 앱 시작 함수 */
  function mount(cb) {
    onOpen = cb;
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    document.body.insertAdjacentHTML('beforeend', HTML);
    document.body.classList.add('locked');
    $('gimGo').onclick = function () { open($('gimPw').value.trim()); };
    $('gimPw').addEventListener('keydown', function (e) { if (e.key === 'Enter') $('gimGo').click(); });
    var saved = null;
    try { saved = localStorage.getItem(LS_PW); } catch (e) {}
    if (saved) open(saved, true).then(function (ok) { if (!ok) $('gimPw').focus(); });
    else $('gimPw').focus();
  }

  function forget() { try { localStorage.removeItem(LS_PW); } catch (e) {} location.reload(); }

  return { mount: mount, open: open, img: img, fill: fill, forget: forget };
})();
