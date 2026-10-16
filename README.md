# web-guvenlik-lab

[![tests](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Bilerek zafiyetli küçük bir web uygulaması ve her açığın **düzeltilmiş** hali. Amaç, yaygın web açıklarını hem istismar edebildiğimi hem de kapatabildiğimi göstermek.

Her açık için üç şey var: **nerede**, **nasıl istismar edilir**, **nasıl düzeltilir**.

> ⚠️ **Güvenlik uyarısı**
> Bu uygulama kasıtlı olarak güvensizdir ve **yalnızca localhost'ta (`127.0.0.1`)** çalışır. Asla internete açmayın, bir sunucuya kurmayın. Zafiyetli bir uygulamayı canlıya almak gerçek bir risktir.
> Tüm kullanıcılar ve veriler sahtedir.

## İçindekiler

- [Kurulum](#kurulum)
- [Açık 1: SQL Injection](#açık-1-sql-injection)
- [Açık 2: Reflected XSS](#açık-2-reflected-xss)
- [Açık 3: IDOR](#açık-3-idor-insecure-direct-object-reference)
- [Özet](#özet)
- [Testler](#testler)

## Kurulum

```bash
pip install -r requirements.txt

# Zafiyetli sürüm:
python app/vulnerable.py    # http://127.0.0.1:5000

# Güvenli (düzeltilmiş) sürüm:
python app/secure.py        # http://127.0.0.1:5001
```

İki sürüm aynı sayfalara sahiptir; tek fark güvenlik düzeltmeleridir. Aynı saldırıyı iki sürümde deneyip farkı görebilirsiniz.

---

## Açık 1: SQL Injection

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `/login`

Kullanıcı girdisi doğrudan SQL sorgusuna yapıştırılıyor:

```python
query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
```

**İstismar:** Giriş formunda parola alanına şunu yaz:

```
' OR '1'='1
```

Sorgu şuna dönüşür ve koşul her zaman doğru olur; parolayı bilmeden `admin` olarak giriş yapılır:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'
```

**Düzeltme:** [`secure.py`](app/secure.py) → parametreli sorgu. Girdi sorguya yapıştırılmaz, `?` yer tutucusuyla ayrı gönderilir; veritabanı onu veri olarak görür, komut olarak değil.

```python
con.execute("SELECT * FROM users WHERE username = ? AND password = ?", (u, p))
```

---

## Açık 2: Reflected XSS

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `/search`

Arama terimi sayfaya hiç temizlenmeden basılıyor:

```python
return page(f"<h3>'{q}' için sonuçlar</h3>...")
```

**İstismar:** Arama kutusuna (ya da URL'ye) şunu yaz:

```
<script>alert(1)</script>
```

Tarayıcı bunu metin değil, kod olarak çalıştırır. Gerçek bir saldırıda bu kodla kurbanın oturum çerezi çalınabilir.

**Düzeltme:** [`secure.py`](app/secure.py) → çıktı kaçışlama. Girdi sayfaya basılmadan önce HTML olarak kaçışlanır; `<script>` zararsız `&lt;script&gt;` metnine dönüşür.

```python
from markupsafe import escape
return page(f"<h3>{escape(q)} için sonuçlar</h3>...")
```

---

## Açık 3: IDOR (Insecure Direct Object Reference)

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `/profile`

Profil, URL'deki `id` ile getiriliyor ama **kimin kimi görebileceği hiç kontrol edilmiyor:**

```python
row = con.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()
```

**İstismar:** URL'de id'yi değiştir:

```
/profile?id=1   ->  admin'in özel notu
/profile?id=2   ->  başka kullanıcının özel notu
```

Giriş yapmadan, sadece numarayı artırarak herkesin özel bilgisi okunur.

**Düzeltme:** [`secure.py`](app/secure.py) → yetki kontrolü. Kullanıcı giriş yapmış olmalı ve yalnızca **kendi** profilini görebilir (admin istisna). Başkasının id'si istenirse `403 Forbidden` döner. Ayrıca id sayı mı diye kontrol edilir ve sorgu parametrelidir.

```python
if row["username"] != session["user"] and session.get("role") != "admin":
    abort(403)
```

---

## Özet

| Açık | OWASP | İstismar | Düzeltme |
|---|---|---|---|
| SQL Injection | A03:2021 | `' OR '1'='1` ile giriş bypass | Parametreli sorgu |
| Reflected XSS | A03:2021 | `<script>` enjeksiyonu | Çıktı kaçışlama |
| IDOR | A01:2021 | id değiştirip başkasının verisi | Yetki kontrolü |

Her düzeltme, girdiye güvenmek yerine **girdiyi veri olarak ele almak** ve **her istekte yetki doğrulamak** ilkesine dayanır.

## Testler

```bash
python -m unittest -v
```

11 test, her açık için iki şeyi otomatik olarak kanıtlar:

- **Zafiyetli sürümde açık gerçekten var:** SQLi ile giriş atlanıyor, XSS kodu ham basılıyor, IDOR ile başkasının notu okunuyor.
- **Güvenli sürümde aynı saldırı engelleniyor, normal kullanım bozulmuyor:** doğru parolayla giriş çalışıyor, kullanıcı kendi profilini görebiliyor, admin herkesi görebiliyor; başkasının profili `403`, sayı olmayan id `400` döndürüyor.

[GitHub Actions](.github/workflows/tests.yml) testleri her push'ta Python 3.10, 3.12 ve 3.13'te çalıştırır.

## Proje yapısı

```text
app/vulnerable.py    Zafiyetli sürüm (port 5000)
app/secure.py        Düzeltilmiş sürüm (port 5001)
app/db.py            Sahte verili SQLite veritabanı
tests/               Açık ve düzeltme testleri
```

## Sorumluluk reddi

Bu teknikler yalnızca bu lab'da ya da izin verilen ortamlarda kullanılmalıdır. İzinsiz sistemlere yönelik kullanımı yasa dışıdır.

## Lisans

[MIT](LICENSE)
