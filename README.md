# web-guvenlik-lab

[![tests](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Bilerek zafiyetli küçük bir web uygulaması (7 açık) ve her açığın **düzeltilmiş** hali. Amaç, yaygın web açıklarını hem istismar edebildiğimi hem de kapatabildiğimi göstermek.

Her açık için üç şey var: **nerede**, **nasıl istismar edilir**, **nasıl düzeltilir**.

> ⚠️ **Güvenlik uyarısı**
> Bu uygulama kasıtlı olarak güvensizdir ve **yalnızca localhost'ta (`127.0.0.1`)** çalışır. Asla internete açmayın, bir sunucuya kurmayın. Zafiyetli bir uygulamayı canlıya almak gerçek bir risktir.
> Tüm kullanıcılar ve veriler sahtedir.

## İçindekiler

- [Kurulum](#kurulum)
- [Açık 1: SQL Injection](#açık-1-sql-injection)
- [Açık 2: Reflected XSS](#açık-2-reflected-xss)
- [Açık 3: IDOR](#açık-3-idor-insecure-direct-object-reference)
- [Açık 4: CSRF](#açık-4-csrf-cross-site-request-forgery)
- [Açık 5: Düz metin parola](#açık-5-düz-metin-parola)
- [Açık 6: Koda yazılmış gizli anahtar](#açık-6-koda-yazılmış-gizli-anahtar)
- [Açık 7: Giriş deneme sınırı yok](#açık-7-giriş-deneme-sınırı-yok)
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

## Açık 4: CSRF (Cross-Site Request Forgery)

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `/note`

"Özel notumu değiştir" formu, isteğin gerçekten bu siteden gelip gelmediğini kontrol etmiyor. Giriş yapmış bir kullanıcı başka bir siteyi ziyaret ettiğinde, o site kullanıcının tarayıcısına bu formu gizlice gönderttirebilir; tarayıcı oturum çerezini otomatik eklediği için istek kabul edilir.

**Düzeltme:** [`secure.py`](app/secure.py) → CSRF token. Her oturum için rastgele bir token üretilir ve her forma gizli alan olarak eklenir. POST isteği bu token'ı getirmezse `400` ile reddedilir. Başka bir site token'ı bilemeyeceği için sahte form gönderemez.

```python
sent = request.form.get("csrf_token", "")
expected = session.get("csrf_token", "")
if not sent or not expected or not secrets.compare_digest(sent, expected):
    abort(400)
```

Not: Testler, ilk yazdığım hâlinde bir hata yakaladı. Token eksik olduğunda "boş == boş" eşleşmesi isteği geçiriyordu. Bu yüzden token'ın boş olmaması da kontrol ediliyor.

---

## Açık 5: Düz metin parola

**Nerede:** [`db.py`](app/db.py) → `init_db()`

Zafiyetli sürümde parolalar veritabanında olduğu gibi saklanıyor. Veritabanı bir şekilde sızarsa tüm parolalar doğrudan okunur ve kullanıcılar aynı parolayı başka yerlerde de kullanıyorsa onlar da tehlikeye girer.

**Düzeltme:** Güvenli sürümde parolalar **tuzlu hash** olarak saklanır (`werkzeug.security`). Girişte parola hash ile karşılaştırılır; veritabanında parolanın kendisi hiç bulunmaz.

```python
generate_password_hash(pw)              # kayıt
check_password_hash(row["password"], p) # giriş
```

---

## Açık 6: Koda yazılmış gizli anahtar

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `app.secret_key`

Oturum çerezlerini imzalayan anahtar kodun içine yazılmış. Kodu gören herkes (ör. GitHub'da) bu anahtarla geçerli oturum çerezi üretip başka bir kullanıcı gibi görünebilir.

**Düzeltme:** Anahtar `SECRET_KEY` ortam değişkeninden okunur; tanımlı değilse her başlatmada rastgele üretilir.

```python
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
```

---

## Açık 7: Giriş deneme sınırı yok

**Nerede:** [`vulnerable.py`](app/vulnerable.py) → `/login`

Giriş formu sınırsız sayıda denenebilir; bu da parola tahmin (brute force) saldırılarını kolaylaştırır.

**Düzeltme:** Aynı IP'den 10 dakika içinde 5 başarısız denemeden sonra giriş `429 Too Many Requests` ile geçici olarak kilitlenir. Ayrıca başarılı girişten sonra oturum yenilenir (oturum sabitleme saldırısına karşı).

Not: Bu sınır bellekte tutulur ve tek sunucu içindir; gerçek bir uygulamada Redis gibi paylaşılan bir depoya ve kullanıcı bazlı kilitlemeye taşınmalıdır.

---

## Özet

| # | Açık | OWASP 2021 | Düzeltme |
|---|---|---|---|
| 1 | SQL Injection | A03 Injection | Parametreli sorgu |
| 2 | Reflected XSS | A03 Injection | Çıktı kaçışlama |
| 3 | IDOR | A01 Broken Access Control | Yetki kontrolü |
| 4 | CSRF | A01 Broken Access Control | CSRF token |
| 5 | Düz metin parola | A02 Cryptographic Failures | Tuzlu parola hash'i |
| 6 | Koda yazılmış gizli anahtar | A05 Security Misconfiguration | Ortam değişkeni / rastgele anahtar |
| 7 | Giriş deneme sınırı yok | A07 Identification and Authentication Failures | IP başına deneme sınırı |

Her düzeltme, girdiye güvenmek yerine **girdiyi veri olarak ele almak** ve **her istekte yetki doğrulamak** ilkesine dayanır.

## Testler

```bash
python -m unittest -v
```

20 test, her açık için iki şeyi otomatik olarak kanıtlar:

- **Zafiyetli sürümde açık gerçekten var:** 7 açığın her biri için bir test.
- **Güvenli sürümde aynı saldırı engelleniyor, normal kullanım bozulmuyor:** doğru parolayla giriş ve token'lı form çalışıyor, kullanıcı kendi profilini görebiliyor, admin herkesi görebiliyor; başkasının profili `403`, sayı olmayan id ve token'sız form `400`, çok fazla hatalı giriş `429` döndürüyor.

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
