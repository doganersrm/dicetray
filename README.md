# 🎲 DiceTray – Sistem Tepsisi Parola Üretici & Şifre Kasası

> Hafif, güvenli ve hızlı bir masaüstü parola yöneticisi. PySide6 ile geliştirilmiş; sistem tepsisinde çalışır, bir tıkla güçlü parola üretir ve güvenle saklar.

![Screenshot](docs/screenshot.png) <!-- Opsiyonel: ekran görüntüsü ekleyebilirsin -->

---

## 🚀 Özellikler

- ⚡ **Hızlı Parola Üretimi**  
  - Politika-gerçekleme: Büyük/Küçük/Rakam/Özel → her sınıftan en az bir karakter garanti  
  - Uzunluk ve karakter sınıfları ayarlanabilir  
  - Kopyala + pano otomatik temizleme süresi

- 🔐 **Güvenli Şifre Kasası**  
  - Anahtar türetme: *Scrypt KDF*  
  - Blok şifreleme: *AES-256 GCM* (authenticated encryption)  
  - Master parola koruması  
  - Şifreli dışa aktar / içe aktar (AES-GCM yedek dosyası)

- 🧠 **Parola Güç Göstergesi**  
  - Entropi tabanlı seviye  
  - Tahmini kırılma süresi (human-readable)  
  - Öneriler (uzunluk, çeşitlilik, tekrar, yaygın kelimeler vb.)

- 🔎 **Hızlı Arama & Yönetim**  
  - Ctrl+Shift+F ile popup arama → Enter ile kopyala  
  - Etiket ve favori desteği  
  - Silinen kayıtlar **çöp kutusuna** gider → geri getir veya kalıcı sil  
  - Kayıtlar SQLite veritabanında şifrelenmiş halde tutulur

- 🧭 **Kullanışlılık + Otomasyon**  
  - **Global sıcak tuş:** (opsiyonel) Ctrl+Alt+G → üret + kopyala  
  - **Otomatik kilit süresi:** İnaktivite sonrası kasa kendini kapatır  
  - Sistem tepsisi simgesinden hızlı erişim  
  - Panodaki parolayı X saniye sonra otomatik temizler

---

## 🛠️ Kurulum

```bash
# 1️⃣ Kütüphaneleri yükle
pip install PySide6 cryptography

# (isteğe bağlı) global kısayol desteği
pip install keyboard

# 2️⃣ Çalıştır
python dicetray.py



MIT License

Copyright (c) 2024 Doğaner Serim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      
copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all      
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE      
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE   
SOFTWARE.
