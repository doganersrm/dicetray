**🎲 DiceTray – Sistem Tepsisi Parola Üretici & Şifre Kasası **

> Hafif, güvenli ve hızlı bir masaüstü parola yöneticisi. PySide6 ile geliştirilmiş; sistem tepsisinde çalışır, bir tıkla güçlü parola üretir ve güvenle saklar.



<img width="535" height="333" alt="1" src="https://github.com/user-attachments/assets/245af5aa-eb2b-4341-ac40-ae0fcd0090a8" />

---

## Özellikler


<img width="252" height="157" alt="4" src="https://github.com/user-attachments/assets/d18c3e3d-9378-4856-8544-cea177950cd5" />

**Hızlı Parola Üretimi**  
  - Politika-gerçekleme: Büyük/Küçük/Rakam/Özel → her sınıftan en az bir karakter garanti  
  - Uzunluk ve karakter sınıfları ayarlanabilir  
  - Kopyala + pano otomatik temizleme süresi


<img width="611" height="496" alt="2" src="https://github.com/user-attachments/assets/38c8899c-96b2-4ed4-9d0c-2652c3780661" />

**Güvenli Şifre Kasası**  
  - Anahtar türetme: *Scrypt KDF*  
  - Blok şifreleme: *AES-256 GCM* (authenticated encryption)  
  - Master parola koruması  
  - Şifreli dışa aktar / içe aktar (AES-GCM yedek dosyası)


<img width="535" height="333" alt="1" src="https://github.com/user-attachments/assets/f3900f97-00f2-4901-9060-f7ea4b383778" />

**Parola Güç Göstergesi**  
  - Entropi tabanlı seviye  
  - Tahmini kırılma süresi (human-readable)  
  - Öneriler (uzunluk, çeşitlilik, tekrar, yaygın kelimeler vb.)


<img width="658" height="197" alt="7" src="https://github.com/user-attachments/assets/60e1c302-ced6-40cd-80fe-c025df819d3f" />

**Hızlı Arama & Yönetim**  
  - Ctrl+Shift+F ile popup arama → Enter ile kopyala  
  - Etiket ve favori desteği  
  - Silinen kayıtlar **çöp kutusuna** gider → geri getir veya kalıcı sil  
  - Kayıtlar SQLite veritabanında şifrelenmiş halde tutulur

<img width="547" height="490" alt="3" src="https://github.com/user-attachments/assets/914bd8fb-d1be-4dc0-8747-f0e8c1aa3469" />

**Kullanışlılık + Otomasyon**  
  - **Global sıcak tuş:** (opsiyonel) Ctrl+Alt+G → üret + kopyala  
  - **Otomatik kilit süresi:** İnaktivite sonrası kasa kendini kapatır  
  - Sistem tepsisi simgesinden hızlı erişim  
  - Panodaki parolayı X saniye sonra otomatik temizler


## Kurulum


Kütüphaneleri yükle
pip install PySide6 cryptography

(isteğe bağlı) global kısayol desteği
pip install keyboard

Çalıştır
python dicetray.py



Copyright (c) 2025 Doğaner Serim
