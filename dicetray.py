#!/usr/bin/env python3
"""
DiceTray – sistem tepsisi (tray) parola üretici & şifre kasası (Türkçe)

Öne çıkanlar
- Politika-gerçekleme üretici: Seçili sınıfların her birinden en az bir karakter garanti.
- Bas-tut göz (👁️), güç göstergesi (entropi + tahmini kırılma süresi).
- Hızlı Arama paleti (Ctrl+Shift+F), aksiyon logu, global sıcak tuş (opsiyonel).
- İnaktivite kilidi, etiket/favori, AES-GCM şifreli yedek (içe/dışa aktar).

Yeni (bu sürüm)
- **Soft-delete**: Sil → çöpe taşır (`deleted_at`). “Çöpü göster” filtresi.
- **Geri getir**: Çöpteki kaydı eski haline döndür.
- **Kalıcı sil**: Yalnızca çöpteyken. (Geri alınamaz)
- **Kaydet**: Aynı başlık çöpteyse otomatik geri getirir (deleted_at=NULL).
- **Yedek**: `deleted_at` alanı da yedeklenir/geri yüklenir.
- **Derin birleştirme** (config), Ayarlar kalıcı ve anında etkili.
- Ara/Ayar açıkken auto-hide/lock zamanlayıcıları durur (pencere kendi kendine kapanmaz).
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import string

# Global sıcak tuş için opsiyonel bağımlılık
try:
    import keyboard  # type: ignore
except Exception:
    keyboard = None

APP_NAME = "DiceTray"

# -------------------------
# Dosya yolları ve basit yapı
# -------------------------
def app_dir() -> Path:
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        d = Path(base) / APP_NAME
    else:
        d = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d

CONFIG_PATH = app_dir() / "config.json"
DB_PATH = app_dir() / "vault.sqlite"
LOG_PATH = app_dir() / "activity.log"

# -------------------------
# Yardımcılar
# -------------------------
def log_event(event: str, detail: str = ""):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ts}\t{event}\t{detail}\n")
    except Exception:
        pass

# -------------------------
# Kripto yardımcıları
# -------------------------
@dataclass
class KeyMaterial:
    key: bytes
    salt: bytes

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_blob(key: bytes, plaintext: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct

def decrypt_blob(key: bytes, blob: bytes) -> bytes:
    aes = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aes.decrypt(nonce, ct, associated_data=None)

# -------------------------
# Varsayılan konfig + derin birleştirme
# -------------------------
DEFAULT_CFG = {
    "initialized": False,
    "salt": None,  # ilk oluştururken doldurulacak
    "keycheck": None,
    "ui": {
        "auto_hide_seconds": 30,
        "default_length": 20,
        "clipboard_clear_seconds": 30,
        "lock_seconds": 300
    },
    "policy": {
        "upper": True,
        "lower": True,
        "digits": True,
        "special": True
    }
}

def deep_merge(base: dict, override: dict) -> dict:
    """override içindeki değerlerle base'i derinlemesine günceller (override kazanır)."""
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out

# -------------------------
# Veritabanı + migrasyon
# -------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT UNIQUE NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at TEXT NOT NULL,
    tags TEXT DEFAULT '',
    favorite INTEGER DEFAULT 0,
    deleted_at TEXT DEFAULT NULL
);
"""
MIGRATIONS = [
    ("ALTER TABLE entries ADD COLUMN tags TEXT DEFAULT ''", "tags"),
    ("ALTER TABLE entries ADD COLUMN favorite INTEGER DEFAULT 0", "favorite"),
    ("ALTER TABLE entries ADD COLUMN deleted_at TEXT DEFAULT NULL", "deleted_at"),
]

def init_db():
    con = sqlite3.connect(DB_PATH)
    with con:
        con.execute(SCHEMA)
        cur = con.execute("PRAGMA table_info(entries)")
        cols = {r[1] for r in cur.fetchall()}
        for sql, col in MIGRATIONS:
            if col not in cols:
                try:
                    con.execute(sql)
                except Exception:
                    pass
        # Güvenlik/sağlamlık için temel pragmalar
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA synchronous=FULL;")
        con.execute("PRAGMA foreign_keys=ON;")
        con.execute("PRAGMA secure_delete=ON;")
    return con

# -------------------------
# Ayarlar yükle / kaydet
# -------------------------
def load_or_init_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        merged = deep_merge(DEFAULT_CFG, loaded)
        if merged.get("salt") is None:
            merged["salt"] = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        save_config(merged)  # normalize et
        return merged

    cfg = deep_merge(
        DEFAULT_CFG,
        {"salt": base64.b64encode(secrets.token_bytes(16)).decode("ascii")}
    )
    save_config(cfg)
    return cfg

def save_config(cfg: dict):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

# -------------------------
# Parola gücü tahmini
# -------------------------
STRENGTH_LABELS = ["Çok Zayıf", "Zayıf", "Orta", "Güçlü", "Çok Güçlü"]

def password_strength(pw: str, policy: dict | None = None) -> tuple[int, str, str]:
    """
    Döndürür: (seviye_index 0..4, insan okunur tahmini kırılma süresi, öneri metni)
    """
    import math
    if not pw:
        return 0, "", "Parola boş."

    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    special_chars = "!@#$%^&*()-_=+[]{};:,<.>?"
    has_special = any(c in special_chars for c in pw)

    pool = 0
    if has_upper: pool += 26
    if has_lower: pool += 26
    if has_digit: pool += 10
    if has_special: pool += len(special_chars)
    if pool == 0:
        pool = len(set(pw))

    entropy = len(pw) * (math.log2(pool) if pool > 0 else 0)

    unique = len(set(pw))
    frac = unique / len(pw)
    if frac < 0.25:
        entropy *= 0.6
    elif frac < 0.5:
        entropy *= 0.8

    common = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou"}
    lower = pw.lower()
    contains_common = any(word in lower for word in common)

    if entropy < 28 or contains_common:
        idx = 0
    elif entropy < 36:
        idx = 1
    elif entropy < 60:
        idx = 2
    elif entropy < 128:
        idx = 3
    else:
        idx = 4

    try:
        guesses = pool ** len(pw)
        seconds = guesses / 1e10
    except OverflowError:
        seconds = float("inf")

    def human_time(sec: float) -> str:
        YEAR = 365*24*3600
        MAX_YEARS = 1_000_000
        if sec == float("inf") or sec/YEAR > MAX_YEARS:
            return f">{MAX_YEARS:,} yıl"
        units = [(YEAR, "yıl"), (24*3600, "gün"), (3600, "saat"), (60, "dk"), (1, "sn")]
        out = []
        for u, name in units:
            if sec >= u:
                v = int(sec // u)
                out.append(f"{v} {name}")
                sec %= u
            if len(out) == 2:
                break
        return ", ".join(out) if out else "<1 sn"

    est = human_time(seconds) if pool > 0 else ""

    suggestions = []
    if policy:
        if policy.get("upper") and not has_upper: suggestions.append("En az bir büyük harf ekleyin.")
        if policy.get("lower") and not has_lower: suggestions.append("En az bir küçük harf ekleyin.")
        if policy.get("digits") and not has_digit: suggestions.append("En az bir rakam ekleyin.")
        if policy.get("special") and not has_special: suggestions.append("En az bir özel karakter ekleyin.")
    else:
        if not has_upper: suggestions.append("Büyük harf ekleyin.")
        if not has_lower: suggestions.append("Küçük harf ekleyin.")
        if not has_digit: suggestions.append("Rakam ekleyin.")
        if not has_special: suggestions.append("Özel karakter ekleyin.")
    if len(pw) < 12: suggestions.append("Uzunluğu 12+ karaktere çıkarın.")
    if contains_common: suggestions.append("Çok yaygın bir sözcük kullanılmış; farklı kombinasyon deneyin.")
    if frac < 0.8: suggestions.append("Tekrarlayan karakterlerden kaçının.")

    sugg_text = " ".join(suggestions) if suggestions else "Güçlü görünüyor."
    return idx, est, sugg_text

# -------------------------
# UI: Master parola diyalogu
# -------------------------
class MasterPasswordDialog(QtWidgets.QDialog):
    def __init__(self, first_run: bool, parent=None):
        super().__init__(parent)
        self.setWindowTitle("DiceTray – " + ("Yeni Master Parola Oluştur" if first_run else "Kasa Kilidini Aç"))
        self.setModal(True)
        self.setFixedSize(420, 180)

        layout = QtWidgets.QVBoxLayout(self)

        label = QtWidgets.QLabel("Güçlü bir master parola seçin. Bu parola kasayı açmak için gereklidir.") if first_run else QtWidgets.QLabel("Lütfen master parolanızı girin.")
        label.setWordWrap(True)
        layout.addWidget(label)

        form = QtWidgets.QFormLayout()
        self.edit1 = QtWidgets.QLineEdit()
        self.edit1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.edit1.setPlaceholderText("Master parola")
        form.addRow("Parola:", self.edit1)

        if first_run:
            self.edit2 = QtWidgets.QLineEdit()
            self.edit2.setEchoMode(QtWidgets.QLineEdit.Password)
            self.edit2.setPlaceholderText("Parola (tekrar)")
            form.addRow("Parola (tekrar):", self.edit2)
        else:
            self.edit2 = None

        layout.addLayout(form)

        self.show_pw = QtWidgets.QCheckBox("Parolayı göster")
        self.show_pw.toggled.connect(self._toggle_show)
        layout.addWidget(self.show_pw)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _toggle_show(self, checked: bool):
        mode = QtWidgets.QLineEdit.Normal if checked else QtWidgets.QLineEdit.Password
        self.edit1.setEchoMode(mode)
        if self.edit2:
            self.edit2.setEchoMode(mode)

    def value(self):
        if self.edit2:
            return self.edit1.text(), self.edit2.text()
        return self.edit1.text(), None

# -------------------------
# Master parola değiştir diyalogu
# -------------------------
class ChangeMasterDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Master Parola Değiştir")
        self.setModal(True)
        self.setFixedSize(420, 220)
        layout = QtWidgets.QFormLayout(self)
        self.current = QtWidgets.QLineEdit(); self.current.setEchoMode(QtWidgets.QLineEdit.Password)
        self.new1 = QtWidgets.QLineEdit(); self.new1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.new2 = QtWidgets.QLineEdit(); self.new2.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addRow("Mevcut parola:", self.current)
        layout.addRow("Yeni parola:", self.new1)
        layout.addRow("Yeni parola (tekrar):", self.new2)
        self.show_pw = QtWidgets.QCheckBox("Parolaları göster"); self.show_pw.toggled.connect(self._toggle_show)
        layout.addRow(self.show_pw)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        layout.addRow(btns)

    def _toggle_show(self, checked: bool):
        mode = QtWidgets.QLineEdit.Normal if checked else QtWidgets.QLineEdit.Password
        for w in (self.current, self.new1, self.new2): w.setEchoMode(mode)

    def values(self):
        return self.current.text(), self.new1.text(), self.new2.text()

# -------------------------
# Ayarlar diyaloğu (UI/politika/lock)
# -------------------------
class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ayarlar")
        self.setModal(True)
        self.setFixedSize(480, 400)
        self.cfg = cfg

        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()

        # UI ayarları
        self.auto_hide = QtWidgets.QSpinBox(); self.auto_hide.setRange(0, 3600); self.auto_hide.setValue(cfg.get('ui', {}).get('auto_hide_seconds', 30))
        self.default_len = QtWidgets.QSlider(Qt.Horizontal); self.default_len.setRange(8, 128); self.default_len.setValue(cfg.get('ui', {}).get('default_length', 20))
        self.default_len_label = QtWidgets.QLabel(str(self.default_len.value())); self.default_len.valueChanged.connect(lambda v: self.default_len_label.setText(str(v)))
        self.clip_clear = QtWidgets.QSpinBox(); self.clip_clear.setRange(0, 300); self.clip_clear.setValue(cfg.get('ui', {}).get('clipboard_clear_seconds', 30))
        self.lock_seconds = QtWidgets.QSpinBox(); self.lock_seconds.setRange(0, 36000); self.lock_seconds.setValue(cfg.get('ui', {}).get('lock_seconds', 300))

        # Parola politikası
        pol_group = QtWidgets.QGroupBox("Parola Politikası"); pol_layout = QtWidgets.QHBoxLayout(pol_group)
        self.chk_upper = QtWidgets.QCheckBox("Büyük harf"); self.chk_upper.setChecked(cfg.get('policy', {}).get('upper', True))
        self.chk_lower = QtWidgets.QCheckBox("Küçük harf"); self.chk_lower.setChecked(cfg.get('policy', {}).get('lower', True))
        self.chk_digits = QtWidgets.QCheckBox("Rakam"); self.chk_digits.setChecked(cfg.get('policy', {}).get('digits', True))
        self.chk_special = QtWidgets.QCheckBox("Özel karakter"); self.chk_special.setChecked(cfg.get('policy', {}).get('special', True))
        for w in (self.chk_upper, self.chk_lower, self.chk_digits, self.chk_special): pol_layout.addWidget(w)

        # Yerleşim
        form.addRow('Pencere otomatik gizleme (sn, 0=devre dışı):', self.auto_hide)
        h = QtWidgets.QHBoxLayout(); h.addWidget(QtWidgets.QLabel('Varsayılan uzunluk:')); h.addWidget(self.default_len); h.addWidget(self.default_len_label); form.addRow(h)
        form.addRow('Panoyu temizleme süresi (sn):', self.clip_clear)
        form.addRow('Kilit süresi (sn, 0=kapalı):', self.lock_seconds)

        layout.addLayout(form)
        layout.addWidget(pol_group)

        # Master değiştir + Yedek
        row = QtWidgets.QHBoxLayout()
        self.change_master_btn = QtWidgets.QPushButton("Master Parolayı Değiştir"); row.addWidget(self.change_master_btn)
        self.export_btn = QtWidgets.QPushButton("Şifreli Dışa Aktar"); row.addWidget(self.export_btn)
        self.import_btn = QtWidgets.QPushButton("Şifreli İçe Aktar"); row.addWidget(self.import_btn)
        layout.addLayout(row)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept); btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def apply(self):
        # Eksik sözlükleri garanti et
        self.cfg.setdefault('ui', {})
        self.cfg.setdefault('policy', {})

        self.cfg['ui']['auto_hide_seconds'] = int(self.auto_hide.value())
        self.cfg['ui']['default_length'] = int(self.default_len.value())
        self.cfg['ui']['clipboard_clear_seconds'] = int(self.clip_clear.value())
        self.cfg['ui']['lock_seconds'] = int(self.lock_seconds.value())
        self.cfg['policy']['upper'] = bool(self.chk_upper.isChecked())
        self.cfg['policy']['lower'] = bool(self.chk_lower.isChecked())
        self.cfg['policy']['digits'] = bool(self.chk_digits.isChecked())
        self.cfg['policy']['special'] = bool(self.chk_special.isChecked())
        save_config(self.cfg)

# -------------------------
# Hızlı arama paleti (yalnızca silinmemişler)
# -------------------------
class QuickPalette(QtWidgets.QDialog):
    def __init__(self, con: sqlite3.Connection, key: bytes, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hızlı Arama")
        self.setModal(True)
        self.setFixedSize(480, 360)
        self.con = con; self.key = key; self.cfg = cfg
        v = QtWidgets.QVBoxLayout(self)
        self.q = QtWidgets.QLineEdit(); self.q.setPlaceholderText("Başlık ara… (Enter: kopyala)"); v.addWidget(self.q)
        self.list = QtWidgets.QListWidget(); v.addWidget(self.list)
        self.q.textChanged.connect(self.refresh)
        self.list.itemDoubleClicked.connect(self.accept)
        self.refresh()

    def refresh(self):
        term = f"%{self.q.text()}%"
        cur = self.con.cursor()
        cur.execute("""
            SELECT title, favorite FROM entries 
            WHERE deleted_at IS NULL AND title LIKE ? 
            ORDER BY favorite DESC, title ASC LIMIT 300
        """, (term,))
        self.list.clear()
        for title, fav in cur.fetchall():
            item = QtWidgets.QListWidgetItem(("★ " if fav else "  ") + title)
            item.setData(Qt.UserRole, title)
            self.list.addItem(item)

    def selected_title(self) -> str | None:
        it = self.list.currentItem()
        return (it.data(Qt.UserRole) if it else None)

# -------------------------
# Arama diyalogu (sil/geri getir/kalıcı sil + çöp filtresi)
# -------------------------
class SearchDialog(QtWidgets.QDialog):
    deleted = QtCore.Signal(str)   # başlık silindiğinde/çöpe taşındığında
    restored = QtCore.Signal(str)  # başlık geri getirildiğinde

    def __init__(self, con: sqlite3.Connection, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kayıt Ara / Yükle")
        self.setModal(True)
        self.setFixedSize(520, 420)
        self.con = con
        v = QtWidgets.QVBoxLayout(self)

        top = QtWidgets.QHBoxLayout()
        self.q = QtWidgets.QLineEdit(); self.q.setPlaceholderText("Başlık veya etiket ara…")
        self.chk_trash = QtWidgets.QCheckBox("Çöpü göster")
        top.addWidget(self.q); top.addWidget(self.chk_trash)
        v.addLayout(top)

        self.list = QtWidgets.QListWidget()
        v.addWidget(self.list)

        self.q.textChanged.connect(self.refresh)
        self.chk_trash.toggled.connect(self.refresh)
        self.list.itemDoubleClicked.connect(lambda _: self.accept())

        # Kısayollar
        QtGui.QShortcut(QtGui.QKeySequence("Return"), self, activated=self.accept)
        QtGui.QShortcut(QtGui.QKeySequence("Delete"), self, activated=self._delete_or_trash_current)

        # Sağ tık menüsü
        self.list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._open_ctx_menu)

        self.refresh()

    def refresh(self):
        term = f"%{self.q.text()}%"
        cur = self.con.cursor()
        if self.chk_trash.isChecked():
            cur.execute("""
                SELECT title, favorite, deleted_at FROM entries
                WHERE (title LIKE ? OR tags LIKE ?)
                ORDER BY (deleted_at IS NULL) DESC, favorite DESC, title ASC
                LIMIT 500
            """, (term, term))
        else:
            cur.execute("""
                SELECT title, favorite, deleted_at FROM entries
                WHERE deleted_at IS NULL AND (title LIKE ? OR tags LIKE ?)
                ORDER BY favorite DESC, title ASC
                LIMIT 500
            """, (term, term))

        self.list.clear()
        for title, fav, deleted_at in cur.fetchall():
            label = ("★ " if fav else "  ") + (f"[ÇÖP] {title}" if deleted_at else title)
            it = QtWidgets.QListWidgetItem(label)
            it.setData(Qt.UserRole, title)
            if deleted_at:
                it.setForeground(QtGui.QBrush(Qt.gray))
            self.list.addItem(it)

    def selected_title(self) -> str | None:
        it = self.list.currentItem()
        return (it.data(Qt.UserRole) if it else None)

    # ---- Yardımcılar ----
    def _open_ctx_menu(self, pos: QtCore.QPoint):
        item = self.list.itemAt(pos)
        if not item:
            return
        title = item.data(Qt.UserRole)
        deleted = self._is_deleted(title)

        menu = QtWidgets.QMenu(self)
        if not deleted:
            act_load = menu.addAction("Yükle (Enter)")
            act_copy_info = menu.addAction("Kopyalama bilgisi…")
            menu.addSeparator()
            act_trash = menu.addAction("Sil → Çöpe taşı…")
            chosen = menu.exec(self.list.mapToGlobal(pos))
            if chosen is act_load:
                self.accept()
            elif chosen is act_copy_info:
                QtWidgets.QMessageBox.information(self, "Bilgi", "Parolayı kopyalamak için kayıtı Yükle ve ana pencereden 📋 butonuna bas.")
            elif chosen is act_trash:
                self._trash_title(title)
        else:
            act_restore = menu.addAction("Geri getir")
            act_delete = menu.addAction("Kalıcı sil…")
            chosen = menu.exec(self.list.mapToGlobal(pos))
            if chosen is act_restore:
                self._restore_title(title)
            elif chosen is act_delete:
                self._purge_title(title)

    def _is_deleted(self, title: str) -> bool:
        cur = self.con.cursor()
        cur.execute("SELECT deleted_at FROM entries WHERE title=?", (title,))
        r = cur.fetchone()
        return bool(r and r[0])

    def _delete_or_trash_current(self):
        title = self.selected_title()
        if not title:
            return
        if self._is_deleted(title):
            self._purge_title(title)
        else:
            self._trash_title(title)

    def _trash_title(self, title: str):
        resp = QtWidgets.QMessageBox.question(
            self, "Silinsin mi?",
            f"“{title}” çöpe taşınsın mı?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        if resp != QtWidgets.QMessageBox.Yes:
            return
        try:
            with self.con:
                self.con.execute("UPDATE entries SET deleted_at=? WHERE title=?", (datetime.utcnow().isoformat(), title))
            self.deleted.emit(title)
            self.refresh()
            QtWidgets.QMessageBox.information(self, "Çöpe taşındı", f"“{title}” çöpe taşındı.")
            log_event("trash", title)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Taşınamadı: {e}")

    def _restore_title(self, title: str):
        try:
            with self.con:
                self.con.execute("UPDATE entries SET deleted_at=NULL WHERE title=?", (title,))
            self.restored.emit(title)
            self.refresh()
            QtWidgets.QMessageBox.information(self, "Geri getirildi", f"“{title}” geri getirildi.")
            log_event("restore", title)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Geri getirilemedi: {e}")

    def _purge_title(self, title: str):
        resp = QtWidgets.QMessageBox.warning(
            self, "Kalıcı silinsin mi?",
            f"“{title}” kalıcı olarak silinsin mi? (Geri alınamaz)",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        if resp != QtWidgets.QMessageBox.Yes:
            return
        try:
            with self.con:
                self.con.execute("DELETE FROM entries WHERE title=?", (title,))
            self.deleted.emit(title)  # ana pencere temizlesin
            self.refresh()
            QtWidgets.QMessageBox.information(self, "Silindi", f"“{title}” kalıcı olarak silindi.")
            log_event("delete", title)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Silinemedi: {e}")

# -------------------------
# Ana pencere
# -------------------------
class MainWindow(QtWidgets.QWidget):
    password_loaded = QtCore.Signal(str, str)  # title, password

    def __init__(self, con: sqlite3.Connection, key: bytes, tray: QtWidgets.QSystemTrayIcon, cfg: dict):
        super().__init__()
        self.con = con; self.key = key; self.tray = tray; self.cfg = cfg
        self.setWindowTitle("DiceTray – Parola Üretici & Kasa")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setFixedSize(420, 236)
        self.locked = False

        small_font = QtGui.QFont(); small_font.setPointSize(9)
        grid = QtWidgets.QGridLayout(self)

        self.title_edit = QtWidgets.QLineEdit(); self.title_edit.setPlaceholderText("Başlık…"); self.title_edit.setFont(small_font)
        self.tags_edit = QtWidgets.QLineEdit(); self.tags_edit.setPlaceholderText("etiket1, etiket2"); self.tags_edit.setFont(small_font)
        self.fav_chk = QtWidgets.QCheckBox("Favori ★")
        grid.addWidget(QtWidgets.QLabel("Başlık"), 0, 0)
        grid.addWidget(self.title_edit, 0, 1, 1, 2)
        grid.addWidget(self.fav_chk, 0, 3)
        grid.addWidget(QtWidgets.QLabel("Etiketler"), 1, 0)
        grid.addWidget(self.tags_edit, 1, 1, 1, 3)

        self.pass_edit = QtWidgets.QLineEdit(); self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password); self.pass_edit.setFont(small_font)
        self.btn_toggle_view = QtWidgets.QPushButton("👁️"); self.btn_toggle_view.setFixedSize(40, 28); self.btn_toggle_view.setToolTip("Basılı tut – göster")
        self.btn_toggle_view.pressed.connect(self._show_pw_pressed)
        self.btn_toggle_view.released.connect(self._show_pw_released)
        grid.addWidget(QtWidgets.QLabel("Parola"), 2, 0)
        grid.addWidget(self.pass_edit, 2, 1, 1, 2)
        grid.addWidget(self.btn_toggle_view, 2, 3)

        self.str_bar = QtWidgets.QProgressBar(); self.str_bar.setRange(0, 4); self.str_bar.setTextVisible(False)
        self.str_lbl = QtWidgets.QLabel("")
        self.str_lbl.setWordWrap(False)
        self.str_lbl.setFixedHeight(18)
        self.str_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        grid.addWidget(self.str_bar, 3, 1, 1, 2)
        grid.addWidget(self.str_lbl, 3, 3)
        self.pass_edit.textChanged.connect(self._update_strength)

        self.len_slider = QtWidgets.QSlider(Qt.Horizontal); self.len_slider.setRange(8, 128); self.len_slider.setValue(self.cfg.get('ui', {}).get('default_length', 20))
        self.len_label = QtWidgets.QLabel(str(self.len_slider.value()))
        self.len_slider.valueChanged.connect(lambda v: self.len_label.setText(str(v)))

        self.btn_generate = QtWidgets.QPushButton("🎲"); self.btn_generate.setFixedSize(36, 28)
        self.btn_save = QtWidgets.QPushButton("💾"); self.btn_save.setFixedSize(36, 28)
        self.btn_copy = QtWidgets.QPushButton("📋"); self.btn_copy.setFixedSize(52, 36)
        self.btn_search = QtWidgets.QPushButton("🔎"); self.btn_search.setFixedSize(52, 36)
        self.btn_settings = QtWidgets.QPushButton("⚙️"); self.btn_settings.setFixedSize(36, 28)

        grid.addWidget(QtWidgets.QLabel("Uzunluk"), 4, 0)
        grid.addWidget(self.len_slider, 4, 1)
        grid.addWidget(self.len_label, 4, 2)
        grid.addWidget(self.btn_generate, 4, 3)
        grid.addWidget(self.btn_search, 5, 0)
        grid.addWidget(self.btn_copy, 5, 1)
        grid.addWidget(self.btn_settings, 5, 2)
        grid.addWidget(self.btn_save, 5, 3)

        self.sugg_frame = QtWidgets.QFrame()
        self.sugg_frame.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sugg_frame.setFixedHeight(26)
        self.sugg_frame.setStyleSheet("background:#f7f7f9; border-top:1px solid #e5e5ee;")
        sugg_layout = QtWidgets.QHBoxLayout(self.sugg_frame)
        sugg_layout.setContentsMargins(8, 0, 8, 0)
        sugg_layout.setSpacing(6)
        self.str_sugg_icon = QtWidgets.QLabel("💡"); self.str_sugg_icon.setFixedWidth(18)
        self.str_sugg = QtWidgets.QLabel("")
        self.str_sugg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.str_sugg.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.str_sugg.setStyleSheet("color:#a33; font-size:11px;")
        sugg_layout.addWidget(self.str_sugg_icon); sugg_layout.addWidget(self.str_sugg)
        grid.addWidget(self.sugg_frame, 6, 0, 1, 4)

        self.btn_generate.clicked.connect(self._wrap_action(self.generate))
        self.btn_save.clicked.connect(self._wrap_action(self.save))
        self.btn_copy.clicked.connect(self._wrap_action(self.copy))
        self.btn_search.clicked.connect(self._wrap_action(self.search))
        self.btn_settings.clicked.connect(self._wrap_action(self.open_settings))
        self.title_edit.returnPressed.connect(lambda: self._wrap_action(self.save)())

        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+G"), self, activated=self._wrap_action(self.generate))
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+S"), self, activated=self._wrap_action(self.save))
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+F"), self, activated=self._wrap_action(self.search))
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+Shift+F"), self, activated=self._wrap_action(self.quick_palette))

        self.password_loaded.connect(self.on_password_loaded)

        self.auto_hide_timer = QtCore.QTimer(self); self.auto_hide_timer.setSingleShot(True); self.auto_hide_timer.timeout.connect(self.hide)
        self.lock_timer = QtCore.QTimer(self); self.lock_timer.setSingleShot(True); self.lock_timer.timeout.connect(self._lock_vault)
        self.reset_auto_hide(); self.reset_lock()

        for w in (self, self.title_edit, self.pass_edit, self.tags_edit): w.installEventFilter(self)

    # görünürlük butonu (bas-tut)
    def _show_pw_pressed(self):
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
    def _show_pw_released(self):
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)

    # zamanlayıcı kontrol
    def pause_timers(self):
        self.auto_hide_timer.stop()
        self.lock_timer.stop()

    def resume_timers(self):
        self.reset_auto_hide()
        self.reset_lock()

    # sarmalayıcı
    def _wrap_action(self, func):
        def wrapped(*a, **k):
            try:
                res = func(*a, **k)
                self.reset_auto_hide()
                self.reset_lock()
                return res
            finally:
                pass
        return wrapped

    def eventFilter(self, obj, event):
        if event.type() in (QtCore.QEvent.MouseButtonPress, QtCore.QEvent.KeyPress):
            self.reset_auto_hide(); self.reset_lock()
        return super().eventFilter(obj, event)

    def reset_auto_hide(self):
        sec = int(self.cfg.get('ui', {}).get('auto_hide_seconds', 30))
        if sec > 0: self.auto_hide_timer.start(sec*1000)
        else: self.auto_hide_timer.stop()

    def reset_lock(self):
        sec = int(self.cfg.get('ui', {}).get('lock_seconds', 300))
        if sec > 0: self.lock_timer.start(sec*1000)
        else: self.lock_timer.stop()

    def _lock_vault(self):
        self.locked = True
        self.hide()

    def _update_strength(self):
        pw = self.pass_edit.text()
        policy = self.cfg.get('policy', {})
        idx, est, sugg = password_strength(pw, policy)
        self.str_bar.setValue(idx)
        label = STRENGTH_LABELS[idx]
        self.str_lbl.setText(label)
        display = label + (f" • ~{est}" if est else "") + (f" — {sugg}" if sugg else "")
        metrics = self.str_sugg.fontMetrics()
        avail = max(10, self.sugg_frame.width() - 8 - 8 - self.str_sugg_icon.width() - 6)
        self.str_sugg.setText(metrics.elidedText(display, Qt.ElideRight, avail))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.str_sugg.text():
            self._update_strength()

    # şifre üretici
    def generate(self):
        length = int(self.len_slider.value())
        pol = self.cfg.get('policy', {})
        pools = []
        if pol.get('upper', True): pools.append(string.ascii_uppercase)
        if pol.get('lower', True): pools.append(string.ascii_lowercase)
        if pol.get('digits', True): pools.append(string.digits)
        if pol.get('special', True): pools.append("!@#$%^&*()-_=+[]{};:,<.>?")
        if not pools: pools = [string.ascii_letters + string.digits]
        all_chars = ''.join(pools)
        required = [secrets.choice(p) for p in pools]
        if length < len(required):
            length = len(required)
            self.len_slider.setValue(length)
        rest = [secrets.choice(all_chars) for _ in range(length - len(required))]
        chars = required + rest
        secrets.SystemRandom().shuffle(chars)
        pw = ''.join(chars)
        self.pass_edit.setText(pw)

    # kayıt işlemleri
    def save(self):
        title = self.title_edit.text().strip()
        tags = self.tags_edit.text().strip()
        fav = 1 if self.fav_chk.isChecked() else 0
        pw = self.pass_edit.text()
        if not title:
            QtWidgets.QMessageBox.warning(self, "Uyarı", "Başlık boş olamaz."); return
        if not pw:
            QtWidgets.QMessageBox.warning(self, "Uyarı", "Parola boş olamaz."); return
        blob = encrypt_blob(self.key, pw.encode('utf-8'))
        try:
            with self.con:
                # Kaydederken varsa çöpten çıkar (deleted_at=NULL)
                self.con.execute(
                    "INSERT INTO entries(title, ciphertext, created_at, tags, favorite, deleted_at) "
                    "VALUES(?,?,?,?,?,NULL) "
                    "ON CONFLICT(title) DO UPDATE SET ciphertext=excluded.ciphertext, created_at=excluded.created_at, "
                    "tags=excluded.tags, favorite=excluded.favorite, deleted_at=NULL",
                    (title, blob, datetime.utcnow().isoformat(), tags, fav),
                )
            self.tray.showMessage("DiceTray", f"Kaydedildi: {title}", QtGui.QIcon(), 1500)
            log_event("save", title)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Kayıt başarısız: {e}")

    def copy(self):
        pw = self.pass_edit.text()
        if not pw:
            QtWidgets.QMessageBox.information(self, "Bilgi", "Kopyalanacak parola yok."); return
        QtWidgets.QApplication.clipboard().setText(pw)
        sec = int(self.cfg.get('ui', {}).get('clipboard_clear_seconds', 30))
        self.tray.showMessage("DiceTray", "Parola panoya kopyalandı", QtGui.QIcon(), 1500)
        log_event("copy", self.title_edit.text().strip())
        if sec > 0:
            QtCore.QTimer.singleShot(sec*1000, self.clear_clipboard)

    def clear_clipboard(self):
        cb = QtWidgets.QApplication.clipboard()
        if cb.text(): cb.clear(mode=cb.Clipboard)

    def search(self):
        self.pause_timers()
        try:
            dlg = SearchDialog(self.con, self)
            dlg.deleted.connect(self.on_deleted_title)
            dlg.restored.connect(self.on_restored_title)
            if dlg.exec() == QtWidgets.QDialog.Accepted:
                t = dlg.selected_title()
                if t:
                    cur = self.con.cursor(); cur.execute("SELECT ciphertext, deleted_at FROM entries WHERE title=?", (t,))
                    row = cur.fetchone()
                    if row:
                        ct, deleted_at = row
                        if deleted_at:
                            QtWidgets.QMessageBox.information(self, "Çöpte", "Bu kayıt çöpte. Geri getirip kullanabilirsiniz.")
                            return
                        try:
                            pw = decrypt_blob(self.key, ct).decode('utf-8')
                            self.password_loaded.emit(t, pw)
                            log_event("search_select", t)
                        except Exception as e:
                            QtWidgets.QMessageBox.critical(self, "Hata", f"Çözme hatası: {e}")
        finally:
            self.resume_timers()

    def quick_palette(self):
        self.pause_timers()
        try:
            dlg = QuickPalette(self.con, self.key, self.cfg, self)
            if dlg.exec() == QtWidgets.QDialog.Accepted:
                t = dlg.selected_title()
                if not t: return
                cur = self.con.cursor(); cur.execute("SELECT ciphertext FROM entries WHERE title=? AND deleted_at IS NULL", (t,))
                row = cur.fetchone()
                if row:
                    pw = decrypt_blob(self.key, row[0]).decode('utf-8')
                    QtWidgets.QApplication.clipboard().setText(pw)
                    sec = int(self.cfg.get('ui', {}).get('clipboard_clear_seconds', 30))
                    if sec > 0: QtCore.QTimer.singleShot(sec*1000, self.clear_clipboard)
                    self.tray.showMessage("DiceTray", f"Kopyalandı: {t}", QtGui.QIcon(), 1200)
                    log_event("quick_copy", t)
        finally:
            self.resume_timers()

    def open_settings(self):
        dlg = SettingsDialog(self.cfg, self)
        dlg.change_master_btn.clicked.connect(lambda: self._wrap_action(self.change_master)())
        dlg.export_btn.clicked.connect(self._wrap_action(self.export_encrypted))
        dlg.import_btn.clicked.connect(self._wrap_action(self.import_encrypted))
        self.pause_timers()
        try:
            if dlg.exec() == QtWidgets.QDialog.Accepted:
                dlg.apply()
                self.reset_auto_hide()
                self.reset_lock()
                self.len_slider.setValue(self.cfg.get('ui', {}).get('default_length', 20))
                self._update_strength()
        finally:
            self.resume_timers()

    # diyaloglardan gelen olaylar
    def on_deleted_title(self, title: str):
        if self.title_edit.text().strip() == title:
            self.title_edit.clear()
            self.tags_edit.clear()
            self.fav_chk.setChecked(False)
            self.pass_edit.clear()
            self._update_strength()
            self.tray.showMessage("DiceTray", f"Silindi/Çöpe taşındı: {title}", QtGui.QIcon(), 1200)

    def on_restored_title(self, title: str):
        self.tray.showMessage("DiceTray", f"Geri getirildi: {title}", QtGui.QIcon(), 1200)

    # master değiştirme ve yedekleme
    def export_encrypted(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Şifreli Dışa Aktar", str(app_dir()/ "vault.backup"), "Backup (*.backup)")
        if not path: return
        pw, ok = QtWidgets.QInputDialog.getText(self, "Yedek Parolası", "Yedek için parola belirle:", QtWidgets.QLineEdit.Password)
        if not ok or not pw: return
        salt = secrets.token_bytes(16); key = derive_key(pw, salt)
        cur = self.con.cursor(); cur.execute("SELECT title, ciphertext, created_at, tags, favorite, deleted_at FROM entries")
        rows = cur.fetchall()
        payload = json.dumps([(t, base64.b64encode(ct).decode('ascii'), c, g, f, d) for (t, ct, c, g, f, d) in rows]).encode('utf-8')
        blob = encrypt_blob(key, payload)
        with open(path, 'wb') as f:
            f.write(b"BKUP"); f.write(salt); f.write(blob)
        self.tray.showMessage("DiceTray", "Yedek kaydedildi", QtGui.QIcon(), 1200)
        log_event("export", Path(path).name)

    def import_encrypted(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Şifreli İçe Aktar", str(app_dir()), "Backup (*.backup)")
        if not path: return
        pw, ok = QtWidgets.QInputDialog.getText(self, "Yedek Parolası", "Yedek parolasını gir:", QtWidgets.QLineEdit.Password)
        if not ok or not pw: return
        with open(path, 'rb') as f:
            header = f.read(4)
            if header != b"BKUP":
                QtWidgets.QMessageBox.critical(self, "Hata", "Geçersiz yedek dosyası."); return
            salt = f.read(16); blob = f.read()
        key = derive_key(pw, salt)
        try:
            payload = decrypt_blob(key, blob)
            rows = json.loads(payload.decode('utf-8'))
        except Exception:
            QtWidgets.QMessageBox.critical(self, "Hata", "Yedek parola hatalı veya dosya bozuk."); return
        try:
            with self.con:
                for (t, ct_b64, c, g, f, d) in rows:
                    ct = base64.b64decode(ct_b64)
                    self.con.execute(
                        "INSERT INTO entries(title, ciphertext, created_at, tags, favorite, deleted_at) VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(title) DO UPDATE SET ciphertext=excluded.ciphertext, created_at=excluded.created_at, "
                        "tags=excluded.tags, favorite=excluded.favorite, deleted_at=excluded.deleted_at",
                        (t, ct, c, g, f, d)
                    )
            self.tray.showMessage("DiceTray", "Yedek içe aktarıldı", QtGui.QIcon(), 1200)
            log_event("import", Path(path).name)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"İçe aktarma başarısız: {e}")

    def change_master(self):
        dlg = ChangeMasterDialog(self)
        if dlg.exec() != QtWidgets.QDialog.Accepted: return
        curr, new1, new2 = dlg.values()
        if not new1 or new1 != new2:
            QtWidgets.QMessageBox.warning(self, "Uyarı", "Yeni parolalar boş veya eşleşmiyor."); return
        try:
            old_salt = base64.b64decode(self.cfg['salt']); old_derived = derive_key(curr, old_salt)
            blob = base64.b64decode(self.cfg.get('keycheck', b'')) if self.cfg.get('keycheck') else None
            if blob is None: QtWidgets.QMessageBox.critical(self, "Hata", "Doğrulama verisi yok."); return
            _ = decrypt_blob(old_derived, blob)
        except Exception:
            QtWidgets.QMessageBox.critical(self, "Hata", "Mevcut parola hatalı."); return
        new_salt = secrets.token_bytes(16); new_derived = derive_key(new1, new_salt)
        cur = self.con.cursor(); cur.execute("SELECT id, ciphertext FROM entries"); rows = cur.fetchall()
        try:
            with self.con:
                for rid, ct in rows:
                    plain = decrypt_blob(old_derived, ct)
                    new_ct = encrypt_blob(new_derived, plain)
                    self.con.execute("UPDATE entries SET ciphertext=? WHERE id=?", (new_ct, rid))
                self.cfg['salt'] = base64.b64encode(new_salt).decode('ascii')
                self.cfg['keycheck'] = base64.b64encode(encrypt_blob(new_derived, b"DiceTrayOK")).decode('ascii')
                save_config(self.cfg)
            QtWidgets.QMessageBox.information(self, "Başarılı", "Master parola değiştirildi.")
            self.key = new_derived; log_event("master_changed")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Hata", f"Parola değiştirilemedi: {e}")

    def toggle_password_visibility(self):
        if self.pass_edit.echoMode() == QtWidgets.QLineEdit.Password:
            self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)

    @QtCore.Slot(str, str)
    def on_password_loaded(self, title: str, pw: str):
        self.title_edit.setText(title); self.pass_edit.setText(pw); log_event("load", title)
        self.tray.showMessage("DiceTray", f"Yüklendi: {title}", QtGui.QIcon(), 1000)

# -------------------------
# Sistem tepsisi
# -------------------------
def dice_icon() -> QtGui.QIcon:
    pm = QtGui.QPixmap(64, 64); pm.fill(Qt.transparent)
    p = QtGui.QPainter(pm); p.setRenderHint(QtGui.QPainter.Antialiasing)
    brush = QtGui.QBrush(Qt.white); pen = QtGui.QPen(Qt.black); pen.setWidth(3)
    p.setBrush(brush); p.setPen(pen); p.drawRoundedRect(4, 4, 56, 56, 12, 12)
    p.setBrush(Qt.black)
    for x, y in [(20,20),(44,44),(20,44),(44,20),(32,32)]: p.drawEllipse(QtCore.QPointF(x,y), 4, 4)
    p.end(); return QtGui.QIcon(pm)

# -------------------------
# Başlatma
# -------------------------
def prompt_master_key(first_run: bool, salt: bytes) -> bytes | None:
    dlg = MasterPasswordDialog(first_run)
    if dlg.exec() != QtWidgets.QDialog.Accepted: return None
    val1, val2 = dlg.value()
    if first_run:
        if not val1 or val1 != val2:
            QtWidgets.QMessageBox.warning(None, "Uyarı", "Parolalar boş veya eşleşmiyor."); return None
        return derive_key(val1, salt)
    else:
        if not val1: return None
        return derive_key(val1, salt)

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    cfg = load_or_init_config()
    salt_b64 = cfg.get('salt')
    if not salt_b64:
        cfg['salt'] = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        save_config(cfg)
        salt_b64 = cfg['salt']
    salt = base64.b64decode(salt_b64)

    first_run = not cfg.get('initialized', False)
    key = prompt_master_key(first_run, salt)
    if key is None: return 0

    if first_run:
        cfg['keycheck'] = base64.b64encode(encrypt_blob(key, b"DiceTrayOK")).decode('ascii')
        cfg['initialized'] = True; save_config(cfg)
    else:
        blob = base64.b64decode(cfg.get('keycheck', b'')) if cfg.get('keycheck') else None
        if blob:
            try: _ = decrypt_blob(key, blob)
            except Exception:
                QtWidgets.QMessageBox.critical(None, "Hata", "Master parola hatalı."); return 0

    con = init_db()

    tray = QtWidgets.QSystemTrayIcon(dice_icon())
    menu = QtWidgets.QMenu()
    act_open = menu.addAction("▸ Aç / Gizle")
    act_gen_copy = menu.addAction("▸ Hızlı Üret + Kopyala")
    act_settings = menu.addAction("▸ Ayarlar")
    menu.addSeparator()
    act_quit = menu.addAction("Çıkış")
    tray.setContextMenu(menu); tray.setToolTip("DiceTray – Modern görünüm")

    win = MainWindow(con, key, tray, cfg)

    def toggle_window(prompt_for_key=True):
        if win.isVisible():
            win.hide()
            return
        if prompt_for_key and getattr(win, "locked", False):
            dlg = MasterPasswordDialog(False)
            if dlg.exec() != QtWidgets.QDialog.Accepted: return
            val, _ = dlg.value()
            try:
                current_salt = base64.b64decode(cfg['salt'])
                derived = derive_key(val, current_salt)
                blob = base64.b64decode(cfg.get('keycheck', b'')) if cfg.get('keycheck') else None
                if blob: _ = decrypt_blob(derived, blob)
                else: QtWidgets.QMessageBox.critical(None, "Hata", "Kontrol verisi bulunamadı."); return
                win.key = derived
                win.locked = False
            except Exception:
                QtWidgets.QMessageBox.critical(None, "Hata", "Master parola hatalı."); return
        win.show(); win.activateWindow(); win.raise_()
        win.reset_auto_hide(); win.reset_lock()

    def quick_generate_copy():
        length = int(cfg.get('ui', {}).get('default_length', 20))
        pol = cfg.get('policy', {})
        pools = []
        if pol.get('upper', True): pools.append(string.ascii_uppercase)
        if pol.get('lower', True): pools.append(string.ascii_lowercase)
        if pol.get('digits', True): pools.append(string.digits)
        if pol.get('special', True): pools.append("!@#$%^&*()-_=+[]{};:,<.>?")
        if not pools: pools = [string.ascii_letters + string.digits]
        all_chars = ''.join(pools)
        required = [secrets.choice(p) for p in pools]
        if length < len(required): length = len(required)
        rest = [secrets.choice(all_chars) for _ in range(length - len(required))]
        chars = required + rest; secrets.SystemRandom().shuffle(chars)
        pw = ''.join(chars)
        QtWidgets.QApplication.clipboard().setText(pw)
        sec = int(cfg.get('ui', {}).get('clipboard_clear_seconds', 30))
        tray.showMessage("DiceTray", "Rastgele parola panoya kopyalandı", QtGui.QIcon(), 1200)
        if sec > 0: QtCore.QTimer.singleShot(sec*1000, win.clear_clipboard)
        log_event("hotkey_copy")

    act_open.triggered.connect(lambda: toggle_window(prompt_for_key=True))
    act_gen_copy.triggered.connect(quick_generate_copy)
    act_settings.triggered.connect(win.open_settings)
    act_quit.triggered.connect(app.quit)

    tray.show()

    def on_activated(reason):
        if reason == QtWidgets.QSystemTrayIcon.Trigger:
            toggle_window(prompt_for_key=True)
    tray.activated.connect(on_activated)

    if keyboard is not None:
        try:
            keyboard.add_hotkey('ctrl+alt+g', lambda: quick_generate_copy())
        except Exception:
            pass

    win.show()
    ret = app.exec()

    if keyboard is not None:
        try:
            keyboard.clear_all_hotkeys()
        except Exception:
            pass

    return ret

if __name__ == "__main__":
    raise SystemExit(main())
