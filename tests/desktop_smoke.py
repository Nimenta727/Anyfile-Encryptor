"""Display-required real Tk GUI integration check, using public fixtures only."""
import tempfile
import time
import tkinter as tk
from pathlib import Path
from unittest.mock import patch
from desktop.app import App


def wait(root, app):
    until = time.monotonic() + 25
    while app.busy and time.monotonic() < until:
        root.update()
        time.sleep(.02)
    assert not app.busy, "GUI job timeout"


def main():
    with tempfile.TemporaryDirectory() as td:
        root = tk.Tk()
        app = App(root)
        p = Path(td)
        source, cipher, key, restored = (p / n for n in ("原始.txt", "out.hdt", "out.mkey", "restored.txt"))
        source.write_bytes(b"public GUI fixture" * 70000)
        parts = ("public-alpha-001", "public-beta-002", "public-gamma-003")
        notices = []
        def notice(*args, **kwargs): notices.append(args)
        with patch("desktop.app.messagebox.askokcancel", return_value=True), patch("desktop.app.messagebox.showinfo", side_effect=notice), patch("desktop.app.messagebox.showerror", side_effect=notice), patch("desktop.app.messagebox.showwarning", side_effect=notice):
            with patch("desktop.app.filedialog.askopenfilename", return_value=str(source)):
                app.browse(0)
            assert app.paths[0].get() == str(source) and app.paths[1].get().endswith(".hdt")
            for var, value in zip(app.paths, map(str, (source, cipher, key))): var.set(value)
            for a, b, value in zip(app.secrets, app.confirm, parts): a.set(value); b.set(value)
            app.choice.current(0)
            app.go.invoke(); assert app.busy
            assert all(v.get() == "" for v in app.secrets + app.confirm)
            wait(root, app)
            assert cipher.is_file() and key.is_file() and "加密完成" in app.status.get()
            app.mode.set("decrypt"); app.change_mode()
            assert str(app.confirm_entries[0].cget("state")) == "disabled"
            for var, value in zip(app.paths, map(str, (cipher, restored, key))): var.set(value)
            for var, value in zip(app.secrets, parts): var.set(value)
            app.choice.current(0); app.go.invoke(); wait(root, app)
            assert restored.read_bytes() == source.read_bytes()
            assert "恢复完成" in app.status.get() and len(notices) == 2
            app.close()
    print("PASS real Tk GUI encrypt/decrypt, browse, masking/clear, mode and worker")


if __name__ == "__main__": main()
