"""Bilingual local GUI. No network, saved secrets or implicit algorithm fallback."""
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from core import hdt
from desktop.jobs import run

SUITES = [("64 MiB · Compatible / 兼容", 1), ("256 MiB · Standard / 标准", 2),
          ("512 MiB · High memory / 高内存", 3), ("1024 MiB · High memory / 高内存", 4),
          ("64 MiB · SHA-512 research / 实验", 257), ("256 MiB · SHA-512 research / 实验", 258),
          ("512 MiB · SHA-512 research / 实验", 259), ("1024 MiB · SHA-512 research / 实验", 260)]
BUDGETS = [(f"{n} MiB", n) for n in (64, 256, 512, 1024)]


class App:
    def __init__(self, root):
        self.root = root
        root.title("MOSAIC-HDT | File Encryptor")
        root.geometry("780x700")
        root.minsize(650, 650)
        self.busy = False
        self.messages = queue.Queue()
        self.mode = tk.StringVar(value="encrypt")
        self.paths = [tk.StringVar() for _ in range(3)]
        self.secrets = [tk.StringVar() for _ in range(3)]
        self.confirm = [tk.StringVar() for _ in range(3)]
        self.reveal = tk.BooleanVar(value=False)
        style = ttk.Style(root)
        style.configure("Title.TLabel", font=("TkDefaultFont", 20, "bold"))
        style.configure("Section.TLabel", font=("TkDefaultFont", 11, "bold"))
        frame = ttk.Frame(root, padding=22)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="MOSAIC-HDT", style="Title.TLabel").grid(sticky="w")
        ttk.Label(frame, text="LOCAL FILE ENCRYPTION / 本地文件加密 · Experimental / 实验版").grid(sticky="w", pady=(0, 12))
        toolbar = ttk.Frame(frame)
        toolbar.grid(sticky="ew", pady=(0, 8))
        self.controls = []
        for value, title in (("encrypt", "Encrypt / 加密"), ("decrypt", "Decrypt / 解密")):
            b = ttk.Radiobutton(toolbar, text=title, variable=self.mode, value=value, command=self.change_mode)
            b.pack(side="left", padx=(0, 18)); self.controls.append(b)
        self.form = ttk.LabelFrame(frame, text="01  Files / 文件", padding=10)
        self.form.grid(sticky="ew", pady=(0, 10))
        self.form.columnconfigure(1, weight=1)
        self.labels = []
        for i, label in enumerate(("Source / 原文件", "Encrypted / 密文", "Keyfile / 密钥文件")):
            l = ttk.Label(self.form, text=label); l.grid(row=i, column=0, sticky="w", padx=(0, 8), pady=4); self.labels.append(l)
            e = ttk.Entry(self.form, textvariable=self.paths[i]); e.grid(row=i, column=1, sticky="ew", pady=4); self.controls.append(e)
            b = ttk.Button(self.form, text="Browse / 选择", command=lambda n=i:self.browse(n)); b.grid(row=i, column=2, padx=(6, 0), pady=4); self.controls.append(b)
        secretbox = ttk.LabelFrame(frame, text="02  Three secrets / 三个秘密参数", padding=10)
        secretbox.grid(sticky="ew", pady=(0, 10)); secretbox.columnconfigure(1, weight=1); secretbox.columnconfigure(2, weight=1)
        self.entries, self.confirm_entries = [], []
        for i, letter in enumerate(("α", "β", "γ")):
            ttk.Label(secretbox, text=letter).grid(row=i, column=0, padx=(0, 12), pady=3)
            e = ttk.Entry(secretbox, textvariable=self.secrets[i], show="*"); e.grid(row=i, column=1, sticky="ew", pady=3); self.entries.append(e); self.controls.append(e)
            e = ttk.Entry(secretbox, textvariable=self.confirm[i], show="*"); e.grid(row=i, column=2, sticky="ew", padx=(8, 0), pady=3); self.confirm_entries.append(e); self.controls.append(e)
        ttk.Label(secretbox, text="Input / 输入").grid(row=3, column=1, sticky="w")
        self.confirm_label = ttk.Label(secretbox, text="Confirm / 确认"); self.confirm_label.grid(row=3, column=2, sticky="w", padx=8)
        reveal = ttk.Checkbutton(secretbox, text="Show / 显示", variable=self.reveal, command=self.update_visibility); reveal.grid(row=4, column=1, sticky="w", pady=(5, 0)); self.controls.append(reveal)
        self.generate = ttk.Button(secretbox, text="Generate random / 随机生成", command=self.generate_secrets); self.generate.grid(row=4, column=2, sticky="e", pady=(5, 0)); self.controls.append(self.generate)
        settings = ttk.LabelFrame(frame, text="03  Security / 安全配置", padding=10)
        settings.grid(sticky="ew", pady=(0, 10)); settings.columnconfigure(1, weight=1)
        self.setting_label = ttk.Label(settings); self.setting_label.grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.choice = ttk.Combobox(settings, state="readonly", width=40); self.choice.grid(row=0, column=1, sticky="ew"); self.controls.append(self.choice)
        ttk.Label(settings, text="Use random secrets. No recovery bypass. Keep keyfile separate.\n推荐随机参数；无恢复后门；密钥与密文分开保存。", wraplength=640).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.go = ttk.Button(frame, command=self.start); self.go.grid(sticky="ew", pady=(0, 7)); self.controls.append(self.go)
        self.progress = ttk.Progressbar(frame, mode="indeterminate"); self.progress.grid(sticky="ew")
        self.status = tk.StringVar(value="Ready / 就绪")
        ttk.Label(frame, textvariable=self.status, wraplength=680, justify="left").grid(sticky="w", pady=(8, 0))
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.change_mode()
        root.after(100, self.poll)

    def update_visibility(self):
        for e in self.entries + self.confirm_entries:
            e.configure(show="" if self.reveal.get() else "*")

    def clear_secrets(self):
        for v in self.secrets + self.confirm: v.set("")
        self.reveal.set(False); self.update_visibility()

    def change_mode(self):
        enc = self.mode.get() == "encrypt"
        for v in self.paths: v.set("")
        self.clear_secrets()
        self.labels[0].configure(text="Source / 原文件" if enc else "Encrypted / 密文")
        self.labels[1].configure(text="Encrypted / 密文" if enc else "Restore to / 恢复到")
        self.setting_label.configure(text="Suite / 套件" if enc else "Memory cap / 内存上限")
        self.choice.configure(values=[n for n, _ in (SUITES if enc else BUDGETS)])
        self.choice.current(1)
        self.go.configure(text="Generate ciphertext + key / 生成密文和密钥" if enc else "Verify and decrypt / 验证并解密")
        for e in self.confirm_entries: e.configure(state="normal" if enc else "disabled")
        self.generate.configure(state="normal" if enc else "disabled")
        self.status.set("Ready / 就绪")

    def browse(self, index):
        enc = self.mode.get() == "encrypt"
        if index == 0 or (index == 2 and not enc):
            path = filedialog.askopenfilename(parent=self.root, filetypes=[("All files / 所有文件", "*")])
        else:
            extension = (".mkey" if index == 2 else ".hdt") if enc else ""
            path = filedialog.asksaveasfilename(parent=self.root, defaultextension=extension)
        if not path: return
        self.paths[index].set(path)
        if index == 0:
            p = Path(path)
            if enc:
                self.paths[1].set(str(p) + ".hdt"); self.paths[2].set(str(p) + ".mkey")
            else:
                base = p.name.removesuffix(".hdt")
                self.paths[1].set(str(p.with_name(base + ".restored")))

    def generate_secrets(self):
        for value, a, b in zip(hdt.generate_parameters(), self.secrets, self.confirm):
            a.set(value); b.set(value)
        self.reveal.set(True); self.update_visibility()
        messagebox.showinfo("Save secrets / 保存参数", "Record all three values in a trusted offline location before encrypting. The app will clear them when starting.\n请先在可信离线位置保存三个参数；开始任务后软件将清空输入框。", parent=self.root)

    def start(self):
        if self.busy: return
        mode = self.mode.get(); setting = (SUITES if mode == "encrypt" else BUDGETS)[self.choice.current()][1]
        args = (mode, *(v.get() for v in self.paths), tuple(v.get() for v in self.secrets), tuple(v.get() for v in self.confirm), setting)
        from desktop.jobs import prepare
        try:
            prepare(*args)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Check inputs / 检查输入", "Invalid paths, parameters, or confirmation. Check all fields. / 路径、参数或确认值不合法，请检查全部字段。", parent=self.root); return
        if mode == "encrypt" and not messagebox.askokcancel("Confirm / 确认", "Have you backed up all three secrets? You need every secret and the keyfile to decrypt.\n已妥善备份三个参数？解密需要全部参数和密钥文件。", parent=self.root): return
        self.busy = True
        self.clear_secrets()
        for w in self.controls: w.configure(state="disabled")
        self.status.set("Working / 正在处理，请勿关闭")
        self.progress.start(12)
        threading.Thread(target=self.worker, args=(args,), daemon=False).start()

    def worker(self, args):
        result = run(*args, stage=lambda s:self.messages.put(("stage", s)))
        self.messages.put(("result", result))

    def poll(self):
        try:
            while True:
                kind, value = self.messages.get_nowait()
                if kind == "stage": self.status.set(value)
                else:
                    self.busy = False; self.progress.stop()
                    for w in self.controls: w.configure(state="normal")
                    self.choice.configure(state="readonly")
                    if self.mode.get() == "decrypt":
                        for e in self.confirm_entries: e.configure(state="disabled")
                        self.generate.configure(state="disabled")
                    self.status.set(value.message)
                    show = {"ok":messagebox.showinfo, "error":messagebox.showerror, "warning":messagebox.showwarning}[value.status]
                    show("MOSAIC-HDT", value.message, parent=self.root)
        except queue.Empty: pass
        self.root.after(100, self.poll)

    def close(self):
        if self.busy:
            messagebox.showwarning("Working / 正在处理", "Wait for the operation to finish before closing. / 请等待任务结束再关闭。", parent=self.root); return
        self.clear_secrets(); self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__": main()
