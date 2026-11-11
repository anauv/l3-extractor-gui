#!/usr/bin/env python3
"""
Cross-platform GUI (Windows & macOS) for the L3 extractor.

Built with customtkinter for a modern look. The heavy work runs on a
background thread so the window stays responsive.
"""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from .core import REQUIRED_FILES, L3Error, L3Result, extract_l3, missing_files

APP_NAME = "L3 Extractor"


class L3App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.title(APP_NAME)
        self.geometry("760x620")
        self.minsize(680, 560)

        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._result: L3Result | None = None
        self._worker: threading.Thread | None = None

        self._build()
        self.after(100, self._drain_log)

    # ------------------------------------------------------------------ UI
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = ctk.CTkLabel(
            self, text="L3 Extractor",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, padx=20, pady=(20, 0), sticky="w")
        sub = ctk.CTkLabel(
            self,
            text="Derive the L3 RSA key (n, d, e) for a BTLD from a PSdZData set.",
            text_color=("gray40", "gray70"),
        )
        sub.grid(row=0, column=0, padx=20, pady=(52, 0), sticky="w")

        # --- inputs frame ---
        form = ctk.CTkFrame(self)
        form.grid(row=1, column=0, padx=20, pady=(16, 8), sticky="ew")
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Input folder").grid(
            row=0, column=0, padx=(16, 8), pady=16, sticky="w"
        )
        self.folder_var = tk.StringVar()
        self.folder_entry = ctk.CTkEntry(
            form, textvariable=self.folder_var,
            placeholder_text="Folder with the 5 sec_* / bmw_* files",
        )
        self.folder_entry.grid(row=0, column=1, padx=8, pady=16, sticky="ew")
        ctk.CTkButton(form, text="Browse\u2026", width=90, command=self._pick_folder).grid(
            row=0, column=2, padx=(8, 16), pady=16
        )

        ctk.CTkLabel(form, text="BTLD ID").grid(
            row=1, column=0, padx=(16, 8), pady=(0, 16), sticky="w"
        )
        self.btld_var = tk.StringVar(value="btld-000014E0")
        self.btld_entry = ctk.CTkEntry(
            form, textvariable=self.btld_var, placeholder_text="btld-000014E0",
        )
        self.btld_entry.grid(row=1, column=1, columnspan=2, padx=8, pady=(0, 16), sticky="ew")

        self.files_label = ctk.CTkLabel(
            form, text="", text_color=("gray40", "gray70"), anchor="w", justify="left",
        )
        self.files_label.grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="ew")

        # --- action row ---
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=2, column=0, padx=20, pady=(0, 8), sticky="ew")
        actions.grid_columnconfigure(3, weight=1)

        self.run_btn = ctk.CTkButton(actions, text="Extract", width=120, command=self._run)
        self.run_btn.grid(row=0, column=0, padx=(0, 8))
        self.save_btn = ctk.CTkButton(
            actions, text="Save l3_\u2026.py", width=130,
            state="disabled", command=self._save,
        )
        self.save_btn.grid(row=0, column=1, padx=8)
        self.copy_btn = ctk.CTkButton(
            actions, text="Copy result", width=120,
            state="disabled", command=self._copy,
        )
        self.copy_btn.grid(row=0, column=2, padx=8)
        self.progress = ctk.CTkProgressBar(actions)
        self.progress.grid(row=0, column=3, padx=(8, 0), sticky="ew")
        self.progress.set(0)

        # --- log ---
        self.log_box = ctk.CTkTextbox(self, font=ctk.CTkFont(family="monospace", size=12))
        self.log_box.grid(row=3, column=0, padx=20, pady=(8, 8), sticky="nsew")
        self.log_box.configure(state="disabled")

        self.status = ctk.CTkLabel(self, text="Ready.", anchor="w",
                                   text_color=("gray40", "gray70"))
        self.status.grid(row=4, column=0, padx=22, pady=(0, 16), sticky="ew")

    # ------------------------------------------------------------- actions
    def _pick_folder(self):
        d = filedialog.askdirectory(title="Select the input folder")
        if d:
            self.folder_var.set(d)
            self._check_folder()

    def _check_folder(self):
        d = self.folder_var.get().strip()
        if not d or not os.path.isdir(d):
            self.files_label.configure(text="")
            return
        miss = missing_files(d)
        if not miss:
            self.files_label.configure(
                text="\u2713 All 5 input files found.", text_color=("green", "#4ec94e")
            )
        else:
            self.files_label.configure(
                text="Missing: " + ", ".join(miss), text_color=("#b00", "#ff6b6b")
            )

    def _log(self, msg: str):
        self._log_queue.put(msg)

    def _drain_log(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                self.log_box.configure(state="normal")
                self.log_box.insert("end", msg + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._drain_log)

    def _run(self):
        if self._worker and self._worker.is_alive():
            return
        folder = self.folder_var.get().strip()
        btld = self.btld_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror(APP_NAME, "Please select a valid input folder.")
            return
        if not btld:
            messagebox.showerror(APP_NAME, "Please enter a BTLD ID.")
            return

        self._result = None
        self.save_btn.configure(state="disabled")
        self.copy_btn.configure(state="disabled")
        self.run_btn.configure(state="disabled", text="Working\u2026")
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.status.configure(text="Extracting\u2026")
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

        self._worker = threading.Thread(
            target=self._work, args=(folder, btld), daemon=True
        )
        self._worker.start()

    def _work(self, folder: str, btld: str):
        try:
            result = extract_l3(folder, btld, log=self._log)
            self.after(0, self._done, result, None)
        except L3Error as e:
            self.after(0, self._done, None, str(e))
        except Exception as e:  # pragma: no cover
            self.after(0, self._done, None, f"Unexpected error: {e}")

    def _done(self, result: L3Result | None, error: str | None):
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1 if result else 0)
        self.run_btn.configure(state="normal", text="Extract")
        if error:
            self.status.configure(text="Failed.")
            self._log("\nERROR: " + error)
            messagebox.showerror(APP_NAME, error)
            return
        self._result = result
        self.status.configure(text=f"Done \u2014 {result.btld}")
        self._log("\n" + result.as_python())
        self._log(f"n_sha256: {result.n_sha256}")
        self.save_btn.configure(state="normal")
        self.copy_btn.configure(state="normal")

    def _default_name(self) -> str:
        safe = self._result.btld.replace("btld-", "").replace(".", "_").upper()
        return f"l3_{safe}.py"

    def _save(self):
        if not self._result:
            return
        path = filedialog.asksaveasfilename(
            title="Save L3 constants",
            defaultextension=".py",
            initialfile=self._default_name(),
            filetypes=[("Python file", "*.py"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w") as f:
            f.write(self._result.as_python())
        self.status.configure(text=f"Saved: {path}")

    def _copy(self):
        if not self._result:
            return
        self.clipboard_clear()
        self.clipboard_append(self._result.as_python())
        self.status.configure(text="Result copied to clipboard.")


def main():
    app = L3App()
    app.mainloop()


if __name__ == "__main__":
    main()
