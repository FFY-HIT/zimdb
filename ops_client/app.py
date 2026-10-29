"""Tkinter desktop client — business/enterprise styling."""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ops.demo_zone import ORIGIN, SCENARIOS
from ops.schema import ZoneEditBatch
from ops.service import ImageStore

COLS = ("op", "owner", "rrtype", "ttl", "rdata", "old_rdata")
COL_LABELS = {
    "op": "操作",
    "owner": "所有者 (FQDN)",
    "rrtype": "类型",
    "ttl": "TTL",
    "rdata": "RDATA",
    "old_rdata": "原 RDATA",
}

# Enterprise palette (slate + steel blue)
C = {
    "bg": "#E8ECF0",
    "panel": "#FFFFFF",
    "header": "#1B2A4A",
    "header_text": "#F5F7FA",
    "accent": "#1A5276",
    "accent_hover": "#154360",
    "border": "#C5CDD6",
    "muted": "#5D6D7E",
    "ok": "#1E8449",
    "warn": "#B7950B",
    "text": "#1C2833",
    "row_alt": "#F4F6F8",
    "input_bg": "#FFFFFF",
    "statusbar": "#D5DBE1",
}


def default_data_dir() -> Path:
    env = os.environ.get("ZIMDB_OPS_DATA")
    if env:
        return Path(env)
    return _ROOT / "ops" / "data"


def _font(size: int = 10, bold: bool = False) -> tuple:
    family = "Microsoft YaHei UI"
    return (family, size, "bold" if bold else "normal")


class OpsApp(tk.Tk):
    def __init__(self, store: ImageStore) -> None:
        super().__init__()
        self.store = store
        self.title("ZimDB 运维控制台")
        self.geometry("1100x760")
        self.minsize(960, 640)
        self.configure(bg=C["bg"])
        self._setup_style()
        self._build()
        self.refresh_status()

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=_font(10), background=C["bg"], foreground=C["text"])
        style.configure("TFrame", background=C["bg"])
        style.configure("Panel.TFrame", background=C["panel"])
        style.configure(
            "Header.TLabel",
            background=C["header"],
            foreground=C["header_text"],
            font=_font(16, bold=True),
        )
        style.configure(
            "HeaderSub.TLabel",
            background=C["header"],
            foreground="#AAB4C4",
            font=_font(9),
        )
        style.configure(
            "Metric.TLabel",
            background=C["header"],
            foreground=C["header_text"],
            font=_font(9),
        )
        style.configure(
            "MetricVal.TLabel",
            background=C["header"],
            foreground="#FFFFFF",
            font=_font(12, bold=True),
        )
        style.configure(
            "Section.TLabelframe",
            background=C["panel"],
            foreground=C["accent"],
            bordercolor=C["border"],
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "Section.TLabelframe.Label",
            background=C["panel"],
            foreground=C["accent"],
            font=_font(10, bold=True),
        )
        style.configure(
            "TLabel",
            background=C["panel"],
            foreground=C["text"],
            font=_font(9),
        )
        style.configure(
            "Muted.TLabel",
            background=C["panel"],
            foreground=C["muted"],
            font=_font(8),
        )
        style.configure(
            "TEntry",
            fieldbackground=C["input_bg"],
            foreground=C["text"],
            insertcolor=C["text"],
        )
        style.configure(
            "TCombobox",
            fieldbackground=C["input_bg"],
            foreground=C["text"],
        )
        style.configure(
            "Toolbar.TButton",
            font=_font(9),
            padding=(12, 6),
        )
        style.configure(
            "Primary.TButton",
            font=_font(10, bold=True),
            padding=(16, 8),
            background=C["accent"],
            foreground="#FFFFFF",
        )
        style.map(
            "Primary.TButton",
            background=[("active", C["accent_hover"]), ("pressed", C["accent_hover"])],
            foreground=[("disabled", "#D5D8DC")],
        )
        style.configure(
            "Treeview",
            background=C["panel"],
            fieldbackground=C["panel"],
            foreground=C["text"],
            rowheight=26,
            font=_font(9),
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=C["statusbar"],
            foreground=C["text"],
            font=_font(9, bold=True),
            relief="flat",
        )
        style.map("Treeview", background=[("selected", "#D4E6F1")])
        style.configure(
            "Status.TLabel",
            background=C["statusbar"],
            foreground=C["muted"],
            font=_font(8),
        )

    def _panel(self, parent: tk.Misc, title: str) -> ttk.LabelFrame:
        lf = ttk.LabelFrame(parent, text=f"  {title}  ", style="Section.TLabelframe")
        return lf

    def _build(self) -> None:
        # —— Top brand header ——
        header = tk.Frame(self, bg=C["header"], height=72)
        header.pack(fill="x")
        header.pack_propagate(False)
        left = tk.Frame(header, bg=C["header"])
        left.pack(side="left", padx=20, pady=12)
        ttk.Label(left, text="ZimDB", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            left,
            text="权威区运维控制台  ·  变更直接同步二进制映像",
            style="HeaderSub.TLabel",
        ).pack(anchor="w")

        metrics = tk.Frame(header, bg=C["header"])
        metrics.pack(side="right", padx=20, pady=10)
        self.m_gen = tk.StringVar(value="—")
        self.m_size = tk.StringVar(value="—")
        self.m_shards = tk.StringVar(value="—")
        self.m_backend = tk.StringVar(value="—")
        for label, var in (
            ("GENERATION", self.m_gen),
            ("映像大小", self.m_size),
            ("分片数", self.m_shards),
            ("后端", self.m_backend),
        ):
            cell = tk.Frame(metrics, bg=C["header"])
            cell.pack(side="left", padx=14)
            ttk.Label(cell, text=label, style="Metric.TLabel").pack(anchor="e")
            ttk.Label(cell, textvariable=var, style="MetricVal.TLabel").pack(anchor="e")

        # —— Body ——
        body = ttk.Frame(self, style="TFrame")
        body.pack(fill="both", expand=True, padx=14, pady=12)

        # Workspace path strip
        path_bar = tk.Frame(body, bg=C["panel"], highlightbackground=C["border"], highlightthickness=1)
        path_bar.pack(fill="x", pady=(0, 10))
        tk.Label(
            path_bar,
            text="  工作区映像",
            bg=C["panel"],
            fg=C["muted"],
            font=_font(8),
        ).pack(side="left", padx=(8, 4), pady=8)
        self.path_var = tk.StringVar(value="…")
        tk.Label(
            path_bar,
            textvariable=self.path_var,
            bg=C["panel"],
            fg=C["text"],
            font=_font(9),
            anchor="w",
        ).pack(side="left", fill="x", expand=True, pady=8)
        self.last_var = tk.StringVar(value="上次提交：—")
        tk.Label(
            path_bar,
            textvariable=self.last_var,
            bg=C["panel"],
            fg=C["muted"],
            font=_font(8),
        ).pack(side="right", padx=12, pady=8)

        # Scenario toolbar
        sc = self._panel(body, "变更场景")
        sc.pack(fill="x", pady=(0, 10))
        tip = ttk.Label(
            sc,
            text="选择场景将预填变更清单；需点击「提交变更」才会写入映像。",
            style="Muted.TLabel",
        )
        tip.pack(anchor="w", padx=12, pady=(8, 0))
        row = ttk.Frame(sc, style="Panel.TFrame")
        row.pack(fill="x", padx=12, pady=10)
        for text, key in (
            ("＋ 添加 A 记录", "add"),
            ("✎ 修改 A 记录", "modify"),
            ("－ 删除 TXT 记录", "delete"),
        ):
            ttk.Button(
                row,
                text=text,
                style="Toolbar.TButton",
                command=lambda k=key: self.load_scenario(k),
            ).pack(side="left", padx=(0, 8))
        ttk.Button(row, text="清空清单", style="Toolbar.TButton", command=self.clear_edits).pack(
            side="left", padx=(8, 0)
        )

        # Main split: edit table + right side (query/log)
        mid = ttk.Frame(body, style="TFrame")
        mid.pack(fill="both", expand=True)

        left_col = ttk.Frame(mid, style="TFrame")
        left_col.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ed = self._panel(left_col, "变更清单")
        ed.pack(fill="both", expand=True)
        tree_wrap = ttk.Frame(ed, style="Panel.TFrame")
        tree_wrap.pack(fill="both", expand=True, padx=10, pady=8)
        self.tree = ttk.Treeview(tree_wrap, columns=COLS, show="headings", height=10)
        widths = {"op": 70, "owner": 180, "rrtype": 60, "ttl": 50, "rdata": 160, "old_rdata": 140}
        for c in COLS:
            self.tree.heading(c, text=COL_LABELS[c])
            self.tree.column(c, width=widths.get(c, 100), stretch=True)
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("odd", background=C["row_alt"])
        self.tree.tag_configure("even", background=C["panel"])

        form = ttk.Frame(ed, style="Panel.TFrame")
        form.pack(fill="x", padx=10, pady=(0, 4))
        self.vars = {c: tk.StringVar() for c in COLS}
        self.vars["op"].set("ADD")
        self.vars["ttl"].set("300")
        for i, c in enumerate(COLS):
            ttk.Label(form, text=COL_LABELS[c]).grid(row=0, column=i, sticky="w", padx=2)
            if c == "op":
                w = ttk.Combobox(
                    form,
                    textvariable=self.vars[c],
                    values=("ADD", "MODIFY", "DELETE"),
                    width=10,
                    state="readonly",
                )
            else:
                w = ttk.Entry(form, textvariable=self.vars[c], width=12)
            w.grid(row=1, column=i, padx=2, sticky="ew", pady=2)
            form.columnconfigure(i, weight=1)

        btns = ttk.Frame(ed, style="Panel.TFrame")
        btns.pack(fill="x", padx=10, pady=(4, 12))
        ttk.Button(btns, text="加入清单", style="Toolbar.TButton", command=self.add_row).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(
            btns, text="移除选中", style="Toolbar.TButton", command=self.remove_selected
        ).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="提交变更", style="Primary.TButton", command=self.submit).pack(
            side="right"
        )

        right_col = ttk.Frame(mid, style="TFrame")
        right_col.pack(side="right", fill="both", expand=False)
        right_col.configure(width=340)

        qf = self._panel(right_col, "资源查询")
        qf.pack(fill="x", pady=(0, 10))
        qr = ttk.Frame(qf, style="Panel.TFrame")
        qr.pack(fill="x", padx=10, pady=8)
        self.query_var = tk.StringVar(value="www.example.com.")
        ttk.Entry(qr, textvariable=self.query_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6)
        )
        ttk.Button(qr, text="查询", style="Toolbar.TButton", command=self.do_query).pack(
            side="left"
        )
        self.query_out = tk.Text(
            qf,
            height=8,
            wrap="word",
            font=_font(9),
            bg="#FBFCFD",
            fg=C["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=C["border"],
            insertbackground=C["text"],
        )
        self.query_out.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        lg = self._panel(right_col, "操作审计")
        lg.pack(fill="both", expand=True)
        self.log = tk.Text(
            lg,
            height=12,
            wrap="word",
            font=_font(8),
            bg="#FBFCFD",
            fg=C["muted"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=C["border"],
            insertbackground=C["text"],
        )
        self.log.pack(fill="both", expand=True, padx=10, pady=10)

        # —— Status bar ——
        sb = tk.Frame(self, bg=C["statusbar"], height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self.sb_var = tk.StringVar(value="就绪")
        tk.Label(
            sb,
            textvariable=self.sb_var,
            bg=C["statusbar"],
            fg=C["muted"],
            font=_font(8),
            anchor="w",
        ).pack(side="left", padx=12)
        tk.Label(
            sb,
            text=f"Origin  {ORIGIN}",
            bg=C["statusbar"],
            fg=C["muted"],
            font=_font(8),
        ).pack(side="right", padx=12)

    def log_line(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def refresh_status(self) -> None:
        st = self.store.status()
        self.path_var.set(st["path"])
        self.m_gen.set(str(st["generation"]))
        size = int(st["size_bytes"])
        if size >= 1024:
            self.m_size.set(f"{size / 1024:.1f} KB")
        else:
            self.m_size.set(f"{size} B")
        self.m_shards.set(str(st["shard_count"]))
        self.m_backend.set(str(st["backend"]))
        last = st.get("last_apply")
        if last:
            self.last_var.set(
                f"上次提交：gen {last['generation_before']}→{last['generation_after']}  "
                f"{last['elapsed_s']}s  "
                f"{last['size_before']}→{last['size_after']} B"
            )
            self.sb_var.set(
                f"已同步 · generation {last['generation_after']} · "
                f"耗时 {last['elapsed_s']}s"
            )
        else:
            self.last_var.set("上次提交：无")
            self.sb_var.set("就绪 · 尚未提交变更")

    def clear_edits(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.sb_var.set("变更清单已清空")

    def _retag(self) -> None:
        for n, iid in enumerate(self.tree.get_children()):
            self.tree.item(iid, tags=("odd" if n % 2 else "even",))

    def load_scenario(self, name: str) -> None:
        self.clear_edits()
        for row in SCENARIOS[name]:
            self.tree.insert(
                "",
                "end",
                values=(
                    row["op"],
                    row["owner"],
                    row["rrtype"],
                    row["ttl"],
                    row["rdata"],
                    row.get("old_rdata") or "",
                ),
            )
        self._retag()
        labels = {"add": "添加", "modify": "修改", "delete": "删除"}
        self.log_line(f"[场景] 已载入「{labels.get(name, name)}」预填，待提交。")
        self.sb_var.set(f"已载入场景「{labels.get(name, name)}」— 请核对后提交")

    def add_row(self) -> None:
        vals = [self.vars[c].get().strip() for c in COLS]
        if not vals[0] or not vals[1] or not vals[2]:
            messagebox.showwarning("信息不完整", "至少需要填写：操作、所有者、类型。")
            return
        self.tree.insert("", "end", values=vals)
        self._retag()

    def remove_selected(self) -> None:
        for i in self.tree.selection():
            self.tree.delete(i)
        self._retag()

    def _batch_from_tree(self) -> ZoneEditBatch:
        rows = []
        for iid in self.tree.get_children():
            v = self.tree.item(iid, "values")
            rows.append(
                {
                    "op": v[0],
                    "owner": v[1],
                    "rrtype": v[2],
                    "ttl": v[3],
                    "rdata": v[4],
                    "old_rdata": v[5] or None,
                }
            )
        return ZoneEditBatch.from_dicts(ORIGIN, rows)

    def submit(self) -> None:
        if not self.tree.get_children():
            messagebox.showinfo("变更清单为空", "请先添加变更或选择场景。")
            return
        try:
            batch = self._batch_from_tree()
        except Exception as exc:
            messagebox.showerror("校验失败", str(exc))
            return
        self.sb_var.set("正在提交变更…")
        self.update_idletasks()
        result = self.store.apply(batch)
        self.log_line(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        self.refresh_status()
        if result.ok:
            messagebox.showinfo(
                "变更已同步",
                f"映像 generation：{result.generation_before} → {result.generation_after}\n"
                f"大小：{result.size_before} → {result.size_after} 字节\n"
                f"耗时：{result.elapsed_s:.4f} 秒",
            )
        else:
            messagebox.showerror("提交失败（映像未修改）", result.error or "unknown")
            self.sb_var.set("提交失败 · 映像保持原状态")

    def do_query(self) -> None:
        owner = self.query_var.get().strip()
        try:
            rows = self.store.preview_owner(owner)
        except Exception as exc:
            messagebox.showerror("查询失败", str(exc))
            return
        self.query_out.delete("1.0", "end")
        if not rows:
            self.query_out.insert("end", f"（无记录）{owner}\n")
        else:
            for r in rows:
                self.query_out.insert(
                    "end",
                    f"{r['owner']}  {r['ttl']}  IN  {r['rrtype']}  {r['rdata']}\n",
                )
        self.sb_var.set(f"查询完成 · {owner}")


def main() -> int:
    data = default_data_dir()
    data.mkdir(parents=True, exist_ok=True)
    store = ImageStore(data / "zone.zimdb", origin=ORIGIN)
    store.ensure()
    app = OpsApp(store)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
