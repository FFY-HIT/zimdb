"""Tkinter desktop client: scenario edits → submit → binary image sync."""
from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

# Repo root on sys.path when launched as python -m ops_client
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from ops.demo_zone import ORIGIN, SCENARIOS
from ops.schema import ZoneEditBatch
from ops.service import ImageStore

COLS = ("op", "owner", "rrtype", "ttl", "rdata", "old_rdata")


def default_data_dir() -> Path:
    env = os.environ.get("ZIMDB_OPS_DATA")
    if env:
        return Path(env)
    return _ROOT / "ops" / "data"


class OpsApp(tk.Tk):
    def __init__(self, store: ImageStore) -> None:
        super().__init__()
        self.store = store
        self.title("ZimDB Ops — 区域编辑 → 二进制映像")
        self.geometry("980x720")
        self.minsize(860, 600)
        self._build()
        self.refresh_status()

    def _build(self) -> None:
        pad = {"padx": 10, "pady": 6}
        # Status
        st = ttk.LabelFrame(self, text="映像状态")
        st.pack(fill="x", **pad)
        self.status_var = tk.StringVar(value="…")
        ttk.Label(st, textvariable=self.status_var, justify="left").pack(
            anchor="w", padx=8, pady=6
        )

        # Scenarios
        sc = ttk.LabelFrame(self, text="运维场景（填入编辑表，需点提交才写入映像）")
        sc.pack(fill="x", **pad)
        row = ttk.Frame(sc)
        row.pack(fill="x", padx=8, pady=6)
        ttk.Button(row, text="添加 A 记录", command=lambda: self.load_scenario("add")).pack(
            side="left", padx=4
        )
        ttk.Button(
            row, text="修改 A 记录", command=lambda: self.load_scenario("modify")
        ).pack(side="left", padx=4)
        ttk.Button(
            row, text="删除 TXT 记录", command=lambda: self.load_scenario("delete")
        ).pack(side="left", padx=4)
        ttk.Button(row, text="清空编辑表", command=self.clear_edits).pack(side="left", padx=4)

        # Edit table
        ed = ttk.LabelFrame(self, text="编辑批（ADD / MODIFY / DELETE）")
        ed.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(ed, columns=COLS, show="headings", height=8)
        widths = {
            "op": 80,
            "owner": 200,
            "rrtype": 70,
            "ttl": 60,
            "rdata": 220,
            "old_rdata": 180,
        }
        for c in COLS:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths.get(c, 100), stretch=True)
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)

        form = ttk.Frame(ed)
        form.pack(fill="x", padx=8, pady=4)
        self.vars = {c: tk.StringVar() for c in COLS}
        self.vars["op"].set("ADD")
        self.vars["ttl"].set("300")
        for i, c in enumerate(COLS):
            ttk.Label(form, text=c).grid(row=0, column=i, sticky="w")
            if c == "op":
                w = ttk.Combobox(
                    form,
                    textvariable=self.vars[c],
                    values=("ADD", "MODIFY", "DELETE"),
                    width=10,
                    state="readonly",
                )
            else:
                w = ttk.Entry(form, textvariable=self.vars[c], width=14)
            w.grid(row=1, column=i, padx=2, sticky="ew")
            form.columnconfigure(i, weight=1)
        btns = ttk.Frame(ed)
        btns.pack(fill="x", padx=8, pady=4)
        ttk.Button(btns, text="加入批", command=self.add_row).pack(side="left", padx=4)
        ttk.Button(btns, text="删除选中行", command=self.remove_selected).pack(
            side="left", padx=4
        )
        ttk.Button(btns, text="提交到映像", command=self.submit).pack(side="left", padx=12)

        # Query
        qf = ttk.LabelFrame(self, text="查询映像中的 owner")
        qf.pack(fill="x", **pad)
        qr = ttk.Frame(qf)
        qr.pack(fill="x", padx=8, pady=4)
        self.query_var = tk.StringVar(value="www.example.com.")
        ttk.Entry(qr, textvariable=self.query_var).pack(
            side="left", fill="x", expand=True, padx=(0, 6)
        )
        ttk.Button(qr, text="查询", command=self.do_query).pack(side="left")
        self.query_out = tk.Text(qf, height=6, wrap="word")
        self.query_out.pack(fill="x", padx=8, pady=4)

        # Log
        lg = ttk.LabelFrame(self, text="提交日志")
        lg.pack(fill="both", expand=False, **pad)
        self.log = tk.Text(lg, height=8, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=4)

    def log_line(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")

    def refresh_status(self) -> None:
        st = self.store.status()
        last = st.get("last_apply")
        last_s = (
            f"last_apply gen {last['generation_before']}→{last['generation_after']} "
            f"in {last['elapsed_s']}s size {last['size_before']}→{last['size_after']}"
            if last
            else "尚未提交"
        )
        self.status_var.set(
            f"path: {st['path']}\n"
            f"backend: {st['backend']}  origin: {st['origin']}  "
            f"generation: {st['generation']}  shards: {st['shard_count']}  "
            f"size: {st['size_bytes']} B\n"
            f"{last_s}"
        )

    def clear_edits(self) -> None:
        for i in self.tree.get_children():
            self.tree.delete(i)

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
        self.log_line(f"已载入场景「{name}」，请点「提交到映像」")

    def add_row(self) -> None:
        vals = [self.vars[c].get().strip() for c in COLS]
        if not vals[0] or not vals[1] or not vals[2]:
            messagebox.showwarning("不完整", "至少需要 op / owner / rrtype")
            return
        self.tree.insert("", "end", values=vals)

    def remove_selected(self) -> None:
        for i in self.tree.selection():
            self.tree.delete(i)

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
            messagebox.showinfo("空批", "编辑表为空")
            return
        try:
            batch = self._batch_from_tree()
        except Exception as exc:
            messagebox.showerror("校验失败", str(exc))
            return
        result = self.store.apply(batch)
        self.log_line(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        self.refresh_status()
        if result.ok:
            messagebox.showinfo(
                "已同步",
                f"generation {result.generation_before} → {result.generation_after}\n"
                f"size {result.size_before} → {result.size_after} bytes\n"
                f"elapsed {result.elapsed_s:.4f}s",
            )
        else:
            messagebox.showerror("Apply 失败（映像未改）", result.error or "unknown")

    def do_query(self) -> None:
        owner = self.query_var.get().strip()
        try:
            rows = self.store.preview_owner(owner)
        except Exception as exc:
            messagebox.showerror("查询失败", str(exc))
            return
        self.query_out.delete("1.0", "end")
        if not rows:
            self.query_out.insert("end", f"(无记录) {owner}\n")
        else:
            for r in rows:
                self.query_out.insert(
                    "end",
                    f"{r['owner']}  {r['ttl']}  IN  {r['rrtype']}  {r['rdata']}\n",
                )


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
