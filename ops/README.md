# Ops 编辑 API（区域变更 → 二进制映像）

运维人员用 `ZoneEdit` / `ZoneEditBatch` 描述 ADD / MODIFY / DELETE，经 `ImageStore.apply` 写入本地二进制映像（原子 rename）。

## 当前后端

| Backend | 状态 |
|---------|------|
| `container_v23` | **可用**（分片 container Apply） |
| 生产 DNSSEC `.bogi`（390s encoder） | **未接通** — `ApplyBackend` 协议预留插槽 |

演示区：内置 `example.com.`（见 `demo_zone.py`），数据目录默认 `ops/data/zone.zimdb`。

## 契约

```json
{
  "origin": "example.com.",
  "edits": [
    {"op": "ADD", "owner": "www.example.com.", "rrtype": "A", "ttl": 300, "rdata": "203.0.113.10"},
    {"op": "MODIFY", "owner": "api.example.com.", "rrtype": "A", "ttl": 300, "rdata": "203.0.113.99", "old_rdata": "203.0.113.1"},
    {"op": "DELETE", "owner": "old.example.com.", "rrtype": "TXT", "ttl": 300, "rdata": "\"to-be-deleted\""}
  ]
}
```

Python：

```python
from pathlib import Path
from ops.service import ImageStore
from ops.schema import ZoneEditBatch
from ops.demo_zone import ORIGIN, SCENARIOS

store = ImageStore(Path("ops/data/zone.zimdb"))
store.ensure()
batch = ZoneEditBatch.from_dicts(ORIGIN, SCENARIOS["add"])
print(store.apply(batch).to_dict())
print(store.preview_owner("www.example.com."))
```

## 桌面 GUI

见仓库根 README「Ops 编辑客户端」；或：

```bash
# 在仓库根目录
python -m ops_client
```
