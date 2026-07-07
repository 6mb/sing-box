---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

# Bridge

!!! quote ""

    仅支持 Linux 和 macOS，且需要特权。

`bridge` 仅接受通过[预匹配](/zh/configuration/shared/pre-match/)中的 `route`
动作转发的 L3 连接（TCP、UDP 和 ICMP），L4 连接将被拒绝。

### 结构

```json
{
  "type": "bridge",
  "tag": "bridge-out",

  "interface": "",
  "bridge_name": "",
  "iproute2_table_index": 0,
  "iproute2_rule_index": 0
}
```

### 字段

#### interface

转发流量流出的网络接口名称。

默认使用默认接口。

接口不可用期间，转发流量将被丢弃。

#### bridge_name

自定义 bridge TUN 接口名前缀，默认使用 `bridge`。

在 Apple 平台上无效。

#### iproute2_table_index

!!! quote ""

    仅支持 Linux，且仅在设置了 `interface` 时生效。

用于固定出口路由的 Linux iproute2 路由表索引。

默认使用 `2200` + 实例索引。

#### iproute2_rule_index

!!! quote ""

    仅支持 Linux。

Linux iproute2 规则起始索引。

默认使用 `100`。
