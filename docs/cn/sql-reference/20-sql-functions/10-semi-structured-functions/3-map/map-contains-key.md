---
title: MAP_CONTAINS_KEY
---
import FunctionDescription from '@site/src/components/FunctionDescription';

<FunctionDescription description="引入或更新于：v1.2.464"/>

判断指定的 MAP (Map) 是否包含指定的键 (Key)。

## 语法

```sql
MAP_CONTAINS_KEY( <map>, <key> )
```

## 参数

| 参数 | 说明 |
|-----------|-------------------------|
| `<map>` | 待搜索的 MAP。 |
| `<key>` | 待查找的键。 |

## 返回类型

布尔值（Boolean）。

## 示例

```sql
SELECT MAP_CONTAINS_KEY({'a':1,'b':2,'c':3}, 'c');
┌────────────────────────────────────────────┐
│ map_contains_key({'a':1,'b':2,'c':3}, 'c') │
├────────────────────────────────────────────┤
│ true                                       │
└────────────────────────────────────────────┘

SELECT MAP_CONTAINS_KEY({'a':1,'b':2,'c':3}, 'x');
┌────────────────────────────────────────────┐
│ map_contains_key({'a':1,'b':2,'c':3}, 'x') │
├────────────────────────────────────────────┤
│ false                                      │
└────────────────────────────────────────────┘
```