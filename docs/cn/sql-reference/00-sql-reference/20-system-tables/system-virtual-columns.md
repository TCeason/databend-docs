---
title: system.virtual_columns
---

import FunctionDescription from '@site/src/components/FunctionDescription';

<FunctionDescription description="Introduced or updated: v1.2.262"/>

包含系统中已创建的 virtual column 的信息。

另请参阅：[SHOW VIRTUAL COLUMNS](../../10-sql-commands/00-ddl/07-virtual-column/show-virtual-columns.md)

```sql
SELECT * FROM system.virtual_columns;

┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│ database │  table │ virtual_columns │         created_on         │         updated_on         │
├──────────┼────────┼─────────────────┼────────────────────────────┼────────────────────────────┤
│ default  │ test   │ val['name']     │ 2023-12-25 21:24:26.127790 │ 2023-12-25 21:24:38.455268 │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```