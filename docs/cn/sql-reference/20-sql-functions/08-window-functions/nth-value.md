---
title: NTH_VALUE
---

import FunctionDescription from '@site/src/components/FunctionDescription';

<FunctionDescription description="引入或更新于：v1.2.697"/>

返回窗口框架中第 `N` 个位置的值，其中 `N` 是一个指定整数，用于确定值的确切位置。

另请参阅：

- [FIRST_VALUE](first-value.md)
- [LAST_VALUE](last-value.md)

## 语法

```sql
NTH_VALUE (expression, n) [ { IGNORE | RESPECT } NULLS ] OVER ([PARTITION BY partition_expression] ORDER BY order_expression [window_frame])
```

- `[ { IGNORE | RESPECT } NULLS ]`: 控制窗口函数中如何处理 NULL 值。
  - 默认情况下，使用 `RESPECT NULLS`，意味着 NULL 值会被包含在计算中并影响结果。
  - 当设置为 `IGNORE NULLS` 时，NULL 值会被排除在考虑范围之外，函数仅对非 NULL 值进行操作。
  - 如果窗口框架中的所有值都是 NULL，即使指定了 `IGNORE NULLS`，函数也会返回 NULL。

- 关于窗口框架的语法，请参阅 [Window Frame Syntax](index.md#window-frame-syntax)。

## 示例

```sql
CREATE TABLE employees (
  employee_id INT,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  salary DECIMAL(10,2)
);

INSERT INTO employees (employee_id, first_name, last_name, salary)
VALUES
  (1, 'John', 'Doe', 5000.00),
  (2, 'Jane', 'Smith', 6000.00),
  (3, 'David', 'Johnson', 5500.00),
  (4, 'Mary', 'Williams', 7000.00),
  (5, 'Michael', 'Brown', 4500.00);

-- 使用 NTH_VALUE 获取第二高薪员工的 first_name
SELECT employee_id, first_name, last_name, salary,
       NTH_VALUE(first_name, 2) OVER (ORDER BY salary DESC ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING) AS second_highest_salary_first_name
FROM employees;

┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│   employee_id   │    first_name    │     last_name    │          salary          │ second_highest_salary_first_name │
├─────────────────┼──────────────────┼──────────────────┼──────────────────────────┼──────────────────────────────────┤
│               4 │ Mary             │ Williams         │ 7000.00                  │ Jane                             │
│               2 │ Jane             │ Smith            │ 6000.00                  │ Jane                             │
│               3 │ David            │ Johnson          │ 5500.00                  │ Jane                             │
│               1 │ John             │ Doe              │ 5000.00                  │ Jane                             │
│               5 │ Michael          │ Brown            │ 4500.00                  │ Jane                             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

以下示例使用 `IGNORE NULLS` 选项从窗口框架中排除 NULL 值：

```sql
CREATE or replace TABLE example AS SELECT * FROM (VALUES
	(0, 1, 614),
	(1, 1, null),
	(2, 1, null),
	(3, 1, 639),
	(4, 1, 2027)
) tbl(id, user_id, order_id);


SELECT
  id,
  user_id,
  order_id,
  NTH_VALUE (order_id, 2) IGNORE NULLS over (
    PARTITION BY user_id
    ORDER BY
      id ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
  ) AS last_order_id
FROM
  example

┌───────────────────────────────────────────────────────┐
│   id  │ user_id │     order_id     │   last_order_id  │
├───────┼─────────┼──────────────────┼──────────────────┤
│     0 │       1 │              614 │             NULL │
│     1 │       1 │             NULL │             NULL │
│     2 │       1 │             NULL │             NULL │
│     3 │       1 │              639 │             NULL │
│     4 │       1 │             2027 │              639 │
└───────────────────────────────────────────────────────┘
```