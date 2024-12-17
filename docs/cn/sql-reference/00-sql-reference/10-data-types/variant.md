---
title: Variant
---

VARIANT 可以存储任何其他类型的值，包括 NULL、BOOLEAN、NUMBER、STRING、ARRAY 和 OBJECT，并且内部值可以是任何级别的嵌套结构，非常适合存储各种数据。VARIANT 也可以称为 JSON，更多信息请参考 [JSON 网站](https://www.json.org/json-en.html)。

以下是在 Databend 中插入和查询 Variant 数据的示例：

创建一个表：
```sql
CREATE TABLE customer_orders(id INT64, order_data VARIANT);
```

向表中插入不同类型的值：
```sql
INSERT INTO
  customer_orders
VALUES
  (
    1,
    '{"customer_id": 123, "order_id": 1001, "items": [{"name": "Shoes", "price": 59.99}, {"name": "T-shirt", "price": 19.99}]}'
  ),
  (
    2,
    '{"customer_id": 456, "order_id": 1002, "items": [{"name": "Backpack", "price": 79.99}, {"name": "Socks", "price": 4.99}]}'
  ),
  (
    3,
    '{"customer_id": 123, "order_id": 1003, "items": [{"name": "Shoes", "price": 59.99}, {"name": "Socks", "price": 4.99}]}'
  );
```

查询结果：
```sql
SELECT * FROM customer_orders;
```

结果：
```sql
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│        id       │                                                   order_data                                                  │
├─────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│               1 │ {"customer_id":123,"items":[{"name":"Shoes","price":59.99},{"name":"T-shirt","price":19.99}],"order_id":1001} │
│               2 │ {"customer_id":456,"items":[{"name":"Backpack","price":79.99},{"name":"Socks","price":4.99}],"order_id":1002} │
│               3 │ {"customer_id":123,"items":[{"name":"Shoes","price":59.99},{"name":"Socks","price":4.99}],"order_id":1003}    │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 访问 JSON 中的元素

### 通过索引访问

VARIANT 类型包含一个数组，这是一个零基的数组，类似于许多其他编程语言。数组中的每个元素也是 VARIANT 类型。可以通过索引使用 **方括号** 访问元素。

#### 示例

创建一个表：
```sql
-- 创建一个表来存储用户爱好
CREATE TABLE user_hobbies(user_id INT64, hobbies VARIANT NULL);
```

向表中插入示例数据：
```sql
INSERT INTO user_hobbies 
VALUES
    (1, '["Cooking", "Reading", "Cycling"]'),
    (2, '["Photography", "Travel", "Swimming"]');
```

检索每个用户的首个爱好：
```sql
SELECT
  user_id,
  hobbies [0] AS first_hobby
FROM
  user_hobbies;
```
结果：
```sql
┌─────────────────────────────────────┐
│     user_id     │    first_hobby    │
├─────────────────┼───────────────────┤
│               1 │ "Cooking"         │
│               2 │ "Photography"     │
└─────────────────────────────────────┘
```

检索每个用户的第三个爱好：
```sql
SELECT
  hobbies [2],
  count() AS third_hobby
FROM
  user_hobbies
GROUP BY
  hobbies [2];
```

结果：
```sql
┌─────────────────────────────────┐
│     hobbies[2]    │ third_hobby │
├───────────────────┼─────────────┤
│ "Swimming"        │           1 │
│ "Cycling"         │           1 │
└─────────────────────────────────┘
```

通过分组检索爱好：
```sql
SELECT
  hobbies [2],
  count() AS third_hobby
FROM
  user_hobbies
GROUP BY
  hobbies [2];
```
结果：
```sql
┌────────────┬─────────────┐
│ hobbies[2] │ third_hobby │
├────────────┼─────────────┤
│ "Cycling"  │           1 │
│ "Swimming" │           1 │
└────────────┴─────────────┘
```

### 通过字段名访问

VARIANT 类型包含键值对，表示为对象，其中每个键是 VARCHAR，每个值是 VARIANT。它的功能类似于其他编程语言中的“字典”、“哈希”或“映射”。可以通过字段名使用 **方括号** 或 **冒号**，以及仅在第二级及更深层次使用 **点** 来访问值（点不能用作第一级名称表示法，以避免与表和列之间的点表示法混淆）。

#### 示例

创建一个表来存储用户偏好，使用 VARIANT 类型：
```sql
CREATE TABLE user_preferences(
  user_id INT64,
  preferences VARIANT NULL,
  profile Tuple(name STRING, age INT)
);
```

向表中插入示例数据：
```sql
INSERT INTO
  user_preferences
VALUES
  (
    1,
    '{"settings":{"color":"red", "fontSize":16, "theme":"dark"}}',
    ('Amy', 12)
  ),
  (
    2,
    '{"settings":{"color":"blue", "fontSize":14, "theme":"light"}}',
    ('Bob', 11)
  );
```

检索每个用户的首选颜色：
```sql
SELECT
  preferences['settings']['color'],
  preferences['settings']:color,
  preferences['settings'].color,
  preferences:settings['color'],
  preferences:settings:color,
  preferences:settings.color
FROM
  user_preferences;
```

结果：
```sql
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ preferences['settings']['color'] │ preferences['settings']:color │ preferences['settings']:color │ preferences:settings['color'] │ preferences:settings:color │ preferences:settings:color │
├──────────────────────────────────┼───────────────────────────────┼───────────────────────────────┼───────────────────────────────┼────────────────────────────┼────────────────────────────┤
│ "red"                            │ "red"                         │ "red"                         │ "red"                         │ "red"                      │ "red"                      │
│ "blue"                           │ "blue"                        │ "blue"                        │ "blue"                        │ "blue"                     │ "blue"                     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

请注意，字段名是 **区分大小写** 的。如果字段名包含空格或特殊字符，请用双引号括起来。

```sql
INSERT INTO
  user_preferences
VALUES
  (
    3,
    '{"new settings":{"color":"red", "fontSize":16, "theme":"dark"}}',
    ('Cole', 13)
  );

-- 双引号字段名 "new settings"
SELECT preferences:"new settings":color 
FROM user_preferences;

┌──────────────────────────────────┐
│ preferences:"new settings":color │
├──────────────────────────────────┤
│ NULL                             │
│ NULL                             │
│ "red"                            │
└──────────────────────────────────┘

-- 当 'c' 在 'color' 中大写时，没有结果返回
SELECT preferences:"new settings":Color 
FROM user_preferences;

┌──────────────────────────────────┐
│ preferences:"new settings":color │
│         Nullable(Variant)        │
├──────────────────────────────────┤
│ NULL                             │
│ NULL                             │
│ NULL                             │
└──────────────────────────────────┘
```

## 数据类型转换

默认情况下，从 VARIANT 列中检索的元素会返回。要将返回的元素转换为特定类型，请添加 `::` 运算符和目标数据类型（例如 expression::type）。

创建一个表来存储用户偏好，使用 VARIANT 列：
```sql
CREATE TABLE user_pref(user_id INT64, pref VARIANT NULL);
```

向表中插入示例数据：
```sql
INSERT INTO user_pref 
VALUES
    (1, parse_json('{"age": 25, "isPremium": "true", "lastActive": "2023-04-10"}')),
    (2, parse_json('{"age": 30, "isPremium": "false", "lastActive": "2023-03-15"}'));
```

将年龄转换为 INT64：
```sql
SELECT user_id, pref:age::INT64 as age FROM user_pref;
```
结果：
```sql
┌─────────┬─────┐
│ user_id │ age │
├─────────┼─────┤
│       1 │  25 │
│       2 │  30 │
└─────────┴─────┘
```

## JSON 函数

请参阅 [Variant 函数](/sql/sql-functions/semi-structured-functions)。