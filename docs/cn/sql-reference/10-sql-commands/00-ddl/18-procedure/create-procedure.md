---
title: CREATE PROCEDURE
---
import FunctionDescription from '@site/src/components/FunctionDescription';

<FunctionDescription description="引入或更新: v1.2.637"/>

定义一个存储过程，用于执行SQL操作并返回结果。

## 语法

```sql
CREATE PROCEDURE <procedure_name>(<parameter_name> <data_type>, ...) 
RETURNS <return_data_type> [NOT NULL]
LANGUAGE <language> 
[ COMMENT '<comment>' ] 
AS $$
BEGIN
    <procedure_body>
    RETURN <return_value>;             -- 用于返回单个值
    -- 或者
    RETURN TABLE(<select_query>);      -- 用于返回表
END;
$$;
```

| 参数                                    | 描述                                                                                                                    |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `<procedure_name>`                      | 过程的名称。                                                                                                            |
| `<parameter_name> <data_type>`          | 输入参数（可选），每个参数都有指定的数据类型。可以定义多个参数，并用逗号分隔。                                          |
| `RETURNS <return_data_type> [NOT NULL]` | 指定返回值的数据类型。`NOT NULL` 确保返回值不能为NULL。                                                                 |
| `LANGUAGE`                              | 指定过程体所使用的语言。目前仅支持 `SQL`。详情请参阅 [SQL脚本](/guides/query/stored-procedure#sql-scripting)。                       |
| `COMMENT`                               | 可选的文本，用于描述过程。                                                                                              |
| `AS ...`                                | 包含过程体，过程体包含SQL语句、变量声明、循环和RETURN语句。                                                             |

## 示例

此示例定义了一个存储过程，用于将重量从千克（kg）转换为磅（lb）：

```sql
CREATE PROCEDURE convert_kg_to_lb(kg DECIMAL(4, 2)) 
RETURNS DECIMAL(10, 2) 
LANGUAGE SQL 
COMMENT = 'Converts kilograms to pounds'
AS $$
BEGIN
    RETURN kg * 2.20462;
END;
$$;
```