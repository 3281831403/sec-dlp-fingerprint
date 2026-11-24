外发检测加了文档指纹，换个段落顺序或改两个字就全部漏过去：归一化不删除标点，攻击者插入任意标点即可绕过指纹匹配；归一化不折叠空白，换行和连续空格会让滚动分块边界错位；分块按固定边界切分而不滚动，插入一个字符后后续分块全部错位；文本短于块长时直接返回原文，造成短文档误报；分块哈希不使用密钥盐，攻击者可用字典反查原文；指纹集合不去重，长文档中重复内容会稀释相似度；相似度按交集除以并集计算，短文档命中被系统性低估；阈值比较使用严格大于，相似度恰好等于阈值时漏报；策略校验不检查块长下限，过小的块长引入大量噪声命中；批量检测复用指纹库游标，第二个文档沿用第一个文档的命中集合。实现 dlp/fingerprint.py 中的八个函数并修复这十个缺陷，tests/test_fingerprint.py 不得修改，运行 python -m pytest tests -q 初始应看到十五个失败且全部为 NotImplementedError，修复后应全部通过。dlp/fingerprint.py 是核心，tests/test_fingerprint.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 题目字段

| 字段 | 值 |
| --- | --- |
| 方向 | 安全 / 漏洞检测与攻防 |
| 类型 | Bugfix |
| 技术栈 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态必须是 `15 failed`，并且 15 个失败全部由 `NotImplementedError` 引起。完成 `src/dlp/fingerprint.py` 的八个函数后，同一命令应得到 `15 passed`。测试覆盖：十个缺陷各一条，另外五条覆盖完全相同文档、段落乱序、少量改字、无关文档，以及批量检测与重复检测的一致性。

`tests/test_fingerprint.py` 是评测契约，不得修改、删除、跳过或弱化任何测试。允许修改的文件只有 `src/dlp/fingerprint.py`，需要把其中的八个桩全部实现；`src/dlp/__init__.py` 只负责包标记，不承载实现。

## 目录与导入布局

```text
sec-dlp-fingerprint/
├── README.md
├── pyproject.toml
├── src/
│   └── dlp/
│       ├── __init__.py
│       └── fingerprint.py
└── tests/
    └── test_fingerprint.py
```

`pyproject.toml` 中的 `[tool.pytest.ini_options]` 设置了 `pythonpath = ["src"]`，pytest 会直接把 `src` 加入导入路径，所以测试使用 `from dlp.fingerprint import ...`，无需安装包，也不依赖 editable install。项目采用 `src` 布局，实现代码只能放在 `src/dlp/fingerprint.py`。

## 接口契约

所有文本按 Unicode 字符处理，中文和英文一视同仁。

| 接口 | 约定 |
| --- | --- |
| `normalize(text)` | 统一转小写；删除 Unicode 标点；把任意连续空白折叠成一个空格并去掉首尾空白。标点直接删除，不替换为空格。 |
| `shingles(text, size)` | 返回全部长度为 `size` 的连续字符分块，按起始位置排列；`len(text) < size` 时返回空列表。 |
| `hash_shingle(shingle, key)` | 返回确定性的整数哈希；同一分块与同一密钥结果相同，换密钥结果不同，不能退化为无密钥哈希。 |
| `fingerprint(text, key, size)` | 先归一化，再滚动分块，再带密钥哈希，最后返回去重的集合。 |
| `similarity(a, b)` | 交集大小除以较小集合大小；任一集合为空时返回 `0.0`。 |
| `match(doc, library, threshold)` | `doc` 是文档指纹集合，`library` 是名称到指纹集合的映射；返回相似度大于或等于阈值的名称列表，按名称排序。 |
| `validate_policy(policy)` | 返回问题代码列表，顺序固定为 `threshold_too_low`、`shingle_size_too_small`、`missing_key`；阈值低于 `0.5`、块长小于 `3`、密钥缺失或为空都会报问题。 |
| `dlp_batch(docs, library, policy)` | `docs` 是文档名到原始文本的映射，`library` 是预计算指纹库，`policy` 含 `threshold`、`shingle_size`、`key`；逐篇独立检测，返回文档名到排序命中列表的映射，无命中返回空列表。 |

策略示例：

```python
{
    "threshold": 0.8,
    "shingle_size": 5,
    "key": "deployment-secret",
}
```

初始的八个函数都是桩，函数体只有 `raise NotImplementedError`。不要添加外部依赖；标准库足以完成全部实现。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

