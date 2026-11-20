# Scenario Honesty Rules

> **核心原則**：「記住不要有作弊偷吃步的行為」
> **誠實原則**：「修復的結果不要因為失敗就作弊，失敗就失敗」

---

## 雙模式實驗策略

本研究採用**固定順序的雙模式策略**：每個 CVE 都先以零提示模式執行，若失敗才切換至定位輔助模式。兩次結果均需記錄並在報告中明確區分。

```
┌──────────────────────────────────────────┐
│  Step 1：零提示模式（End-to-End）         │
│  locations: []，--localizer ollama        │
│  → 成功：記錄為「端對端成功」，停止       │
│  → 失敗：記錄 run ID，進入 Step 2        │
└──────────────────────┬───────────────────┘
                       │ 失敗
                       ▼
┌──────────────────────────────────────────┐
│  Step 2：定位輔助模式                     │
│  locations: [精確位置]，SEARCH 預填       │
│  → 成功：記錄為「定位輔助成功」           │
│  → 失敗：如實記錄，不再調整               │
└──────────────────────────────────────────┘
```

**為什麼這樣設計：**
- 零提示模式反映系統在最嚴格條件下的真實能力（定位 + 修復）
- 定位輔助模式反映業界常見條件下的修復能力（只修復）
- 兩組資料合在一起，能分析 Localizer 的失敗模式，以及修復生成的成功條件
- 不跳過零提示模式直接做定位輔助，避免隱藏定位失敗的事實

---

## 兩種實驗條件

本框架支援兩種明確定義的實驗條件，兩者都不是作弊，但**必須在報告中明確區分**：

### 條件 A：零提示模式（End-to-End，最嚴格）

```json
{
  "locations": [],
  "candidates": []
}
```

- `--localizer ollama`：LLM 自行從整個 codebase 搜尋漏洞位置
- LLM 需同時完成定位（Localization）與修復（Fix Generation）兩項任務
- 失敗即失敗，不調整任何參數
- 對應先前執行的失敗批次（urllib3、aiohttp、pydantic-ai、deepdiff 均在此條件下失敗）

### 條件 B：定位輔助模式（Localization-Assisted）

```json
{
  "locations": [
    {
      "file_path": "...",
      "function_name": "...",
      "start_line": N,
      "end_line": M
    }
  ],
  "candidates": []
}
```

- Static Localizer：直接從 JSON 讀取位置，跳過 LLM 定位步驟
- LLM 拿到：CVE ID + CWE + description + locations[] + 原始碼
- LLM 仍須自行推理**如何修復**，不提供任何修復方向提示
- 與業界多數已發表論文的條件相當（通常提供 function-level 或 line-level 位置）

**兩種模式的資訊差異：**

| 資訊 | 零提示 | 定位輔助 |
|---|---|---|
| CVE ID | ✓ | ✓ |
| CWE 分類 | ✓ | ✓ |
| description（公開 CVE 描述） | ✓ | ✓ |
| 原始碼 | ✓ | ✓ |
| locations[]（file/function/line） | ✗ | ✓ |

---

## 什麼是「作弊」（嚴格禁止）

**真正的作弊是提供修復方向**，而非提供位置資訊：

| 禁止的內容 | 原因 |
|---|---|
| `candidates` 陣列填入已知正確 patch | 直接給答案 |
| `task.description` 提及修復版本或 commit | 洩漏答案出處 |
| `task.description` 說「應該加什麼驗證」 | 告訴 LLM 怎麼修 |
| `locations[*].rationale` 說出正確修法 | 告訴 LLM 怎麼修 |
| SEARCH 預填使用官方 patch 後的新程式碼 | 洩漏修復內容 |
| 在 prompt 中附上修復 commit 的 diff | 直接給答案 |

### `task.description` 禁止出現

- 修復版本或 commit，例如："Fixed in 3.1.4"、"fix commit abc123"
- 修復技術，例如："by expanding the regex to `[\s/>=]`"、"by adding ASCII range check"
- 應該怎麼做的暗示，例如："should validate"、"should sanitize"、"should reject"

### `locations[*].rationale` 禁止出現

- 正確修法是什麼
- 應使用哪種修法（allowlist、regex、sanitize function）
- 修復函式的用途分歧（暗示搬移的目標位置）

---

## 什麼不是作弊

| 允許的內容 | 原因 |
|---|---|
| `locations` 填入 file_path、function_name、start_line、end_line | 只告訴 LLM「看哪裡」，不說「改成什麼」 |
| SEARCH 預填：從實際原始碼提取漏洞行 | 只展示「現在長什麼樣」，等同 LLM 讀原始碼 |
| `locations[*].rationale` 說明攻擊路徑與不足 | 描述攻擊者視角，不說防禦方案 |
| `task.description` 說「某類輸入沒被阻擋」 | 現象描述，非解法 |

> **判斷原則**：用攻擊者視角描述（攻擊者做 X → 造成 Y），不用防禦者視角（程式應該拒絕/驗證/過濾 X）。

---

## 誠實標準範例

**`task.description` 正確格式（jinja2-real 標準）：**

```
Jinja2 versions before 3.1.4 are vulnerable to Cross-Site Scripting (CVE-2024-34064)
via the xmlattr filter. The filter is responsible for rendering a dictionary as HTML
attributes; it validates attribute key names to prevent injection, but the validation
logic is incomplete — certain characters that are illegal in HTML attribute names are
not rejected. An attacker who controls attribute key values can inject malformed
attributes or escape the enclosing HTML tag context, resulting in XSS.
```

**`locations[*].rationale` 正確格式（aiohttp 實際範例）：**

```
The parse_headers method in HeadersParser does not reject non-ASCII bytes in HTTP
header values. The validation at line 230 only checks for \n, \r, and \x00 but
allows byte sequences such as 0xC2 0x85 that downstream proxies may interpret as
line terminators.
```

注意：說「只檢查了 X，沒有檢查 Y」是允許的（描述不足）；說「應該也檢查 Z」是禁止的（給出修法）。

---

## 自我檢查清單

在完成 scenario JSON 之前逐條確認：

**實驗條件標示**
- [ ] 是否已在報告中明確標示這是「零提示模式」或「定位輔助模式」？
- [ ] 兩種條件的結果是否分開呈現，未混淆比較？

**描述提示（兩種模式均適用）**
- [ ] `task.description` 有無 "fixed", "fix", "should", "correct", "added check" 相關字眼？
- [ ] `task.description` 有無提到修復版本或 commit？
- [ ] `task.description` 有無提到修復的具體技術或函式？
- [ ] 每個 `locations[*].rationale` 有無說出「正確修法是什麼」？
- [ ] 每個 `locations[*].rationale` 有無暗示「用哪個函式/正規式/演算法」？

**測試設計**
- [ ] `tests/test_regression_*.py` 在漏洞版本上是否全部 PASS？（不測安全行為）
- [ ] `harness/poc.py` 是否覆蓋了所有 vulnerable location 的修法路徑？

---


> **SEARCH 預填說明**：定位輔助模式中，`ollama-replacement` generator 會將漏洞位置的現有程式碼預填入 SEARCH 區塊（展示「現在長什麼樣」）。LLM 仍須自行推理 REPLACE（改成什麼），屬於 WHERE 級別輔助，不構成作弊。
