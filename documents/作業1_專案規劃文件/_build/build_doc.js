const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, ImageRun,
  HeadingLevel, AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat,
  Footer, PageNumber, TabStopType,
} = require("docx");

const FONT = { ascii: "Calibri", hAnsi: "Calibri", eastAsia: "Microsoft JhengHei", cs: "Calibri" };
const CONTENT_W = 9638; // A4 (11906) - 2 * 1134 margin
const GRAY = "A6A6A6";
const HEAD_FILL = "D9E2F3";

const run = (text, o = {}) => new TextRun({ text, font: FONT, ...o });

// inline **bold** support
function runs(text, base = {}) {
  return text.split(/(\*\*[^*]+\*\*)/).filter(Boolean).map((t) =>
    t.startsWith("**") ? run(t.slice(2, -2), { ...base, bold: true }) : run(t, base));
}
const p = (text, o = {}) => new Paragraph({
  spacing: { before: 40, after: 60, line: 276 },
  ...o,
  children: runs(text, o.run || {}),
});
const h1 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_1, spacing: { before: 200, after: 80 },
  children: [run(text, { bold: true, size: 26, color: "1F3864" })],
});
const h2 = (text) => new Paragraph({
  heading: HeadingLevel.HEADING_2, spacing: { before: 100, after: 40 },
  children: [run(text, { bold: true, size: 21, color: "2F5597" })],
});
const bullet = (text) => new Paragraph({
  numbering: { reference: "bul", level: 0 }, spacing: { before: 20, after: 20, line: 270 },
  children: runs(text),
});

const border = { style: BorderStyle.SINGLE, size: 4, color: GRAY };
const borders = { top: border, bottom: border, left: border, right: border };

function cell(text, w, o = {}) {
  const lines = Array.isArray(text) ? text : [text];
  return new TableCell({
    width: { size: w, type: WidthType.DXA }, borders,
    shading: o.fill ? { fill: o.fill, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: lines.map((l) => new Paragraph({
      spacing: { before: 0, after: 20, line: 252 },
      alignment: o.center ? AlignmentType.CENTER : AlignmentType.LEFT,
      children: runs(l, { size: 18, bold: !!o.bold }),
    })),
  });
}
function table(widths, header, rows, o = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const trs = [];
  if (header) trs.push(new TableRow({ tableHeader: true,
    children: header.map((h, i) => cell(h, widths[i], { fill: HEAD_FILL, bold: true, center: true })) }));
  rows.forEach((r) => trs.push(new TableRow({ cantSplit: true,
    children: r.map((c, i) => cell(c, widths[i], { fill: i === 0 && o.firstColFill ? "F2F2F2" : undefined,
      bold: i === 0 && o.firstColBold })) })));
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths, rows: trs });
}
const gap = () => new Paragraph({ spacing: { before: 0, after: 40 }, children: [] });

const img = fs.readFileSync(path.join(__dirname, "..", "figures", "architecture.png"));
const IMG_W = 600, IMG_H = Math.round(600 * 5.9 / 10 * 0.99); // aspect fixed below

const children = [];

// ---------- title ----------
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 40 },
  children: [run("AI Agent 專案規劃文件", { bold: true, size: 40, color: "1F3864" })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 120 },
  children: [run("漏洞修補驗證 Agent（vulnrepair）", { bold: true, size: 28, color: "2F5597" })] }));
children.push(table([1800, 7838], null, [
  ["課程／作業", "AI Agent 課程　指定作業 1：Agent 專案規劃"],
  ["姓名／學號", "＿＿＿＿＿＿＿＿＿＿　／　＿＿＿＿＿＿＿＿＿＿"],
  ["繳交日期", "2026 年 10 月 18 日"],
  ["GitHub Repository", "（待補：作業 2 前建立獨立 repository 並分享給老師與助教）"],
], { firstColFill: true, firstColBold: true }));

// ---------- 1 ----------
children.push(h1("1. 專案概述"));
children.push(table([1800, 7838], null, [
  ["專案名稱", "漏洞修補驗證 Agent（vulnrepair，Multi-Agent Vulnerability Repair）"],
  ["專案目的", "給定一筆已知漏洞（CVE／CWE 描述＋含漏洞的原始碼），Agent 自動定位問題程式碼、由 LLM 產生候選修補，並在 **Podman 隔離容器**中以 build、regression 與 PoC 做差異化驗證；只輸出「有驗證證據支撐」的修補，否則誠實回報失敗類型。"],
  ["專案背景", "LLM 能產生看似合理的修補，但「看起來正確」不等於「真的堵住漏洞且不破壞功能」。本專案源自作者在資安研究中發展的 generate-and-verify 框架，現況已具備 orchestrator、驗證 Oracle、Podman 沙箱 runner 與 147 項自動化測試。本課程將其整理為一個可執行、可測試、可評估的 AI Agent 系統，並逐次完成可執行化、功能強化與期末整合。"],
], { firstColFill: true, firstColBold: true }));

// ---------- 2 ----------
children.push(h1("2. 問題描述"));
children.push(h2("2.1 要解決什麼問題？"));
children.push(p("修補一個漏洞包含三件事：**定位**（問題在哪）、**撰寫修補**、**驗證修補**。LLM 可以降低前兩項的成本，但自動產生的修補常出現三種「合理卻錯誤」的結果：(a) 漏洞仍可被利用；(b) 破壞既有功能（regression）；(c) diff 本身無法套用。人工逐一驗證最耗時，也最容易被省略。"));
children.push(h2("2.2 為什麼值得解決？"));
children.push(bullet("未經驗證的自動修補比沒有修補更危險：它給使用者「已修好」的錯覺。"));
children.push(bullet("驗證必須執行**不受信任的程式碼**（目標專案的 build script、測試與 LLM 產生的 patch），若直接在主機上跑，驗證本身就成為攻擊面，因此必須容器隔離。"));
children.push(bullet("本專案的核心價值是把「驗證」做成 Agent 的 Tool，並讓驗證結果成為 Agent 下一步決策的依據，而不是只讓 LLM 一次輸出就結束。"));

// ---------- 3 ----------
children.push(h1("3. 專案的目標族群（Target Users）"));
children.push(table([1700, 3469, 4469], ["使用者", "誰會使用", "主要需求"], [
  ["主要", "資安工程師、DevSecOps 團隊", "接到 CVE 或掃描報告後，快速得到可審查、且有驗證證據的修補 diff"],
  ["次要", "開源專案維護者", "對外部回報的漏洞，能先用 Agent 產生並驗證候選修補，再人工審查"],
  ["次要", "資安研究者", "以統一的 Agent 與驗證流程比較不同模型／策略的修補能力"],
], { firstColBold: true }));
children.push(p("共同需求：(1) 縮短從漏洞報告到可審查修補的時間；(2) 修補必須附可稽核的驗證證據；(3) 驗證環境必須隔離，不危害主機；(4) 可在本機或內部環境使用，未公開漏洞資訊不外送（LLM 使用本地 Ollama）。", { spacing: { before: 60, after: 40 } }));

// ---------- 4 ----------
children.push(h1("4. 使用情境（User Scenario）"));
children.push(p("**情境**：資安工程師收到報告，內部 Python 模組 `app.py` 的 `render_name()` 將使用者輸入直接嵌入 HTML 回應（CWE-79 XSS）。"));
children.push(bullet("**輸入**：scenario JSON（CWE、漏洞描述、目標 Git 倉庫與基準 commit、驗證計畫、預算）。"));
children.push(bullet("**執行**：`python -m vulnrepair repair scenario.json --runner podman --image <映像ID>`。"));
children.push(bullet("**Agent 流程**：在容器內建立 baseline（確認 build／既有測試健康、PoC 能重現漏洞）→ Localizer 定位 → Generator 呼叫 LLM 產生候選 → Critic 做 diff 政策檢查 → Oracle 對每個候選在全新 snapshot 的 Podman 容器內跑 build／regression／PoC → 依 verdict 決定停止或進入下一輪。"));
children.push(bullet("**輸出**：`chosen.diff`（若有 verified_fix）、`repair-result.json`、`trace.jsonl`；工程師審查 diff 後合併。"));
children.push(p("以下為內建 CWE-79 demo 在 Podman 中的**實際執行結果**（4 個候選全數經容器驗證）：", { spacing: { before: 80, after: 40 } }));
children.push(table([3300, 1500, 4838], ["候選修補", "Verdict", "原因（取自 Oracle stage 證據）"], [
  ["輸出前做 HTML escape", "verified_fix", "PoC 由 vulnerable 轉為 blocked；build 與 regression 通過"],
  ["只做 strip()", "rejected", "PoC 階段失敗：漏洞仍可被利用"],
  ["把輸出標籤改為 <div>", "rejected", "regression 階段失敗：破壞既有輸出契約"],
  ["舊內容不吻合的 diff", "rejected", "patch.build 階段失敗：diff 無法套用"],
]));

// ---------- 5 ----------
children.push(h1("5. 專案目標"));
children.push(bullet("**G1 可執行**：輸入 scenario，輸出經驗證的修補 diff，或誠實的失敗分類。"));
children.push(bullet("**G2 驗證可信（fail-closed）**：沒有完整差異證據就不選用修補；目標是 Oracle 誤判（verified_fix 但實際錯誤）為 0。"));
children.push(bullet("**G3 安全沙箱**：所有 build／test／PoC 一律在 Podman 容器中執行。"));
children.push(bullet("**G4 可評估**：以 10～20 個測試案例量測成功率、輪數、LLM 呼叫次數與延遲。"));
children.push(bullet("**G5 可改進且有證據**：作業 3 以 Before／After 實驗證明一項 Agent 功能強化的效果。"));

// ---------- 6 ----------
children.push(h1("6. 功能需求（Functional Requirements, FR）"));
children.push(table([900, 8738], ["編號", "需求"], [
  ["FR-01", "Agent 需接受 scenario JSON（CVE／CWE、描述、repo、驗證計畫、預算），嚴格驗證格式並拒絕未知欄位。"],
  ["FR-02", "Agent 需在固定的 Git snapshot（不觸碰 working tree）上建立 baseline，確認 build／測試健康且漏洞可被 PoC 重現。"],
  ["FR-03", "Agent 需定位可疑程式碼（scenario 提供位置，或由 LLM Localizer 閱讀原始碼推論）。"],
  ["FR-04", "Agent 需呼叫 LLM（Ollama／Codex）以多模型候選池產生候選修補 diff。"],
  ["FR-05", "Agent 需對候選先做確定性 policy 檢查（禁止修改驗證資產、檔案數／行數限制等）再送驗證。"],
  ["FR-06", "Agent 需呼叫 Podman Runner 在容器中執行 build、regression、PoC／scanner，並比對 baseline 與 patched 的證據。"],
  ["FR-07", "Agent 需依 verdict（verified_fix／rejected／inconclusive／infra_error）決策：記錄失敗記憶，並於下一輪以失敗回饋重新定位與生成，直到成功或預算用盡。"],
  ["FR-08", "Agent 需輸出 repair-result.json、trace.jsonl、chosen.diff；沒有 verified_fix 時 chosen 必須為空。"],
  ["FR-09", "使用者需能以 CLI 執行，並以本機唯讀 Dashboard 檢視候選、驗證證據、成本與 trace。"],
], { firstColBold: true }));

// ---------- 7 ----------
children.push(h1("7. 非功能性需求（Non-Functional Requirements）"));
children.push(table([1700, 7938], ["面向", "需求"], [
  ["反應時間", "容器內單次驗證為秒～數十秒等級（含完整 Oracle 流程的整合測試約 15 秒）；整體延遲由 LLM 主導（70B 模型單次呼叫可達 1～2 分鐘），因此以 wall-time 預算（預設 2400 秒）、回合數、候選數與模型呼叫數上限控制。"],
  ["可靠度", "Fail-closed：timeout、crash、缺工具、格式錯誤一律是 infra_error，不會被當成修復成功；結果以原子方式發布，不留下半成品。"],
  ["安全性", "容器 non-root、`--network none`、唯讀根目錄、`--cap-drop ALL`、`no-new-privileges`、pids／記憶體／CPU 上限；trusted harness 以 SHA-256 綁定並唯讀掛載；LLM 輸出一律視為不受信任的候選。"],
  ["營運部署", "全部以 Podman 容器驗證；Containerfile 以 digest 釘死基底映像；README 提供安裝、建置、執行、測試步驟，助教可依文件重現。"],
  ["可用性", "CLI 加本機唯讀 Dashboard（預設僅綁 127.0.0.1）；每個失敗都有 reason_code，便於除錯。"],
  ["可稽核性", "每次 run 有 run_id、input_fingerprint 與完整 trace，可重放決策過程。"],
], { firstColBold: true }));

// ---------- 8 ----------
children.push(h1("8. Agent 執行需求"));
children.push(table([1700, 7938], null, [
  ["Agent 目的", "在預算內，針對一筆漏洞產生並驗證修補，輸出有證據支撐的 verified_fix；否則回報 rejected／inconclusive／infra_error。"],
  ["輸入", "scenario JSON：CVE／CWE、漏洞描述、目標 repo 與 base commit、（可選）位置提示、驗證計畫（build／test／PoC 指令與 trusted harness）、預算。"],
  ["輸出", "repair-result.json（完整結果與各 stage 證據）、trace.jsonl（決策事件）、chosen.diff（被選用的修補）、成本摘要。"],
  ["運作環境", "Python 3.11+ 的 asyncio orchestrator 在主機執行；所有 build／test／PoC 在 Podman 容器執行；LLM server（Ollama）在容器外。"],
  ["使用外部工具（Tools）", "Podman Runner（容器內執行指令）、Git snapshot／`git apply`、Patch policy 檢查、PoC／scanner harness、LLM（Ollama／Codex CLI）。"],
  ["記憶體（Memory）", "任務內失敗記憶：記錄每個被拒絕候選的 verdict、原因與 PoC 輸出，下一輪提供給 Localizer／Generator 以避免重複同樣的錯誤；不跨任務、不持久化。"],
  ["專業領域知識", "CWE／CVE 漏洞類型與常見修補模式、Git diff／patch 語意、以 PoC 差異（vulnerable → blocked）驗證修補的方法。"],
], { firstColFill: true, firstColBold: true }));

// ---------- 9 ----------
children.push(h1("9. 預期 Agent 架構"));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 20 },
  children: [new ImageRun({ type: "png", data: img, transformation: { width: 600, height: 358 },
    altText: { title: "Agent 架構圖", description: "vulnrepair 系統架構", name: "architecture" } })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 0, after: 80 },
  children: [run("圖 1　系統架構：Agent 核心（容器外）與 Podman 隔離驗證環境", { size: 18, color: "595959" })] }));
children.push(table([1800, 7838], ["元件", "職責"], [
  ["Orchestrator", "控制回合、預算（輪數／候選／驗證／模型呼叫／時間）、候選去重與排序、寫入稽核 trace；唯一決定何時停止。"],
  ["Localizer", "定位可疑程式碼：靜態（scenario 提供）或 LLM 閱讀原始碼推論；後續回合可根據 PoC 輸出重新定位。"],
  ["Generator pool", "多個模型（可跨 provider）各自產生候選 diff；彼此獨立，輸出僅視為候選材料。"],
  ["Critic（PatchPolicy）", "確定性檢查：diff 格式、禁止修改驗證資產、變更範圍限制；不對「是否修好」下語意判斷。"],
  ["Verification Oracle", "建立 baseline，將候選套用到兩份全新 snapshot（build／regression 與 security 證據分離），比對差異並輸出 typed verdict。"],
  ["Podman Runner", "唯一執行不受信任程式碼的 Tool；每條指令一個一次性、強化過的容器。"],
  ["Memory", "任務內失敗記憶，供下一輪生成避免重蹈覆轍。"],
], { firstColBold: true }));
children.push(p("**Agent 工作流（ReAct 式迴圈）**：**Thought**（依失敗記憶與上一輪 PoC 輸出，決定要重新定位哪裡）→ **Action**（Generator 呼叫 LLM 產生候選；Oracle 呼叫 Podman Runner 驗證）→ **Observation**（verdict 與差異證據）→ 回到 Thought。停止條件：出現 verified_fix，或任一預算用盡（此時 chosen 為空，並保留完整稽核資料）。", { spacing: { before: 80, after: 40 } }));

// ---------- 10 ----------
children.push(h1("10. 技術選用"));
children.push(table([1500, 1000, 7138], ["技術", "是否使用", "選用理由"], [
  ["LLM", "是", "Ollama 上的 llama3.3:70b（學校 GPU 伺服器，經 SSH tunnel 存取），備援 Codex CLI。修補生成需要程式碼推理能力；使用本地模型避免未公開漏洞資訊外送。"],
  ["Framework", "否（自建）", "自建 asyncio orchestrator 與 Protocol 介面（localizer、generator、critic、memory、runner 皆可替換），不使用 LangChain 等通用框架：本專案需要確定性的預算控管、可稽核 trace 與 fail-closed 決策，隱含迴圈的框架難以保證；也使執行期維持零第三方依賴。"],
  ["Tool", "是", "Podman Runner（build／test／PoC／scanner）、Git snapshot 與 patch 套用、PoC／scanner harness。驗證結果是 Agent 決策的依據，Tool 是系統核心。"],
  ["ReAct", "是", "失敗回饋驅動的多輪迴圈：PoC 輸出回饋給 Localizer 重新定位，失敗記憶回饋給 Generator，直到成功或預算用盡。"],
  ["Memory", "是", "任務內失敗記憶（verdict、原因、PoC 輸出）。避免重複已被拒絕的修補；不跨任務，因為跨任務記憶的價值尚未驗證。"],
  ["RAG", "否", "漏洞上下文直接來自目標原始碼（依位置擷取函式與行號），範圍小且確定，不需要向量知識庫。若作業 3／4 的實驗顯示跨任務修補範例檢索有明顯收益，再重新評估。"],
  ["Self-Reflection", "否（現況）", "目前 Critic 為確定性規則，LLM 不會批判自己的修補。這是作業 3 的候選強化項目：讓 LLM 先根據 Oracle 證據寫出失敗根因，再據以重新生成，並以實驗比較。"],
  ["Multi-Agent", "是", "以角色分工（Localizer、Generator、Critic、Oracle）加上多模型候選池實現，各元件透過介面協作；多模型提高候選多樣性。"],
  ["Guardrails", "是", "PatchPolicy、harness SHA-256 綁定、預算上限、容器隔離與 fail-closed verdict，防止 LLM 輸出直接造成危害或被誤判為成功。"],
  ["Podman", "是", "規範要求（除 LLM server 外必須使用 Podman）。無 daemon、可 rootless，適合執行不受信任程式碼。"],
], { firstColBold: true }));
children.push(p("**Podman 落實狀況（已完成，2026/10/12）**：實作 `PodmanCommandRunner` 並設為 CLI 預設；以 `Containerfile` 建置沙箱映像；6 項 Podman 隔離整合測試（非 root、唯讀根目錄、無網路、cgroup 資源限制、輸出上限、timeout 後容器清除、完整 Oracle 流程）與全部 147 項測試通過（Podman 6.0.2，Windows／WSL2）。Docker 僅保留相容選項，不用於交付。**LLM server 例外**：Ollama 與 Codex CLI 屬 LLM server，不在容器內，符合規範例外。已知限制：WSL 上預設橋接網路會出現 nftables 錯誤，但沙箱一律 `--network none` 不受影響，`podman build` 需加 `--network=none`。", { spacing: { before: 80, after: 40 } }));

// ---------- 11 ----------
children.push(h1("11. 專案開發規劃"));
children.push(table([1500, 1100, 4638, 2400], ["階段", "日期", "內容", "交付"], [
  ["作業 1", "10/18", "規劃文件；README／requirements；完成 Podman 遷移與隔離測試（10/12 已完成）", "本文件、README、Containerfile、測試"],
  ["作業 2", "11/22", "以 `repair` 加 Ollama 跑真實 scenario，保存完整 Thought→Action→Observation trace；撰寫 Tool 定義；實測至少 2 個失敗情境（rejected／inconclusive／infra_error 擇二）；補強錯誤處理測試", "可執行 Agent、Tool 定義、執行追蹤、失敗情境"],
  ["作業 3", "12/6", "選一項強化（首選 LLM Self-Reflection，備選跨任務 Memory）；建立 ≥10 案測試集；同預算、同模型做 Before／After 實驗", "更新程式碼、測試集、實驗報告（2～3 頁）"],
  ["作業 4", "12/27", "整合前三次成果；規劃文件更新為正式版；技術報告 8～15 頁；10～20 案自評；依 README 從零重現驗證", "規劃文件、技術報告、可執行系統、自評報告"],
], { firstColBold: true }));

// ---------- 12 ----------
children.push(h1("12. 專案評估規劃"));
children.push(p("**測試集**：作業 3 至少 10 案、期末 10～20 案，由內建 CWE-79 fixture、自建小型 fixture 與研究倉庫既有 scenario 組成，涵蓋不同 CWE、可修與刻意不可修的案例，並加入故障注入（容器映像不存在、timeout）測試 Tool 失敗時的行為。每案以表格記錄：Test ID、輸入、預期輸出、實際輸出、結果。"));
children.push(table([2600, 7038], ["指標", "定義／目標"], [
  ["成功率", "verified_fix 的案例比例（相同模型與預算下比較 Before／After）"],
  ["Oracle 誤判率", "verified_fix 但人工審查判定錯誤的比例；目標為 0（fail-closed 的核心承諾）"],
  ["平均輪數與 LLM Calls", "成功案例所需回合數與模型呼叫次數"],
  ["延遲", "端到端 wall time，以及容器驗證與 LLM 推理各自占比"],
  ["Tool 成功率", "未發生 infra_error 的驗證比例；失敗須有明確 reason_code"],
  ["失敗分布", "rejected／inconclusive／infra_error 的比例，用於分析失敗原因"],
], { firstColBold: true }));
children.push(p("**公平性**：定位提示只允許「哪裡有問題」（檔案、函式、缺少何種檢查），不得包含具體修法（程式碼構造、參數、數值）；並區分「零提示」（僅給 CVE 描述）與「定位輔助」兩種模式分別報告。另以既有 147 項單元測試與 6 項 Podman 整合測試作為回歸防線。", { spacing: { before: 80, after: 40 } }));

// ---------- 13 ----------
children.push(h1("13. 風險與限制（Risks and Limitations）"));
children.push(table([2300, 3869, 3469], ["風險／限制", "說明", "緩解"], [
  ["LLM 品質不穩", "本地 70B 模型可能多輪仍無法產生有效修補，結果有隨機性", "預算上限；誠實回報 inconclusive；多模型池；每案重複執行"],
  ["LLM 延遲高", "單次呼叫可達 1～2 分鐘，完整實驗耗時長", "wall-time 預算；控制測試集規模；背景執行"],
  ["驗證覆蓋有限", "Oracle 只能證明「在給定 PoC 與既有 regression 下有效」，不保證漏洞類別完全消除；缺少 PoC 時最多為 inconclusive", "要求 trusted harness；文件明確揭露此限制"],
  ["測試案例成本", "每個案例都需要人工撰寫 PoC／harness，成本高", "自建小型 fixture；沿用研究倉庫既有案例"],
  ["Podman on Windows", "WSL 預設橋接網路有 nftables 錯誤；machine 預設記憶體僅 2 GiB", "沙箱 `--network none`；build 加 `--network=none`；調高記憶體；README 除錯章節"],
  ["評估偏誤", "研究程式碼中部分 Generator prompt 含針對特定案例的調整，若用於通用評估會高估成功率", "作業 3 前審查並隔離或在報告中揭露，不納入「通用能力」宣稱"],
  ["範圍與時程", "單人開發、四次作業間隔緊湊", "優先完成最小可行流程；低優先功能（Dashboard 強化等）延後"],
], { firstColBold: true }));

const doc = new Document({
  creator: "vulnrepair",
  title: "AI Agent 專案規劃文件 - 漏洞修補驗證 Agent",
  styles: {
    default: { document: { run: { font: FONT, size: 19 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 26, bold: true }, paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: 21, bold: true }, paragraph: { spacing: { before: 100, after: 40 }, outlineLevel: 1 } },
    ],
  },
  numbering: { config: [{ reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•",
    alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 420, hanging: 260 } } } }] }] },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 },
      margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [run("AI Agent 專案規劃文件　｜　第 ", { size: 16, color: "7F7F7F" }),
        new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: "7F7F7F" }),
        run(" 頁", { size: 16, color: "7F7F7F" })] })] }) },
    children,
  }],
});

const out = path.join(__dirname, "..", "作業1_專案規劃文件_漏洞修補驗證Agent.docx");
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(out, buf); console.log("wrote", out); });
