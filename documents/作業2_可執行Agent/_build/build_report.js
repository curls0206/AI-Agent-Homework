const fs = require("fs");
const path = require("path");
const DOCX = path.join(__dirname, "..", "..", "作業1_專案規劃文件", "_build", "node_modules", "docx");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell, HeadingLevel, AlignmentType,
  WidthType, ShadingType, BorderStyle, LevelFormat, Footer, PageNumber,
} = require(DOCX);

const ROOT = path.join(__dirname, "..", "..", "..");
const EV = path.join(ROOT, "documents", "作業2_可執行Agent", "evidence");
const EVC = path.join(ROOT, "evidence", "container");
const read = (dir, name) => fs.readFileSync(path.join(dir, name), "utf8").replace(/\r/g, "");

const FONT = { ascii: "Calibri", hAnsi: "Calibri", eastAsia: "Microsoft JhengHei", cs: "Calibri" };
const MONO = { ascii: "Consolas", hAnsi: "Consolas", eastAsia: "Microsoft JhengHei", cs: "Consolas" };
const GRAY = "A6A6A6", HEAD_FILL = "D9E2F3";

const run = (text, o = {}) => new TextRun({ text, font: FONT, ...o });
const runs = (text, base = {}) => text.split(/(`[^`]+`)/).filter(Boolean).map((t) =>
  t.startsWith("`")
    ? new TextRun({ text: t.slice(1, -1), font: MONO, ...base, size: (base.size || 19) - 1 })
    : run(t, base));
const p = (text, o = {}) => new Paragraph({ spacing: { before: 40, after: 70, line: 288 }, ...o, children: runs(text, o.run || {}) });
const h1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 220, after: 80 }, children: [run(t, { bold: true, size: 26, color: "1F3864" })] });
const h2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 120, after: 50 }, children: [run(t, { bold: true, size: 21, color: "2F5597" })] });
const bullet = (t) => new Paragraph({ numbering: { reference: "bul", level: 0 }, spacing: { before: 20, after: 20, line: 276 }, children: runs(t) });
const note = (t) => p(t, { run: { size: 17, color: "595959" } });

const border = { style: BorderStyle.SINGLE, size: 4, color: GRAY };
const borders = { top: border, bottom: border, left: border, right: border };
function cell(text, w, o = {}) {
  const lines = Array.isArray(text) ? text : [text];
  return new TableCell({
    width: { size: w, type: WidthType.DXA }, borders,
    shading: o.fill ? { fill: o.fill, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: lines.map((l) => new Paragraph({ spacing: { before: 0, after: 20, line: 260 },
      alignment: o.center ? AlignmentType.CENTER : AlignmentType.LEFT, children: runs(l, { size: o.size || 18, bold: !!o.bold }) })),
  });
}
function table(widths, header, rows, o = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  const trs = [];
  if (header) trs.push(new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, widths[i], { fill: HEAD_FILL, bold: true, center: true })) }));
  rows.forEach((r) => trs.push(new TableRow({ cantSplit: !o.splitRows,
    children: r.map((c, i) => cell(c, widths[i], { fill: i === 0 && o.firstColFill ? "F2F2F2" : undefined, bold: i === 0 && o.firstColBold })) })));
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths, rows: trs });
}
function codeBox(text) {
  const lines = text.replace(/\n+$/, "").split("\n");
  return new Table({ width: { size: 9638, type: WidthType.DXA }, columnWidths: [9638], rows: [new TableRow({ children: [new TableCell({
    width: { size: 9638, type: WidthType.DXA }, borders,
    shading: { fill: "F7F7F7", type: ShadingType.CLEAR, color: "auto" }, margins: { top: 60, bottom: 60, left: 110, right: 110 },
    children: lines.map((l) => new Paragraph({ spacing: { before: 0, after: 0, line: 240 },
      children: [new TextRun({ text: l === "" ? " " : l, font: MONO, size: 16 })] })) })] })] });
}

// 把 show-trace 的輸出轉成規範用的流程用語
function traceRows(text) {
  const rows = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^\s*(\d+)\s+(Input|Action|Observation|Decision|Result)\s+(.*)$/);
    if (!m) continue;
    let [, n, kind, body] = m;
    if (kind === "Input") kind = "使用者輸入";
    else if (kind === "Decision") kind = "Agent 決策";
    else if (kind === "Observation") kind = "執行結果觀察";
    else if (kind === "Result") kind = "最後結果";
    else if (body.startsWith("Tool Call:")) { kind = "Tool Call"; body = body.replace("Tool Call:", "").trim(); }
    else kind = "Agent 行動";
    rows.push([n, kind, body]);
  }
  return rows;
}
const traceTable = (text) => table([600, 1600, 7438], ["步驟", "階段", "內容"], traceRows(text), { splitRows: true });

const diff = read(EV, "success_cwe79.chosen.diff");
const c = [];

// ---------- 標題 ----------
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 40 }, children: [run("指定作業 2：可執行之 Agent + Tool / ReAct Agent", { bold: true, size: 34, color: "1F3864" })] }));
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 }, children: [run("漏洞修補驗證 Agent（vulnrepair）", { bold: true, size: 26, color: "2F5597" })] }));
c.push(table([1800, 7838], null, [
  ["姓名／學號", "＿＿＿＿＿＿＿＿＿＿　／　＿＿＿＿＿＿＿＿＿＿"],
  ["繳交日期", "2026 年 11 月 22 日"],
  ["GitHub Repository", "（待補）"],
  ["執行環境", "Windows 11、Podman 6.0.2（WSL2 machine）。Agent 容器內是 Fedora 44、Python 3.13、Podman 5.8.9。LLM server 是校內的 Ollama（llama3.3:70b），不在容器內。"],
], { firstColFill: true, firstColBold: true }));

// ---------- 概述 ----------
c.push(h1("概述"));
c.push(p("這份報告是把作業 1 規劃的漏洞修補 Agent 做成可以實際執行的版本。流程是：給 Agent 一個有漏洞的程式，它請 LLM 寫修補，再把修補放進 Podman 容器裡跑檢查，三項檢查都過才採用，沒過就把原因記下來再試。規範 6.2 的最低流程對應如下："));
c.push(codeBox("使用者輸入（scenario.json：漏洞類型、描述、程式碼位置）\n        ↓\n      Agent（orchestrator：控制輪數、時間、決策）\n        ↓\nLLM（定位、產生修補）／Agent Logic（預審、記錄失敗、決定停止）／Tool（Podman 驗證）\n        ↓\n執行輸出（repair-result.json、trace.jsonl、chosen.diff）"));
c.push(h2("架構的選擇"));
c.push(p("規範 6.1 說不一定要用 ReAct，但要說明。我的 Agent 是類似 ReAct 的迴圈：每一輪先決定要做什麼，呼叫工具，看工具的結果，再決定下一步，直到修補通過或預算用完。差別在於「決策」我是用固定規則寫的，沒有交給 LLM。像什麼時候停、要不要採用某個修補，我希望每次的結果可以重現，也方便事後檢查，所以這部分不讓模型決定。LLM 只負責需要看懂程式碼的兩件事：找出問題在哪裡，以及寫修補。"));
c.push(p("規範 6.2 提到需要的話要加入 State／Memory。重試時 Agent 必須知道上一輪為什麼失敗，所以我留了一個只在單次任務內有效的失敗記憶，記錄每個被拒絕的修補、拒絕的原因和攻擊檢查的輸出，下一輪的提示詞會帶進去。這份記憶不會跨任務保存。"));

// ---------- 1 ----------
c.push(h1("1. Agent 原始碼"));
c.push(p("原始碼放在 GitHub：（待補）。Agent 的程式在 `src/vulnrepair/`，測試在 `tests/`，建置與執行的步驟寫在 `README.md`。"));

// ---------- 2 ----------
c.push(h1("2. Tool 定義"));
c.push(p("Agent 用到五個工具，下面照規範列出名稱、目的、輸入、輸出和 Error Handling。"));
const tool = (name, purpose, input, output, errors) => [
  table([1700, 7938], null, [
    ["Tool 名稱", name], ["目的", purpose], ["輸入", input], ["輸出", output], ["Error Handling", errors],
  ], { firstColFill: true, firstColBold: true }),
  new Paragraph({ spacing: { after: 80 }, children: [] }),
];
c.push(...tool(
  "Podman 容器執行器（PodmanCommandRunner.run，runners.py）",
  "在一次性的 Podman 容器裡執行一條指令。所有不可信的程式碼（目標專案的 build、測試、LLM 寫的修補）都只透過它執行。",
  "CommandSpec（名稱、指令 argv、逾時秒數、工作目錄）和一個工作目錄。映像必須是 sha256 映像 ID 或 digest，不接受 latest 這類可變的 tag。",
  "CommandResult：結果（pass、fail、timeout、infra_error）、return code、stdout、stderr、執行時間、reason_code。",
  ["指令格式不合法（用 shell 字串、含換行、工作目錄跑到外面）：回傳 infra_error，reason_code 為 invalid_command。", "逾時：回傳 timeout，並強制移除容器。", "容器層的錯誤碼 125、126、127、137、143：歸為 infra_error，不當成修補失敗。", "輸出超過上限（預設 1 MiB）：截斷並標記。", "清理容器失敗：另外記錄。"]));
c.push(...tool(
  "差異化驗證（Oracle.baseline、Oracle.validate，oracle.py）",
  "先在原始程式上建立 baseline，再對每個候選修補比對修補前後的結果，判斷它有沒有修好又沒有破壞原功能。",
  "漏洞任務、驗證計畫（build 指令、功能檢查指令、攻擊檢查 PoC、harness 的 SHA-256）、候選修補、baseline。",
  "baseline 結果，以及每個候選的 verdict：verified_fix、rejected、inconclusive、infra_error，附上每個階段的證據。",
  ["baseline 的 build 或功能檢查沒過，或攻擊重現不了：標為 baseline 不可用，不再驗證候選。", "harness 的 SHA-256 對不上、PoC 輸出格式錯誤：infra_error。", "缺少針對這個漏洞的證據：最多只能是 inconclusive。", "沒有修補前後的完整證據，不會給 verified_fix。"]));
c.push(...tool(
  "修補預審（PolicyCritic.critique，adapters.py、patches.py）",
  "在進容器之前先擋掉格式不對或改太多的修補，只看 diff 本身，不判斷有沒有修好。",
  "候選修補的 diff 和任務編號。",
  "pass 或 reject，reject 時附 reason_code。",
  ["空 diff、不是 UTF-8、二進位、超過大小上限（256 KB、20 個檔案、1000 行）、改檔名或複製、改權限、symlink、submodule、任務編號不符：reject，並記錄在 trace。"]));
c.push(...tool(
  "LLM 產生修補（Ollama 客戶端，models.py、ollama_client.py）",
  "請 LLM 針對有問題的那段程式寫修補，再轉成合法的 diff。",
  "漏洞任務、程式碼位置、失敗記憶、候選數量上限、成本上限。",
  "候選修補清單（記錄是哪個模型產生的）。",
  ["連線失敗、逾時、回傳格式不對：只記錄為 provider_errors，不會讓整個流程中斷。", "整輪因為 LLM 出錯而沒有候選：如果輪數還沒用完就重試。", "超過模型呼叫次數或成本的預算：丟棄這批候選。"]));
c.push(...tool(
  "定位（Localizer.localize，adapters.py、ollama_localizer.py）",
  "找出程式裡有問題的位置。可以由 scenario 直接提供，也可以讓 LLM 讀程式碼推論。",
  "漏洞任務，第二輪起可以附上一輪的攻擊檢查輸出。",
  "程式碼位置清單（檔案、函式、起訖行、信心、理由）。",
  ["沒有位置就沒有候選，該輪結束。位置依信心和行號排序，結果固定。"]));

// ---------- 3 ----------
c.push(h1("3. Agent 執行追蹤"));
c.push(p("我用 XSS 範例（cwe79，`render_name` 把輸入直接放進 HTML）跑一次，LLM 是 llama3.3:70b，驗證在 Podman 容器裡。結果是第 1 輪失敗、第 2 輪成功，共 2 輪、2 次 LLM 呼叫，約 36 秒。下表是 `show-trace` 的輸出，階段名稱換成規範的用語。"));
c.push(traceTable(read(EV, "success_cwe79.trace.txt")));
c.push(p("對照規範的流程：步驟 1 是使用者輸入；步驟 2 到 15 是 Agent 決策、Tool Call、執行結果觀察一再重複；步驟 17 是最後結果。", { spacing: { before: 80, after: 40 } }));
c.push(p("第一輪是步驟 6 到 10。LLM 寫的修補在 f-string 裡又用了一次雙引號，容器裡的 Python 3.11 不接受，所以 build 階段就失敗，後面的功能檢查和攻擊檢查都沒有跑（步驟 10）。Agent 把這次失敗記下來。第二輪是步驟 11 到 15，失敗原因被放進提示詞，LLM 這次改用標準函式庫的 `html.escape`，build、功能檢查都通過，攻擊也從成功變成被擋下，Agent 就採用這個修補（步驟 16）。"));
c.push(p("被採用的修補：", { spacing: { before: 60, after: 20 } }));
c.push(codeBox(diff));

// ---------- 4 ----------
c.push(h1("4. 失敗情境"));
c.push(p("規範要求至少兩個，我整理了六個。前三個是我故意製造的，用 `scripts/collect_failure_evidence.py` 可以重現。後三個是用真實 LLM 跑的時候自己遇到的。六個情境最後都沒有誤把失敗當成功，追蹤檔放在 `documents/作業2_可執行Agent/evidence/`。"));
c.push(table([1500, 2900, 2600, 2638], ["情境", "失敗狀況", "原因", "解決方法"], [
  ["1. LLM 伺服器連不上", "每一輪都顯示 LLM 呼叫失敗（ConnectionError），沒有候選。重試到輪數用完就結束，chosen 是空的。", "SSH 通道沒開，或 `--ollama-host` 的位址不對。", "重新建立通道並確認位址。Agent 遇到這種情況只會結束並記錄，不會中斷，也不會當成成功。"],
  ["2. 容器映像不存在", "baseline 階段就失敗（podman_run_error，infra_error），流程在還沒開始修補前結束。", "`--image` 指到本機沒有的映像。沙箱設定了 `--pull=never`，不會自動下載。", "重新 `podman build`，用 `podman image inspect` 查正確的映像 ID。容器版的入口腳本會自動建沙箱映像，可以避開這個問題。"],
  ["3. 檢查指令逾時", "baseline 的 build 階段 timeout，流程結束。`podman ps -a` 看不到殘留的容器。", "build 指令超過 timeout_seconds。我用 `sleep 60` 模擬卡住的建置。", "調高該指令的逾時，或修掉卡住的建置。逾時時 Agent 會強制移除容器，所以不會拖住主機。"],
  ["4. LLM 寫出語法錯誤的修補", "第 3 節第一輪，build 階段失敗（nonzero_exit），錯誤是 `SyntaxError: f-string: unmatched '('`，修補被判 rejected。", "模型在 f-string 裡又用了雙引號，Python 3.11 不允許。", "Agent 把失敗原因放進失敗記憶，下一輪重新生成。第二輪改用 `html.escape` 就通過了。"],
  ["5. 驗證通過，但修補可以被繞過", "路徑穿越範例（cwe22）第一次跑得到 verified_fix，採用的修補是 `filename.lstrip(\"./\")`。但 `sub/../../secret.txt` 這種路徑還是讀得到機密檔，它還把參數名稱 `name` 改成 `filename`。", "我寫的 PoC 只測了 `../secret.txt` 和絕對路徑，沒有測「先進子目錄再往上跳」。驗證只能證明修補擋得住 PoC 涵蓋的攻擊。", "我補上這個攻擊，並在功能檢查加入合法的子目錄讀取。同一個修補重新驗證後變成 rejected（patched_exploit_persists）。補強後重跑 4 輪都沒有修補通過，Agent 不採用任何候選。所以 verified_fix 不能當成漏洞已經完全消除。"],
  ["6. 工具的輸出格式限制", "命令注入範例（cwe78）每次 LLM 呼叫都出現 `no valid changes found in JSON`，4 輪都沒有候選。", "我把模型的原始輸出攔下來看，它的修法是對的（改用 list 參數、拿掉 `shell=True`）。但工具要求 `old_stripped` 對應原始碼的一行，漏洞程式的 `subprocess.run(...)` 橫跨三行，模型把它寫成一行，所以比對不到。", "目前還沒解決，我沒有改範例去迴避。可能的做法是讓比對支援多行的敘述，或解析失敗時改用完整 diff 的生成方式，留到作業 3 評估。"],
], { splitRows: true }));

// ---------- 5 ----------
c.push(h1("5. 測試資料與測試結果"));
c.push(p("測試資料是四個我自己寫的漏洞範例：XSS（cwe79）、路徑穿越（cwe22）、SQL injection（cwe89）、命令注入（cwe78）。它們不是真實的 CVE。每個範例有含漏洞的程式、功能檢查和攻擊檢查（PoC），用 `fixture` 指令產生，程式碼在 `src/vulnrepair/course_fixtures.py`。"));
c.push(p("我用 llama3.3:70b 在 Podman 驗證下各跑一次，位置提示模式。每個範例只跑一次，結果有成有敗，不能當成成功率。", { spacing: { before: 60, after: 40 } }));
c.push(table([1700, 1500, 800, 1200, 4438], ["範例", "結果", "輪數", "耗時", "過程"], [
  ["cwe79 XSS", "verified_fix", "2", "36.5 秒", "第 1 輪 build 失敗，第 2 輪改用 html.escape 通過"],
  ["cwe89 SQL injection", "verified_fix", "1", "27.9 秒", "第 1 輪就改成參數化查詢並通過"],
  ["cwe22 路徑穿越", "沒有修補", "4", "132.7 秒", "build 失敗、功能檢查失敗、build 失敗、攻擊仍成功，預算內沒有通過的修補"],
  ["cwe78 命令注入", "沒有修補", "4", "92.7 秒", "4 輪都沒有候選，原因是失敗情境 6"],
], { firstColBold: true }));
c.push(p("自動化測試共 159 項，全部通過（另有 2 項因平台條件而跳過）。其中和這次作業直接相關的有：6 項 Podman 隔離測試（非 root、唯讀、無網路、資源上限、輸出上限、逾時清除容器、完整驗證流程）、漏洞範例測試（正確修補通過，空修補被拒絕）、3 項失敗情境測試、2 項 `show-trace` 測試、2 項重試測試。", { spacing: { before: 80, after: 40 } }));

// ---------- 6 ----------
c.push(h1("6. 執行環境與重現方式"));
c.push(p("課程要求 Agent 要能用 Podman 在不同平台重現執行，所以我把 Agent 本身也包成 Podman 映像（根目錄的 `Containerfile`）。映像裡自帶 Podman，驗證用的沙箱容器由它在容器裡再啟動。LLM server 在容器外。完整步驟在 `README.md`，主要指令如下。"));
c.push(codeBox("podman build --network=host -t vulnrepair-agent -f Containerfile .\npodman volume create vulnrepair-store\npodman run --rm --privileged --network=host -v vulnrepair-store:/var/lib/containers \\\n    -v \"${PWD}\\out:/out\" vulnrepair-agent demo       # 離線 demo，不需要 LLM\npodman run ... vulnrepair-agent solve cwe79 --generator ollama-replacement \\\n    --ollama-host http://<Ollama 位址>:11434 --ollama-model llama3.3:70b\npodman run ... vulnrepair-agent test                   # 在容器內跑全部測試"));
c.push(p("我在容器裡實際跑過這三個指令。`demo` 的 4 個候選都由容器內的沙箱驗證，選出通過的那個。`test` 跑了 159 項，全部通過。`solve cwe79` 用真實的 llama3.3:70b，第 1 輪就通過，約 14 秒，追蹤如下：", { spacing: { before: 60, after: 40 } }));
c.push(traceTable(read(EVC, "solve_cwe79.trace.txt")));
c.push(p("沙箱的資源限制在容器裡一開始沒有生效，因為官方 Podman 映像預設把 cgroup 關掉。我在入口腳本裡開啟並委派給子容器，之後用測試確認 pids 和記憶體的上限都有作用。如果無法委派，Agent 會直接報錯，不會在沒有限制的情況下跑。", { spacing: { before: 80, after: 40 } }));
c.push(note("限制：我只在 Windows 11（amd64）上測過。映像的基底都固定為多平台的版本（含 arm64），所以 Linux 和 macOS 應該也可以，但我沒有實測。在 Windows 上，容器要連到主機的 Ollama，必須用 WSL 看到的主機位址（我這台是 172.29.192.1），並讓 SSH 通道綁在這個位址，細節寫在 README。"));

// ---------- 7 ----------
c.push(h1("7. 功能完整性"));
c.push(p("對照作業 1 的功能需求，目前的狀態如下。"));
c.push(table([900, 5338, 3400], ["編號", "需求（摘要）", "狀態"], [
  ["FR-01", "讀入並嚴格檢查 scenario JSON", "完成，有未知欄位的拒絕測試"],
  ["FR-02", "在固定的快照上建立 baseline，確認漏洞可以重現", "完成"],
  ["FR-03", "定位可疑程式碼", "完成。靜態位置已用在實驗，LLM 定位已實作，但還沒做實驗"],
  ["FR-04", "呼叫 LLM 產生候選修補", "完成。只用單一模型，多模型池已支援但沒用在實驗"],
  ["FR-05", "候選修補的預審", "完成"],
  ["FR-06", "在 Podman 容器裡執行 build、功能檢查、攻擊檢查並比對 baseline", "完成"],
  ["FR-07", "依結果決策，記錄失敗並回饋到下一輪", "完成"],
  ["FR-08", "輸出 repair-result、trace、chosen.diff", "完成"],
  ["FR-09", "命令列與唯讀 Dashboard", "完成，Dashboard 沿用原本的實作和測試"],
], { firstColBold: true }));
c.push(p("還沒做好的地方：LLM 的輸出有隨機性，同一個範例重跑可能需要不同的輪數，作業 3 會用多個案例和重複執行來量測。目前重試只是把失敗記錄原樣帶給 LLM，作業 3 打算評估讓 LLM 先分析失敗原因再重寫是否更有效。", { spacing: { before: 80, after: 40 } }));

const doc = new Document({
  creator: "vulnrepair", title: "指定作業 2：可執行之 Agent + Tool / ReAct Agent",
  styles: {
    default: { document: { run: { font: FONT, size: 19 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 26, bold: true }, paragraph: { spacing: { before: 220, after: 80 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { font: FONT, size: 21, bold: true }, paragraph: { spacing: { before: 120, after: 50 }, outlineLevel: 1 } },
    ],
  },
  numbering: { config: [{ reference: "bul", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 420, hanging: 260 } } } }] }] },
  sections: [{
    properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [
      run("指定作業 2　｜　第 ", { size: 16, color: "7F7F7F" }),
      new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 16, color: "7F7F7F" }), run(" 頁", { size: 16, color: "7F7F7F" })] })] }) },
    children: c,
  }],
});
const out = path.join(__dirname, "..", "作業2_可執行Agent報告_漏洞修補驗證Agent.docx");
Packer.toBuffer(doc).then((b) => { fs.writeFileSync(out, b); console.log("wrote", out); });
