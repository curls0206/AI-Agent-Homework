# 漏洞修補驗證 Agent（vulnrepair）

給定一筆漏洞（CVE/CWE + 受影響原始碼），Agent 自動定位問題程式碼、由 LLM 產生候選修補，
並在 **Podman 隔離容器**中執行 build / regression / PoC 差異化驗證。只有「證實修補成功且沒有
破壞既有功能」的候選才會被選用；否則誠實回報 `rejected` / `inconclusive` / `infra_error`，
`chosen` 保持為空，不做未經驗證的宣稱。

```text
VulnTask ─► Localizer ─► Generator pool (LLM) ─► Critic/policy ─► Verification Oracle ─► RepairResult
                                                                    │  (Podman 沙箱內執行)
                                                         baseline vs patched 差異證據
```

## 容器架構

**Agent 本體與驗證沙箱都跑在 Podman 上**，只有 LLM server（Ollama）在容器外（規範例外）：

```text
你的電腦 ── Podman engine ──► [ Agent 容器 vulnrepair-agent ]   ← 根目錄 Containerfile
                                  │  Agent 程式（Python）
                                  └─► 容器內的 Podman（巢狀）──► [ 驗證沙箱 ]   ← sandbox/Containerfile
                                                                  無網路、非 root、唯讀、無 capability、
                                                                  pids / 記憶體 / CPU 上限
LLM server（Ollama）：容器外，透過 --ollama-host 連線
```

為什麼用巢狀 Podman：Agent 容器自帶一個 Podman engine，驗證沙箱由它在容器內啟動，因此整個流程只依賴
「主機能執行 privileged Podman 容器」這一件事，不受主機路徑、Python 版本或作業系統差異影響。

## 1. 系統需求

| 項目 | 需求 |
| --- | --- |
| Podman | 已驗證 6.0.2（Windows 11 + WSL2 podman machine，amd64）；Linux 可直接使用 |
| 其他軟體 | **不需要**主機安裝 Python 或 Git（都在映像裡，Python 3.13） |
| 權限 | Agent 容器需 `--privileged`（用來在容器內啟動巢狀 Podman 並委派 cgroup） |
| 網路 | 第一次建置映像需連網（下載基底映像與套件）；LLM 需連得到 Ollama |
| 記憶體 | 建議 WSL／虛擬機可用記憶體 ≥ 4 GiB（`podman machine list` 顯示的 2GiB 對 WSL 後端只是設定值，實際由 WSL 決定） |

跨平台狀態：基底映像固定為多平台索引 digest（amd64／arm64／ppc64le／s390x），沙箱基底映像同為多平台。
**實際驗證只做過 Windows 11 + amd64**；Linux 與 macOS（Apple Silicon）預期可行但尚未實測。

## 2. 安裝 Podman

Windows：

1. 安裝 Podman Desktop 與 Podman 引擎（擇一）：圖形介面首次啟動依 onboarding 按 **Install Podman**；
   或 `winget install RedHat.Podman`。
2. 建立並啟動 podman machine（需要 WSL2）：

   ```powershell
   podman machine init
   podman machine start
   ```

3. 重新開啟終端機，確認 `podman --version` 與 `podman machine list`（狀態應為 Currently running）。

Linux 直接用套件管理員安裝 `podman`；macOS 用 `brew install podman` 後 `podman machine init && podman machine start`。

> **已知限制（WSL 核心）**：podman machine 預設橋接網路可能出現 `netavark ... nftables error`。
> 因此本 README 的建置與執行都加 `--network=host`。一般 Linux 不受影響。

## 3. 快速開始：用 Podman 重現 Agent 的執行

以下指令在專案根目錄執行（PowerShell；Linux／macOS 把 `${PWD}\out` 改成 `"$PWD/out"`）。

### 3.1 建置 Agent 映像

```powershell
podman build --network=host -t vulnrepair-agent -f Containerfile .
podman volume create vulnrepair-store
```

`vulnrepair-store` 保存容器內 Podman 的映像儲存區（沙箱映像只在第一次執行時建置，之後重複使用）。

### 3.2 執行內建離線 demo（不需要 LLM）

```powershell
New-Item -ItemType Directory -Force out | Out-Null
podman run --rm --privileged --network=host `
  -v vulnrepair-store:/var/lib/containers -v "${PWD}\out:/out" `
  vulnrepair-agent demo
```

demo 建立含 CWE-79（XSS）漏洞的暫時 Git 倉庫，提交 4 個候選修補，全部在容器內的沙箱驗證。
結果寫入主機的 `out/<run_id>/`。

### 3.3 讓 LLM 修補一個漏洞範例

```powershell
podman run --rm --privileged --network=host `
  -v vulnrepair-store:/var/lib/containers -v "${PWD}\out:/out" `
  vulnrepair-agent solve cwe79 `
    --generator ollama-replacement `
    --ollama-host http://<Ollama位址>:11434 --ollama-model llama3.3:70b
```

`solve <範例>` 會依序：建立漏洞範例（`cwe79`／`cwe22`／`cwe89`／`cwe78`）→ 讓 Agent 修補 → 印出
Decision／Action／Observation 追蹤。額外參數會原樣傳給 `repair`（例如 `--max-rounds 4`）。
設定環境變數 `VULNREPAIR_MODE=zero`（`-e VULNREPAIR_MODE=zero`）可改成不提供位置提示。

**LLM 位址**：容器用 `--network=host`，所以在 Linux 上若 Ollama 在本機，位址就是 `http://127.0.0.1:11434`。
在 Windows／macOS，容器跑在 podman machine 虛擬機內，**`127.0.0.1` 指的是虛擬機而不是你的電腦**，
需要使用「虛擬機看到的主機位址」。以 Windows + WSL2 為例：

1. 查位址：`podman machine ssh "ip route show default"`，`via` 後面的 IP 就是主機位址（本機實測為 `172.29.192.1`，重開機或 `wsl --shutdown` 後可能改變）。
2. 若 Ollama 經 SSH 通道提供，通道要綁在這個位址（而不是預設的 127.0.0.1），例如：
   `ssh <使用者>@<伺服器> -L 172.29.192.1:11440:127.0.0.1:11434 -N`（只對 WSL 開放，不是整個區網）。
3. 指令使用 `--ollama-host http://172.29.192.1:11440`。

已實測（Windows 11 + WSL2 podman machine）：從 Agent 容器內經上述通道連到校內 Ollama，由 llama3.3:70b 完成
`solve cwe79`——第 1 輪產生 `html.escape` 修補，經容器內的 Podman 沙箱驗證為 `verified_fix`，約 14 秒
（證據：`evidence/container/solve_cwe79.*`）。注意：模型閒置後第一次請求要重新載入，70B 模型約需 2 分鐘，
`--ollama-timeout-seconds`（預設 300）與 `--max-elapsed-seconds` 要留足夠時間。

### 3.4 在容器內執行全部測試

```powershell
podman run --rm --privileged --network=host -v vulnrepair-store:/var/lib/containers vulnrepair-agent test
```

涵蓋單元測試與巢狀 Podman 的隔離測試（非 root、唯讀根目錄、無網路、cgroup 資源限制、輸出上限、
timeout 後容器清除、完整 Oracle 流程），預期 `Ran 159 tests ... OK (skipped=2)`。

### 3.5 重現三個失敗情境

```powershell
podman run --rm --privileged --network=host `
  -v vulnrepair-store:/var/lib/containers -v "${PWD}\out:/out" `
  vulnrepair-agent evidence
```

三個情境：LLM server 連不上、容器映像不存在（`infra_error`）、驗證指令逾時（容器被清除）。每個情境的
追蹤與 `repair-result.json` 寫入 `out/evidence/`；對應的自動化測試是 `tests/test_failure_cases.py`。

### 3.6 參數說明

| 參數 | 為什麼需要 |
| --- | --- |
| `--privileged` | 讓容器內的 Podman 能建立沙箱容器並把 cpu／memory／pids 控制權委派給它；缺少時入口腳本會直接報錯結束（fail-closed，不會在沒有資源限制下執行） |
| `--network=host` | 繞過 WSL 虛擬機的橋接網路問題，並讓容器能連到 LLM server；沙箱本身一律 `--network none` |
| `-v vulnrepair-store:/var/lib/containers` | 保存容器內 Podman 的映像，避免每次重建沙箱映像 |
| `-v <主機>\out:/out` | 把結果帶回主機 |

### 3.7 檢視結果

```powershell
podman run --rm --privileged --network=host -v vulnrepair-store:/var/lib/containers -v "${PWD}\out:/out" `
  vulnrepair-agent show-trace /out/<run_id>      # Decision / Action / Observation 追蹤
```

`out/<run_id>/` 含 `repair-result.json`（完整結果）、`trace.jsonl`（決策事件）、`chosen.diff`（被選用的修補）。

## 4. 套件相依性

`vulnrepair` 執行期只使用 Python 標準函式庫，**沒有第三方執行期套件**；映像內的系統套件只有
`python3.13` 與 `git-core`（由 `Containerfile` 安裝）。`requirements.txt` 列出相依性說明與開發品質檢查工具
（`build`、`mypy`、`ruff`），執行 Agent 不需要安裝它們。

## 5. 環境變數

| 名稱 | 用途 | 是否必要 |
| --- | --- | --- |
| `VULNREPAIR_SANDBOX_IMAGE` | 沙箱映像 ID（`sha256:...`），可取代 `--image`；入口腳本會自動設定，使用者不必手動設定 | 否 |
| `VULNREPAIR_MODE` | 容器版 `solve`：`located`（預設）或 `zero` | 否 |
| `VULNREPAIR_OUT` | 容器內結果輸出目錄（預設 `/out`） | 否 |

LLM 相關設定以 CLI 參數傳入：`--ollama-host`、`--ollama-model`、`--ollama-api-key`（API 金鑰不會寫入 trace 或結果檔）。

## 6. 預期輸出

### 6.1 demo 摘要（stdout）

```json
{"artifact_dir": "/out/<run_id>", "candidates": 4, "chosen": "a7f3219f...", "run_id": "<run_id>", "task_id": "demo-cwe-79", "validations": 4}
```

### 6.2 四個候選的預期 verdict

| 候選 | 預期 verdict | 原因 |
| --- | --- | --- |
| HTML escape 修補 | `verified_fix` | PoC 由 `vulnerable` 轉為 `blocked`，build 與 regression 通過 |
| 只做 `strip()` | `rejected` | PoC 仍可利用（`candidate.poc` 失敗） |
| 改輸出標籤為 `<div>` | `rejected` | regression 失敗（`candidate.test.0`） |
| 舊內容不吻合的 diff | `rejected` | patch 無法套用（`candidate.patch.build`） |

### 6.3 `solve` 追蹤範例（LLM 連不上時，Agent 不會假裝成功）

```text
1  Input        使用者提供漏洞任務 course-cwe79
2  Action       Tool Call: Oracle.baseline → Podman 容器執行 build / regression / PoC
3  Observation  baseline 可用：baseline vulnerability evidence established
4  Action       Localizer 定位可疑程式碼
5  Observation  取得 1 個位置
6  Observation  LLM 呼叫失敗（1 次）：llama3.3:70b sample 1: ConnectionError: Ollama ... unreachable
7  Decision     本輪沒有新候選（輪數用盡前會重試）
...
10 Result       chosen=無（未取得 verified_fix）
```

## 7. 除錯建議

| 症狀 | 原因與處理 |
| --- | --- |
| `ERROR: cgroup v2 is not writable. Run the container with --privileged.` | 少了 `--privileged`，或主機 cgroup 不是 v2；Agent 為避免在沒有資源限制下執行而拒絕啟動 |
| `netavark ... nftables error` | 預設橋接網路在 WSL 核心不可用；`podman build`／`podman run` 加 `--network=host` |
| 第一次執行很久 | 正在容器內建置沙箱映像並下載基底映像；之後會存在 `vulnrepair-store` 磁碟區 |
| `LLM 呼叫失敗 ... unreachable` | 容器連不到 Ollama；Windows／macOS 的 `127.0.0.1` 是虛擬機自己，見 3.3 |
| Git Bash 執行 `-v ...:/out` 出現奇怪路徑 | Git Bash 會改寫以 `/` 開頭的路徑；改用 PowerShell，或設定 `MSYS_NO_PATHCONV=1` |
| `podman: command not found`（Windows） | 重新開啟終端機；Podman 預設位於 `%LOCALAPPDATA%\Programs\Podman`，需在 PATH 中 |
| 容器被 OOM 終止（`container_resource_termination`） | WSL 虛擬機記憶體不足；`podman machine ssh free -m` 查看，必要時在 `%USERPROFILE%\.wslconfig` 設 `[wsl2] memory=8GB`，`wsl --shutdown` 後重啟 podman machine |
| 驗證結果為 `infra_error` | runner、harness、timeout 或容器啟動失敗；**不會**被視為修復成功，請檢查 `trace.jsonl` |
| 容器內映像儲存區異常 | 沙箱容器隨 Agent 容器結束而消失；若 `vulnrepair-store` 磁碟區損壞，執行 `podman volume rm vulnrepair-store` 後重建，下次執行會自動重建沙箱映像 |

## 8. 專案結構

```text
README.md                 本文件
requirements.txt          相依性說明（執行期無第三方套件）與開發工具
Containerfile             Agent 映像（含巢狀 Podman）
container/entrypoint.sh   Agent 容器入口：cgroup 委派、建置沙箱映像、demo／solve／test
sandbox/Containerfile     驗證沙箱映像（build／regression／PoC 在其中執行）
pyproject.toml            套件設定
src/vulnrepair/           Agent 原始碼（orchestrator、localizer、generator、oracle、runners、trace_view、course_fixtures ...）
scripts/                  證據蒐集腳本（失敗情境，在 Agent 容器內以 `evidence` 執行）
tests/                    單元測試與 Podman 整合測試
documents/                各次作業的證據檔與文件建置腳本（Word 報告另行繳交，不在此 repository）
evidence/container/       容器內執行的證據（demo、solve、測試摘要）
docs_src_ref/             原框架設計文件（架構、scenario 格式）
```

## 授權

MIT License，見 [LICENSE](LICENSE)。
