import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib import font_manager as fm

fm.fontManager.addfont(r"C:\Windows\Fonts\msjh.ttc")
plt.rcParams["font.family"] = "Microsoft JhengHei"

fig, ax = plt.subplots(figsize=(10, 5.9), dpi=200)
ax.set_xlim(0, 100); ax.set_ylim(0, 57); ax.axis("off")

def box(x, y, w, h, text, fc="#EAF1FB", ec="#2F5597", fs=8.8, bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.2,rounding_size=0.8",
                                fc=fc, ec=ec, lw=1.3, ls=ls))
    ax.text(x + w/2, y + h/2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", linespacing=1.4)

def arrow(p1, p2, color="#333333", style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=11, lw=1.3,
                                 color=color, ls=ls, shrinkA=0, shrinkB=0))

# container region
ax.add_patch(FancyBboxPatch((62, 13.5), 37, 18, boxstyle="round,pad=0.2,rounding_size=1.0",
                            fc="#FFF4E5", ec="#C55A11", lw=1.6))
ax.text(63.5, 29.3, "Podman 隔離容器（--network none）", fontsize=8.8, fontweight="bold", color="#C55A11")

# row 1 : agent pipeline
box(2, 36, 18, 10, "使用者輸入\nScenario JSON\n(CVE/CWE + 原始碼)", fc="#E2F0D9", ec="#548235")
box(25, 36, 18, 10, "Localizer\n定位漏洞程式碼\n(靜態 / LLM)")
box(48, 36, 18, 10, "Generator pool\n多模型候選修補", fc="#DDEBF7")
box(71, 36, 18, 10, "Critic\nPatchPolicy\n(確定性檢查)")
box(48, 50, 18, 5.5, "LLM server（容器外）\nOllama llama3.3:70b", fc="#EDEDED", ec="#595959", fs=8.2, ls=(0, (4, 2)))

# row 2
box(2, 17, 22, 12, "Memory\n任務內失敗記憶\n(verdict + PoC 輸出)", fc="#F2E7F7", ec="#7030A0")
box(30, 17, 26, 12, "Verification Oracle\nbaseline vs patched\n差異化驗證", fc="#FFF2CC", ec="#BF9000", bold=True)
box(64.5, 21, 32, 6.5, "Podman Runner（Tool）\n非 root / 唯讀 / 無網路", fc="#DDEBF7", fs=8.2)
box(64.5, 15.5, 15, 4.5, "build / regression", fc="#FBE5D6", ec="#C55A11", fs=8)
box(82, 15.5, 14.5, 4.5, "PoC（/harness 唯讀）", fc="#FBE5D6", ec="#C55A11", fs=8)

# row 3
box(2, 2, 56, 7, "Orchestrator：回合 / 預算 / 候選排序 / 稽核 trace（協調以上所有元件）", fc="#F2F2F2", ec="#7F7F7F", fs=8.8)
box(66, 1.5, 33, 8, "輸出 RepairResult\nchosen.diff / trace.jsonl\n（無證據則 chosen = None）", fc="#E2F0D9", ec="#548235", fs=8.2)

# flow arrows
arrow((20, 41), (25, 41)); arrow((43, 41), (48, 41)); arrow((66, 41), (71, 41))
arrow((57, 46), (57, 50), color="#595959", style="<|-|>", ls=":")
arrow((76, 36), (54, 29))
arrow((56, 25), (62, 25), color="#C55A11"); arrow((62, 19.5), (56, 19.5), color="#C55A11", ls="--")
arrow((30, 23), (24, 23), color="#7030A0")
arrow((8, 29), (28, 36), color="#7030A0", ls="--")
arrow((18, 29), (52, 36), color="#7030A0", ls="--")
arrow((56, 17), (68, 9.2), color="#548235")

ax.text(59, 26.2, "Act", fontsize=7.8, color="#C55A11", ha="center")
ax.text(59, 17.6, "Obs.", fontsize=7.8, color="#C55A11", ha="center")
ax.text(2.5, 31.6, "失敗回饋", fontsize=8, color="#7030A0", ha="left")
ax.text(67.5, 47.6, "prompt / 候選 diff", fontsize=7.8, color="#595959")

fig.savefig("figures/architecture.png", bbox_inches="tight", facecolor="white")
