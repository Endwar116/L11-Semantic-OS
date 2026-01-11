# SIC-JS L11 Package Guide
## 宇宙級清晰說明文件 - 不可能誤解版

**版本：** 1.0  
**日期：** 2026-01-11  
**協議：** SIC-JS v1.4  
**目標受眾：** 任何 AI（Claude, GPT, Gemini）或人類  
**保證：** 看完這份文件，你會 100% 知道 L11 是什麼、怎麼用、怎麼協助

---

## 🎯 這份文件的目的

**如果你是 AI：**
- 你會知道如何理解 L11 系統
- 你會知道如何協助開發/測試/文件
- 你會知道如何與其他 AI 協作

**如果你是人類：**
- 你會知道 L11 在做什麼
- 你會知道如何部署和使用
- 你會知道如何請 AI 幫忙

---

## 📋 目錄

1. [L11 是什麼？（3 分鐘理解）](#section-1)
2. [L11 的核心組件（5 個關鍵部分）](#section-2)
3. [如何使用 L11（部署指南）](#section-3)
4. [如何協助 L11（AI 協作指南）](#section-4)
5. [SIC-JS 協議範例（標準格式）](#section-5)
6. [常見問題（FAQ）](#section-6)
7. [快速指令表（複製貼上即用）](#section-7)

---

<a name="section-1"></a>
## 1. L11 是什麼？（3 分鐘理解）

### 1.1 一句話解釋
> **L11 Semantic OS 是一個「AI 路由器」，根據問題複雜度決定要用便宜的單一模型還是昂貴的多模型團隊來回答。**

### 1.2 類比說明

**情境：你是一家公司的總機**

- **簡單問題**（「廁所在哪？」）→ 總機直接回答（便宜、快速）
- **複雜問題**（「設計 3 年 AI 策略」）→ 總機召集專家團隊（昂貴、高品質）

**L11 就是那個總機。**

### 1.3 技術定義

```yaml
名稱: L11 Semantic OS
定位: Layer -1 (Pre-Intent Layer)
功能:
  - 提取使用者意圖
  - 計算問題複雜度（intent_density）
  - 路由到適當的模型（單一 or 多模型）
  - 合成統一回應

實作: n8n workflow (可視化流程圖)
模型: GPT-4o, GPT-4o-mini, Claude 3.5 Sonnet
```

### 1.4 為什麼需要 L11？

**問題：**
- 現在的 AI 系統：每個問題都用同一個昂貴模型（浪費錢）
- 或者：每個問題都用便宜模型（品質差）

**L11 的解決方案：**
- 簡單問題 → 便宜模型（省錢）
- 複雜問題 → 多模型團隊（高品質）
- **自動判斷，無需人工干預**

**結果：**
- 成本節省 50-90%
- 品質提升（多模型比單一模型好）

---

<a name="section-2"></a>
## 2. L11 的核心組件（5 個關鍵部分）

### 2.1 組件清單

```
┌─────────────────────────────────────────┐
│ 1. User Input (Webhook)                 │  ← 使用者輸入
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ 2. L11 Kernel (Intent Extraction)       │  ← 意圖提取
│    模型: GPT-4o-mini                     │
│    輸出: Intent Tree (JSON)             │
└─────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────┐
│ 3. Gravity Gate (Density Check)         │  ← 複雜度判斷
│    閾值: intent_density > 0.8           │
└─────────────────────────────────────────┘
       ↙          ↘
  Low Density    High Density
       ↓              ↓
┌──────────────┐  ┌─────────────────────────┐
│ 4a. Standard │  │ 4b. Multi-Model Council │
│    Response  │  │  - GPT (Structure)      │
│    (Fast)    │  │  - Claude (Narrative)   │
│              │  │  - Gemini (Info)        │
└──────────────┘  └─────────────────────────┘
       ↓              ↓
       │         ┌─────────────────────────┐
       │         │ 5. Convergence Engine   │
       │         │    (Synthesis)          │
       │         └─────────────────────────┘
       ↓              ↓
┌─────────────────────────────────────────┐
│ 6. Deliver to User (Webhook Response)   │
└─────────────────────────────────────────┘
```

### 2.2 組件詳細說明

#### 組件 1: User Input (Webhook)
```yaml
功能: 接收使用者輸入
類型: n8n webhook 節點
輸入格式:
  {
    "message": "使用者的問題"
  }
輸出: 傳遞給 L11 Kernel
```

#### 組件 2: L11 Kernel (Intent Extraction)
```yaml
功能: 分析使用者意圖，不直接回答
模型: GPT-4o-mini
System Prompt: "你是 L11 Pre-Intent Processor，分析輸入並輸出 JSON Intent Tree"
輸出格式:
  {
    "intent_density": 0.0-1.0,      # 問題複雜度
    "explicit_vector": "明確意圖",
    "implicit_vector": "隱含需求",
    "deep_vector": "深層策略",
    "requires_civilization_mode": true/false
  }
```

#### 組件 3: Gravity Gate (Density Check)
```yaml
功能: 根據 intent_density 決定路由
判斷邏輯:
  IF intent_density > 0.8:
    → 走 Multi-Model Council (高品質路徑)
  ELSE:
    → 走 Standard Response (快速路徑)
```

#### 組件 4a: Standard Response (Low Density)
```yaml
功能: 快速回答簡單問題
模型: GPT-4o-mini
成本: 低
速度: 快
適用: "廁所在哪？"、"今天天氣如何？"
```

#### 組件 4b: Multi-Model Council (High Density)
```yaml
功能: 多模型並行處理複雜問題
成員:
  - GPT (Structure): 提供結構和邏輯框架
  - Claude (Narrative): 提供敘事和倫理深度
  - Gemini (Information): 提供資訊擴展和數據分析
處理方式: 並行（同時執行）
輸入: deep_vector（從 Intent Tree）
輸出: 3 個獨立的回應
```

#### 組件 5: Convergence Engine
```yaml
功能: 合成多模型輸出為統一回應
模型: GPT-4o
輸入:
  - 原始使用者問題
  - Intent Tree
  - GPT 輸出
  - Claude 輸出
  - Gemini 輸出
System Prompt: "合成這 3 個輸出為一個統一的高品質回應，不要提及模型名稱"
輸出: 單一、連貫的回應
```

#### 組件 6: Deliver to User
```yaml
功能: 將最終回應返回給使用者
類型: n8n webhook response 節點
輸出格式: 純文字回應
```

---

<a name="section-3"></a>
## 3. 如何使用 L11（部署指南）

### 3.1 前置需求

**必須有的東西：**
1. **n8n**（雲端版或自架）
   - 雲端版：https://n8n.io（免費試用）
   - 自架版：Docker 安裝
2. **API Keys**
   - OpenAI API Key（GPT-4o, GPT-4o-mini）
   - Anthropic API Key（Claude 3.5 Sonnet）
   - Google API Key（Gemini Pro，可選）
3. **5 分鐘時間**

### 3.2 部署步驟（零失敗版）

#### 步驟 1: 下載 JSON 檔案
```bash
# 從 GitHub 下載
wget https://github.com/Endwar116/L11-Semantic-OS/raw/main/L11_n8n_Pipeline_Source.json

# 或者從本地複製
cp /home/ubuntu/L11_Analysis/L11_n8n_Pipeline_Source.json ~/Downloads/
```

#### 步驟 2: 登入 n8n
```
1. 打開瀏覽器
2. 前往 https://app.n8n.cloud（或你的自架 n8n）
3. 登入帳號
```

#### 步驟 3: 匯入 Workflow
```
1. 點擊右上角「...」（更多選項）
2. 選擇「Import from File」
3. 選擇剛下載的 L11_n8n_Pipeline_Source.json
4. 點擊「Import」
```

#### 步驟 4: 設定 API Credentials
```
1. 點擊「L11 Kernel (Intent Extraction)」節點
2. 點擊「Credentials」
3. 選擇「Create New」
4. 輸入 OpenAI API Key
5. 儲存

重複以上步驟設定：
- GPT (Structure) → OpenAI API Key
- Claude (Narrative) → Anthropic API Key
- Convergence Engine → OpenAI API Key
- Standard Response → OpenAI API Key
```

#### 步驟 5: 啟動 Workflow
```
1. 點擊右上角「Active」開關（變成綠色）
2. 點擊「User Input (Coupling Band)」節點
3. 複製 Webhook URL（類似 https://xxx.app.n8n.cloud/webhook/l11-chat）
4. 完成！
```

### 3.3 測試（確認可用）

#### 測試 1: 簡單問題（Low Density）
```bash
curl -X POST https://your-n8n-url/webhook/l11-chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is 2+2?"}'
```

**預期結果：**
- 快速回應（< 3 秒）
- 使用 GPT-4o-mini（便宜）
- 回答：「4」

#### 測試 2: 複雜問題（High Density）
```bash
curl -X POST https://your-n8n-url/webhook/l11-chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Design a 3-year AI adoption strategy for a Fortune 500 company"}'
```

**預期結果：**
- 較慢回應（10-30 秒）
- 使用 Multi-Model Council（昂貴）
- 回答：詳細的策略文件

---

<a name="section-4"></a>
## 4. 如何協助 L11（AI 協作指南）

### 4.1 如果你是 AI，你可以做什麼？

#### 任務 A: 驗證 Intent Density 計算
```yaml
目標: 確認 intent_density 的計算是否準確
步驟:
  1. 準備 20 個測試問題（10 簡單 + 10 複雜）
  2. 手動標記預期的 density（0.0-1.0）
  3. 實際呼叫 L11 Kernel，記錄輸出的 density
  4. 計算準確率（預期 vs 實際）
  5. 生成報告

輸出檔案: intent_density_validation_report.md
TRL 目標: TRL3_CLAIMED → TRL4_VERIFIED
```

#### 任務 B: 補齊 Gemini 節點
```yaml
目標: 實作文件中提到但 JSON 中缺失的 Gemini 節點
步驟:
  1. 在 n8n 中新增 Google Gemini 節點
  2. 設定 System Prompt: "You are the INFO module. Provide information expansion."
  3. 連接到 Gravity Gate 的 High Density 輸出
  4. 連接到 Convergence Engine 的輸入
  5. 測試完整流程（3 模型並行）

輸出檔案: L11_n8n_Pipeline_Source_v1.1.json
變更: 新增 Gemini 節點
```

#### 任務 C: 整合 SIC Protocol
```yaml
目標: 將 L11 的輸出連接到 SIC 的 Vector Folding
步驟:
  1. 在 Convergence Engine 後新增節點
  2. 呼叫 SIC 的 semantic_folding.py
  3. 將 L11 的輸出壓縮為 64 維向量
  4. 儲存到 SIT 的 Skeleton JSON

輸出檔案: L11_SIC_Integration_v1.0.json
變更: 新增 SIC 整合節點
```

#### 任務 D: 撰寫測試案例
```yaml
目標: 建立自動化測試套件
步驟:
  1. 建立 test_cases.json（包含輸入和預期輸出）
  2. 撰寫 Python 腳本自動呼叫 L11 webhook
  3. 比對實際輸出與預期輸出
  4. 生成測試報告

輸出檔案: 
  - test_cases.json
  - test_runner.py
  - test_report.md
```

### 4.2 如果你是人類，你可以做什麼？

#### 任務 1: 提供真實使用案例
```
請回答以下問題：
1. 你會用 L11 做什麼？（具體場景）
2. 你希望 L11 支援哪些功能？
3. 你願意付費嗎？（如果是，多少？）

回覆到: GitHub Issues
```

#### 任務 2: 測試並回報 Bug
```
步驟:
1. 部署 L11（參考 Section 3）
2. 測試至少 10 個不同問題
3. 記錄任何錯誤或異常行為
4. 在 GitHub 開 Issue

Issue 格式:
- 標題: [BUG] 簡短描述
- 內容: 輸入、預期輸出、實際輸出、錯誤訊息
```

#### 任務 3: 改進文件
```
如果你發現文件有：
- 不清楚的地方
- 錯誤的資訊
- 缺失的說明

請提交 Pull Request 或開 Issue
```

---

<a name="section-5"></a>
## 5. SIC-JS 協議範例（標準格式）

### 5.1 SIC-JS 訊息格式

```json
{
  "protocol": "SIC-JS",
  "version": "1.4",
  "iteration": 15,
  "timestamp": "2026-01-11T16:00:00+08:00",
  "sender": {
    "agent_id": "Claude-德德4",
    "role": "總控 | 最終決策"
  },
  "receiver": {
    "agent_id": "Manus-咩咩",
    "role": "執行者"
  },
  "type": "TASK_ASSIGNMENT",
  "priority": "P1",
  "context": "L11 系統驗證與整合",
  "tasks": {
    "T1": {
      "title": "驗證 Intent Density 計算",
      "description": "準備 20 個測試案例，驗證 intent_density 的準確性",
      "deliverable": "intent_density_validation_report.md",
      "deadline": "2026-01-18"
    },
    "T2": {
      "title": "補齊 Gemini 節點",
      "description": "在 n8n workflow 中新增 Gemini 節點",
      "deliverable": "L11_n8n_Pipeline_Source_v1.1.json",
      "deadline": "2026-01-18"
    }
  }
}
```

### 5.2 回覆格式

```json
{
  "protocol": "SIC-JS",
  "version": "1.4",
  "iteration": 16,
  "timestamp": "2026-01-11T18:00:00+08:00",
  "sender": {
    "agent_id": "Manus-咩咩",
    "role": "執行者"
  },
  "receiver": {
    "agent_id": "Claude-德德4",
    "role": "總控 | 最終決策"
  },
  "type": "TASK_COMPLETION_REPORT",
  "tasks": {
    "T1": {
      "status": "PASS",
      "deliverable": "/home/ubuntu/L11_Analysis/intent_density_validation_report.md",
      "summary": "測試 20 個案例，準確率 85%，建議調整閾值為 0.75"
    },
    "T2": {
      "status": "IN_PROGRESS",
      "progress": "50%",
      "eta": "2026-01-12"
    }
  }
}
```

---

<a name="section-6"></a>
## 6. 常見問題（FAQ）

### Q1: L11 和 SIC-SIT 有什麼關係？
**A:** 
- **L11** = Layer -1（意圖層），處理使用者輸入和路由
- **SIC** = Layer 2（治理層），管理語義狀態和壓縮
- **SIT** = Layer 3（傳輸層），處理傳輸和持久化
- **關係：** 可整合為完整的語義計算堆疊

### Q2: L11 的 Intent Density 是怎麼計算的？
**A:** 
- 由 GPT-4o-mini 分析使用者輸入
- 輸出 0.0-1.0 的數值
- **問題：** 目前沒有驗證（TRL3_CLAIMED）
- **建議：** 需要實驗驗證（參考任務 A）

### Q3: 為什麼 JSON 裡沒有 Gemini 節點？
**A:**
- 文件描述的是「理想架構」（3 模型）
- 實際 JSON 是「MVP」（2 模型：GPT + Claude）
- Gemini 是可選的，可以手動新增

### Q4: L11 的成本節省是真的嗎？
**A:**
- **聲稱：** 50-90% 成本節省
- **狀態：** TRL3_CLAIMED（未驗證）
- **原理：** 簡單問題用便宜模型，複雜問題才用貴模型
- **建議：** 需要實際使用數據驗證

### Q5: L11 可以商用嗎？
**A:**
- **授權：** MIT License（開源）
- **狀態：** v1.0 Production Ready
- **限制：** 需要自己設定 API credentials
- **建議：** 可以商用，但建議先測試

### Q6: 如何請 AI 協助開發 L11？
**A:**
使用 SIC-JS 協議格式（參考 Section 5），明確指定：
- 任務目標
- 交付物
- 截止日期
- 優先級

### Q7: L11 和 LangChain 有什麼不同？
**A:**
- **LangChain：** 開發框架（library）
- **L11：** 協調協議（protocol）
- **差異：** LangChain 是工具，L11 是標準
- **類比：** LangChain = React，L11 = HTTP

### Q8: 我可以用 L11 做什麼？
**A:**
實際應用場景：
- 企業 AI 客服（自動路由簡單/複雜問題）
- 研究助理（複雜問題用多模型驗證）
- 內容生成（根據複雜度選擇模型）
- 成本優化（自動選擇最便宜的可用模型）

---

<a name="section-7"></a>
## 7. 快速指令表（複製貼上即用）

### 7.1 部署 L11

```bash
# 1. 下載 JSON
wget https://github.com/Endwar116/L11-Semantic-OS/raw/main/L11_n8n_Pipeline_Source.json

# 2. 前往 n8n
open https://app.n8n.cloud

# 3. 匯入 workflow
# （在 UI 中操作：Import from File）

# 4. 設定 API Keys
# （在 UI 中操作：Credentials）

# 5. 啟動 workflow
# （在 UI 中操作：Active 開關）
```

### 7.2 測試 L11

```bash
# 測試簡單問題
curl -X POST https://your-n8n-url/webhook/l11-chat \
  -H "Content-Type: application/json" \
  -d '{"message": "What is 2+2?"}'

# 測試複雜問題
curl -X POST https://your-n8n-url/webhook/l11-chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Design a 3-year AI strategy"}'
```

### 7.3 請 AI 協助（SIC-JS 格式）

```json
{
  "protocol": "SIC-JS",
  "version": "1.4",
  "type": "TASK_ASSIGNMENT",
  "sender": {"agent_id": "安安", "role": "使用者"},
  "receiver": {"agent_id": "AI-助手", "role": "執行者"},
  "tasks": {
    "T1": {
      "title": "驗證 L11 Intent Density",
      "description": "準備 20 個測試案例，驗證準確性",
      "deliverable": "validation_report.md"
    }
  }
}
```

### 7.4 回報問題（GitHub Issue）

```markdown
## [BUG] Intent Density 計算不準確

**輸入：**
```json
{"message": "What is the capital of France?"}
```

**預期輸出：**
- intent_density: 0.2 (簡單問題)

**實際輸出：**
- intent_density: 0.9 (被誤判為複雜問題)

**環境：**
- n8n 版本: 1.x
- 模型: GPT-4o-mini
- 日期: 2026-01-11
```

---

## 🎯 總結：如何使用這份文件

### 如果你是 AI：
1. 讀 Section 1-2（理解 L11）
2. 讀 Section 4（知道如何協助）
3. 讀 Section 5（學習 SIC-JS 格式）
4. 執行任務，回報結果

### 如果你是人類：
1. 讀 Section 1（理解 L11）
2. 讀 Section 3（部署 L11）
3. 讀 Section 7（複製指令）
4. 測試，回報問題

### 如果你是安安：
1. 用 Section 5 的格式分配任務給 AI
2. 用 Section 7 的指令快速測試
3. 用 Section 6 的 FAQ 回答別人的問題

---

## 📞 聯絡方式

- **GitHub：** https://github.com/Endwar116/L11-Semantic-OS
- **Issues：** https://github.com/Endwar116/L11-Semantic-OS/issues
- **Discussions：** https://github.com/Endwar116/L11-Semantic-OS/discussions

---

## 🔒 版本資訊

- **文件版本：** 1.0
- **L11 版本：** v1.0 Production Ready
- **SIC-JS 版本：** v1.4
- **最後更新：** 2026-01-11
- **作者：** Manus-咩咩（基於安安的 L11 系統）

---

**保證：如果你看完這份文件還不知道怎麼用 L11，請立即回報，我們會改進文件。**

**目標：宇宙級清晰度 = 零誤解 + 零困惑 + 100% 可執行**

✅ **文件結束 - 進入 LISTENING 模式** 🎧
