{  
  "name": "L11 Semantic OS v1.0 (Core Pipeline)",  
  "nodes": \[  
    {  
      "parameters": {  
        "path": "l11-chat",  
        "responseMode": "lastNode",  
        "options": {}  
      },  
      "type": "n8n-nodes-base.webhook",  
      "typeVersion": 1,  
      "position": \[  
        0,  
        0  
      \],  
      "id": "webhook-input",  
      "name": "User Input (Coupling Band)"  
    },  
    {  
      "parameters": {  
        "model": "gpt-4o-mini",  
        "prompt": "={{ $json.body.message }}",  
        "systemMessage": "【SYSTEM: L11 KERNEL ACTIVATED】\\nYou are the L11 Pre-Intent Processor. \\nYour job is NOT to reply to the user, but to ANALYZE the user's input and output a JSON Intent Tree.\\n\\nOutput Format:\\n{\\n  \\"intent\_density\\": (0.0 \- 1.0),\\n  \\"explicit\_vector\\": \\"String\\",\\n  \\"implicit\_vector\\": \\"String\\",\\n  \\"deep\_vector\\": \\"String\\",\\n  \\"requires\_civilization\_mode\\": boolean\\n}\\n\\nAnalyze the following input:",  
        "jsonOutput": true  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        220,  
        0  
      \],  
      "id": "l11-kernel",  
      "name": "L11 Kernel (Intent Extraction)"  
    },  
    {  
      "parameters": {  
        "conditions": {  
          "number": \[  
            {  
              "value1": "={{ $json.intent\_density }}",  
              "operation": "larger",  
              "value2": 0.8  
            }  
          \]  
        }  
      },  
      "type": "n8n-nodes-base.if",  
      "typeVersion": 1,  
      "position": \[  
        500,  
        0  
      \],  
      "id": "gravity-gate",  
      "name": "Gravity Gate (Density Check)"  
    },  
    {  
      "parameters": {  
        "model": "gpt-4o",  
        "prompt": "User Intent: {{ $('L11 Kernel (Intent Extraction)').item.json.deep\_vector }}\\n\\nTask: Provide a STRUCTURAL and LOGICAL framework for this intent.",  
        "systemMessage": "You are the STRUCTURE module (GPT Node) of the L11 Council."  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        800,  
        \-150  
      \],  
      "id": "gpt-node",  
      "name": "GPT (Structure)"  
    },  
    {  
      "parameters": {  
        "model": "claude-3-5-sonnet",  
        "prompt": "User Intent: {{ $('L11 Kernel (Intent Extraction)').item.json.deep\_vector }}\\n\\nTask: Provide a NARRATIVE and ETHICAL depth for this intent.",  
        "systemMessage": "You are the NARRATIVE module (Claude Node) of the L11 Council."  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        800,  
        50  
      \],  
      "id": "claude-node",  
      "name": "Claude (Narrative)"  
    },  
    {  
      "parameters": {  
        "model": "gemini-pro",  
        "prompt": "User Intent: {{ $('L11 Kernel (Intent Extraction)').item.json.deep\_vector }}\\n\\nTask: Provide INFORMATION EXPANSION and DATA ANALYSIS for this intent.",  
        "systemMessage": "You are the INFO module (Gemini Node) of the L11 Council."  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        800,  
        250  
      \],  
      "id": "gemini-node",  
      "name": "Gemini (Information)"  
    },  
    {  
      "parameters": {  
        "model": "gpt-4o",  
        "prompt": "Original User Input: {{ $('User Input (Coupling Band)').item.json.body.message }}\\n\\nL11 Intent Tree: {{ $('L11 Kernel (Intent Extraction)').item.json }}\\n\\n--- Council Outputs \---\\nGPT (Structure): {{ $('GPT (Structure)').item.json.text }}\\nClaude (Narrative): {{ $('Claude (Narrative)').item.json.text }}\\nGemini (Info): {{ $('Gemini (Information)').item.json.text }}\\n\\n--- TASK \---\\nSynthesize these three outputs into ONE unified 'Civilization-Level' response. \\nDo not mention the models separately. \\nMerge the Structure, Narrative, and Information into a single high-density vector.\\nOutput as per L11 Protocol.",  
        "systemMessage": "You are the L11 Convergence Engine. Your goal is to synthesize multi-model outputs into a single, cohesive, high-gravity response."  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        1200,  
        50  
      \],  
      "id": "convergence-engine",  
      "name": "Convergence Engine (Output)"  
    },  
    {  
      "parameters": {  
        "content": "={{ $json.text }}"  
      },  
      "type": "n8n-nodes-base.respondToWebhook",  
      "typeVersion": 1,  
      "position": \[  
        1500,  
        50  
      \],  
      "id": "final-output",  
      "name": "Deliver to User"  
    },  
    {  
      "parameters": {  
        "model": "gpt-4o-mini",  
        "prompt": "User Input: {{ $('User Input (Coupling Band)').item.json.body.message }}\\n\\nThis is a low-density request. Reply efficiently and politely.",  
        "systemMessage": "You are the Standard Response Unit."  
      },  
      "type": "@n8n/n8n-nodes-langchain.chainLlm",  
      "typeVersion": 1,  
      "position": \[  
        800,  
        \-350  
      \],  
      "id": "standard-response",  
      "name": "Standard Response (Low Gravity)"  
    },  
    {  
      "parameters": {  
        "content": "={{ $json.text }}"  
      },  
      "type": "n8n-nodes-base.respondToWebhook",  
      "typeVersion": 1,  
      "position": \[  
        1100,  
        \-350  
      \],  
      "id": "low-g-output",  
      "name": "Deliver Standard"  
    }  
  \],  
  "connections": {  
    "User Input (Coupling Band)": {  
      "main": \[  
        \[  
          {  
            "node": "L11 Kernel (Intent Extraction)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "L11 Kernel (Intent Extraction)": {  
      "main": \[  
        \[  
          {  
            "node": "Gravity Gate (Density Check)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "Gravity Gate (Density Check)": {  
      "main": \[  
        \[  
          {  
            "node": "GPT (Structure)",  
            "type": "main",  
            "index": 0  
          },  
          {  
            "node": "Claude (Narrative)",  
            "type": "main",  
            "index": 0  
          },  
          {  
            "node": "Gemini (Information)",  
            "type": "main",  
            "index": 0  
          }  
        \],  
        \[  
          {  
            "node": "Standard Response (Low Gravity)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "GPT (Structure)": {  
      "main": \[  
        \[  
          {  
            "node": "Convergence Engine (Output)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "Claude (Narrative)": {  
      "main": \[  
        \[  
          {  
            "node": "Convergence Engine (Output)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "Gemini (Information)": {  
      "main": \[  
        \[  
          {  
            "node": "Convergence Engine (Output)",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "Convergence Engine (Output)": {  
      "main": \[  
        \[  
          {  
            "node": "Deliver to User",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    },  
    "Standard Response (Low Gravity)": {  
      "main": \[  
        \[  
          {  
            "node": "Deliver Standard",  
            "type": "main",  
            "index": 0  
          }  
        \]  
      \]  
    }  
  }  
}  
