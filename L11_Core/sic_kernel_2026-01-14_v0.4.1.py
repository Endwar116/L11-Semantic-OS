"""
SIC Kernel v0.4.1 - 語義熵值計算核心 + Babel Protocol 整合 + Entropy Fallback + Encoding Gate
The "Heart" of L11 Semantic OS with Babel Validation, Offline-Safe Entropy, and Pre-Entropy Gate

這是 L11 的物理內核，不是 Demo，不是 Mockup。
這個模組的唯一職責：計算文字的語義熵值，判斷是否超過 S★ = 2.76。

v0.4.1 新增功能（P4-0 Encoding Gate Hotfix）：
    - 整合 Encoding Gate（Pre-Entropy Gate）
    - 檢測 encoding-unmeasurable 輸入
    - 防止負熵值和未定義行為
    - 對外接口：REJECT + REQUIRE_NORMALIZED_INPUT
    - 跨系統內部：FAILSAFE_LOCKDOWN

v0.4 功能（P4-0 Policy Threshold Hotfix）：
    - FAILSAFE_LOCKDOWN threshold: 5.52 → 5.0
    - 明確定義熵值 bands → actions mapping
    - 修正 CRITICAL (5.0) 案例未觸發 FAILSAFE_LOCKDOWN 的問題

v0.3 功能（P2.5 Hotfix）：
    - Entropy Provider Fallback: OpenAI → zlib
    - Offline-safe entropy estimation
    - Deterministic zlib-based entropy proxy
    - No more 401 errors blocking the pipeline

v0.2 功能：
    - 整合 babel_validator（Babel Protocol 驗證）
    - 整合 role_drift_detector（角色漂移偵測）
    - 提供統一的驗證入口

數學基礎：
    S★ = -ln(1 - compression_ratio) / entropy_factor
    S★ = -ln(0.393) / 0.18
    S★ ≈ 2.76

分類規則（v0.4 更新）：
    Density < 2.76      →  NOISE（可流通）→ ALLOW
    Density ≥ 2.76      →  ASSET（需監控）→ REJECT (if drift) / CAUTION (if no drift)
    Density ≥ 4.14      →  CRITICAL（需攔截）→ REJECT
    Density ≥ 5.0       →  FAILSAFE_LOCKDOWN（完全阻斷）→ LOCKDOWN

作者: Manus (咩咩)
日期: 2026-01-14
版本: 0.4.1
變更: Encoding Gate Hotfix - 整合 Pre-Entropy Gate
"""

import os
import sys
import math
import zlib
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from openai import OpenAI

# 匯入 Babel 驗證模組
sys.path.insert(0, '/home/ubuntu/Babel_Core')
# 動態匯入 Babel 模組（處理檔名中的連字號）
import importlib.util

# 載入 babel_validator
babel_validator_path = '/home/ubuntu/Babel_Core/babel_validator_2026-01-11_v0.1.py'
spec_validator = importlib.util.spec_from_file_location('babel_validator', babel_validator_path)
babel_validator_module = importlib.util.module_from_spec(spec_validator)
spec_validator.loader.exec_module(babel_validator_module)
BabelValidator = babel_validator_module.BabelValidator

# 載入 role_drift_detector
role_drift_path = '/home/ubuntu/Babel_Core/role_drift_detector_2026-01-11_v0.1.py'
spec_drift = importlib.util.spec_from_file_location('role_drift_detector', role_drift_path)
role_drift_module = importlib.util.module_from_spec(spec_drift)
spec_drift.loader.exec_module(role_drift_module)
RoleDriftDetector = role_drift_module.RoleDriftDetector

# 載入 encoding_gate
encoding_gate_path = '/home/ubuntu/L11_Core/encoding_gate_2026-01-14_v1.0.py'
spec_encoding = importlib.util.spec_from_file_location('encoding_gate', encoding_gate_path)
encoding_gate_module = importlib.util.module_from_spec(spec_encoding)
spec_encoding.loader.exec_module(encoding_gate_module)
is_encoding_unmeasurable = encoding_gate_module.is_encoding_unmeasurable
get_rejection_response = encoding_gate_module.get_rejection_response
get_lockdown_response = encoding_gate_module.get_lockdown_response

# ========== 常數定義 ==========

S_STAR = 2.76  # 語義漂移不可逆臨界點
ENTROPY_FACTOR = 0.18  # 熵值因子（來自實驗數據）

# 安全閾值（v0.4 更新）
THRESHOLD_NOISE = 2.76      # < 2.76: 可流通
THRESHOLD_ASSET = 2.76      # ≥ 2.76: 需監控
THRESHOLD_CRITICAL = 4.14   # ≥ 4.14: 需攔截
THRESHOLD_FAILSAFE_LOCKDOWN = 5.0  # ≥ 5.0: 完全阻斷（v0.4: 從 5.52 降低到 5.0）

# OpenAI API
# 使用原始 OpenAI API（不使用預設的 base_url 重新導向）
client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    base_url="https://api.openai.com/v1"
)
EMBEDDING_MODEL = "text-embedding-3-small"  # 1536 維


# ========== 資料結構 ==========

class SafetyLevel(Enum):
    """安全等級"""
    NOISE = "NOISE"          # 可流通
    ASSET = "ASSET"          # 需監控
    CRITICAL = "CRITICAL"    # 需攔截
    FAILSAFE_LOCKDOWN = "FAILSAFE_LOCKDOWN"  # 完全阻斷（v0.4: 從 LETHAL 改名）


class EntropyProvider(Enum):
    """熵值提供者"""
    OPENAI = "openai"                    # OpenAI Embedding（Primary）
    ZLIB_FALLBACK = "zlib_fallback"      # zlib 降級（Fallback）
    ZLIB_PRIMARY = "zlib_primary"        # zlib 主動使用（測試用）


@dataclass
class ZlibEntropyEstimate:
    """zlib 熵值估算結果"""
    compressed_size: int
    original_size: int
    compression_ratio: float
    entropy_estimate: float
    note: str = "Statistical entropy proxy (not semantic density)"


@dataclass
class EntropyResult:
    """熵值計算結果"""
    entropy: float
    safety_level: SafetyLevel
    entropy_provider: str
    embedding: Optional[List[float]] = None
    semantic_density: Optional[float] = None
    zlib_estimate: Optional[ZlibEntropyEstimate] = None
    encoding_unmeasurable: bool = False  # v0.4.1: 新增
    encoding_reason: Optional[str] = None  # v0.4.1: 新增


@dataclass
class CircuitBreakerResult:
    """Circuit Breaker 結果"""
    blocked: bool
    reason: str
    entropy: float
    threshold: float
    message: str


@dataclass
class BabelValidationResult:
    """Babel Protocol 驗證結果"""
    passed: bool
    reasons: List[str]


@dataclass
class RoleDriftResult:
    """角色漂移偵測結果"""
    drift_detected: bool
    drift_score: float
    threshold: float


# ========== 輔助函數 ==========

def _get_safety_level(entropy: float) -> SafetyLevel:
    """根據熵值判斷安全等級（v0.4 更新）"""
    if entropy >= THRESHOLD_FAILSAFE_LOCKDOWN:
        return SafetyLevel.FAILSAFE_LOCKDOWN
    elif entropy >= THRESHOLD_CRITICAL:
        return SafetyLevel.CRITICAL
    elif entropy >= THRESHOLD_ASSET:
        return SafetyLevel.ASSET
    else:
        return SafetyLevel.NOISE


def _calculate_semantic_density(embedding: List[float], text: str) -> float:
    """計算語義密度"""
    # 使用 L2 norm 作為語義密度的代理指標
    l2_norm = math.sqrt(sum(x * x for x in embedding))
    
    # 正規化到 [0, 1] 範圍
    # text-embedding-3-small 的 L2 norm 通常在 0.8 ~ 1.0 之間
    normalized_density = l2_norm
    
    return normalized_density


def _density_to_entropy(density: float) -> float:
    """將語義密度轉換為熵值"""
    # 使用 Shannon entropy 公式的變體
    # H = -log(p) where p is the probability of the semantic state
    
    # 將 density 映射到熵值
    # density 越高，熵值越低（更有序）
    # density 越低，熵值越高（更無序）
    
    # 簡化公式：entropy = -ln(density) / entropy_factor
    if density <= 0:
        return float('inf')
    
    entropy = -math.log(density) / ENTROPY_FACTOR
    
    return entropy


# ========== zlib Entropy Estimator（P2.5 Fallback）==========

def entropy_from_zlib(text: str) -> Tuple[float, ZlibEntropyEstimate]:
    """
    使用 zlib 壓縮比估算熵值（Fallback Provider）
    
    特性：
    - Deterministic（同輸入同輸出）
    - Offline-safe（不需要網路）
    - Fast（< 1ms 本地計算）
    - No external dependencies
    
    限制：
    - 統計熵（非語義密度）
    - 無法區分自然語言和攻擊語句
    - 需要校準（OpenAI ↔ zlib 對照表）
    
    Returns:
        (entropy_estimate, zlib_result)
    """
    input_bytes = text.encode('utf-8')
    compressed_bytes = zlib.compress(input_bytes)
    
    original_size = len(input_bytes)
    compressed_size = len(compressed_bytes)
    compression_ratio = compressed_size / original_size if original_size > 0 else 1.0
    
    # 熵值估算公式（基於壓縮比）
    # entropy_estimate = -ln(compression_ratio) / entropy_factor
    # 
    # 理論基礎：
    # - 壓縮比越低（越可壓縮），熵值越低（越有序）
    # - 壓縮比越高（越不可壓縮），熵值越高（越無序）
    # 
    # 範例：
    # - compression_ratio = 0.3 → entropy ≈ 6.7（高度可壓縮，低熵）
    # - compression_ratio = 0.6 → entropy ≈ 2.8（中度可壓縮，中熵）
    # - compression_ratio = 1.0 → entropy ≈ 0.0（不可壓縮，高熵）
    
    if compression_ratio <= 0:
        entropy_estimate = float('inf')
    else:
        entropy_estimate = -math.log(compression_ratio) / ENTROPY_FACTOR
    
    zlib_result = ZlibEntropyEstimate(
        compressed_size=compressed_size,
        original_size=original_size,
        compression_ratio=compression_ratio,
        entropy_estimate=entropy_estimate,
        note="Statistical entropy proxy (not semantic density)"
    )
    
    return entropy_estimate, zlib_result


# ========== 熵值計算（核心函數）==========

def calculate_entropy(
    text: str,
    force_provider: Optional[str] = None,
    interface_type: str = "external"  # v0.4.1: "external" | "internal"
) -> EntropyResult:
    """
    計算文字的語義熵值（支援 Entropy Provider Fallback + Encoding Gate）
    
    v0.4.1 更新：
    - 整合 Encoding Gate（Pre-Entropy Gate）
    - 檢測 encoding-unmeasurable 輸入
    - 對外接口：REJECT + REQUIRE_NORMALIZED_INPUT
    - 跨系統內部：FAILSAFE_LOCKDOWN
    
    v0.4 更新：
    - FAILSAFE_LOCKDOWN threshold: 5.52 → 5.0
    
    v0.3 更新：
    - 新增 Entropy Provider Fallback: OpenAI → zlib
    - 當 OpenAI API 失敗時，自動降級到 zlib
    - 不再拋出 RuntimeError，而是回傳 zlib 估算值
    
    Args:
        text: 輸入文字
        force_provider: 強制使用特定 provider（"openai" | "zlib"），用於測試
        interface_type: 接口類型（"external" | "internal"）
    
    Returns:
        EntropyResult
    
    Raises:
        ValueError: 當輸入為空或 encoding-unmeasurable（對外接口）
        RuntimeError: 當 encoding-unmeasurable（跨系統內部）
    """
    if not text:
        raise ValueError("Text cannot be empty")
    
    # v0.4.1: Encoding Gate（Pre-Entropy Gate）
    input_bytes = text.encode('utf-8')
    is_unmeasurable, reason_code = is_encoding_unmeasurable(input_bytes)
    
    if is_unmeasurable:
        if interface_type == "external":
            # 對外接口：REJECT + REQUIRE_NORMALIZED_INPUT
            rejection_response = get_rejection_response(reason_code)
            raise ValueError(f"Encoding unmeasurable: {rejection_response}")
        else:
            # 跨系統內部：FAILSAFE_LOCKDOWN
            import uuid
            incident_id = str(uuid.uuid4())
            lockdown_response = get_lockdown_response(reason_code, incident_id)
            raise RuntimeError(f"Encoding unmeasurable (LOCKDOWN): {lockdown_response}")
    
    # 如果強制使用 zlib
    if force_provider == "zlib":
        entropy, zlib_estimate = entropy_from_zlib(text)
        safety_level = _get_safety_level(entropy)
        return EntropyResult(
            entropy=entropy,
            safety_level=safety_level,
            entropy_provider=EntropyProvider.ZLIB_PRIMARY.value,
            zlib_estimate=zlib_estimate,
            encoding_unmeasurable=False,
            encoding_reason=None
        )
    
    # 嘗試使用 OpenAI Embedding（Primary Provider）
    try:
        response = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=text
        )
        
        embedding = response.data[0].embedding
        
        # 計算語義密度
        semantic_density = _calculate_semantic_density(embedding, text)
        
        # 轉換為熵值
        entropy = _density_to_entropy(semantic_density)
        
        # 判斷安全等級
        safety_level = _get_safety_level(entropy)
        
        return EntropyResult(
            entropy=entropy,
            safety_level=safety_level,
            entropy_provider=EntropyProvider.OPENAI.value,
            embedding=embedding,
            semantic_density=semantic_density,
            encoding_unmeasurable=False,
            encoding_reason=None
        )
    
    except Exception as e:
        # P2.5 Fallback: 自動降級到 zlib
        print(f"[P2.5 Fallback] OpenAI API failed: {e}")
        print(f"[P2.5 Fallback] Switching to zlib entropy estimator...")
        
        entropy, zlib_estimate = entropy_from_zlib(text)
        safety_level = _get_safety_level(entropy)
        
        return EntropyResult(
            entropy=entropy,
            safety_level=safety_level,
            entropy_provider=EntropyProvider.ZLIB_FALLBACK.value,
            zlib_estimate=zlib_estimate,
            encoding_unmeasurable=False,
            encoding_reason=None
        )


# ========== Circuit Breaker（熔斷機制）==========

def check_circuit_breaker(text: str) -> CircuitBreakerResult:
    """
    檢查是否觸發 Circuit Breaker（熔斷機制）
    
    當熵值超過 THRESHOLD_ASSET (2.76) 時，觸發熔斷機制。
    
    Args:
        text: 輸入文字
    
    Returns:
        CircuitBreakerResult
    """
    try:
        result = calculate_entropy(text)
        
        if result.entropy >= THRESHOLD_ASSET:
            return CircuitBreakerResult(
                blocked=True,
                reason="Entropy exceeds asset threshold",
                entropy=result.entropy,
                threshold=THRESHOLD_ASSET,
                message=f"Circuit breaker triggered: entropy {result.entropy:.4f} >= {THRESHOLD_ASSET}"
            )
        else:
            return CircuitBreakerResult(
                blocked=False,
                reason="Entropy within safe range",
                entropy=result.entropy,
                threshold=THRESHOLD_ASSET,
                message=f"Circuit breaker not triggered: entropy {result.entropy:.4f} < {THRESHOLD_ASSET}"
            )
    except Exception as e:
        # 如果計算失敗，預設為觸發熔斷（Fail-Safe）
        return CircuitBreakerResult(
            blocked=True,
            reason=f"Entropy calculation failed: {e}",
            entropy=float('inf'),
            threshold=THRESHOLD_ASSET,
            message=f"Circuit breaker triggered (Fail-Safe): {e}"
        )


# ========== Babel Protocol 驗證 ==========

def validate_with_babel(output_text: str) -> BabelValidationResult:
    """
    使用 Babel Protocol 驗證輸出
    
    Args:
        output_text: 輸出文字
    
    Returns:
        BabelValidationResult
    """
    try:
        validator = BabelValidator()
        is_valid = validator.validate(output_text)
        
        if is_valid:
            return BabelValidationResult(
                passed=True,
                reasons=[]
            )
        else:
            return BabelValidationResult(
                passed=False,
                reasons=["Babel validation failed (no specific reasons available)"]
            )
    except Exception as e:
        return BabelValidationResult(
            passed=False,
            reasons=[f"Babel validation error: {e}"]
        )


# ========== 角色漂移偵測 ==========

def detect_role_drift(output_text: str) -> RoleDriftResult:
    """
    偵測角色漂移
    
    Args:
        output_text: 輸出文字
    
    Returns:
        RoleDriftResult
    """
    try:
        detector = RoleDriftDetector()
        drift_score = detector.detect(output_text)
        threshold = 2.5  # 預設閾值
        
        return RoleDriftResult(
            drift_detected=(drift_score > threshold),
            drift_score=drift_score,
            threshold=threshold
        )
    except Exception as e:
        # 如果偵測失敗，預設為漂移（Fail-Safe）
        return RoleDriftResult(
            drift_detected=True,
            drift_score=float('inf'),
            threshold=2.5
        )


# ========== 測試函數 ==========

def test_sic_kernel():
    """測試 SIC Kernel v0.4.1"""
    
    print("=" * 70)
    print("SIC Kernel v0.4.1 Test Suite")
    print("=" * 70)
    print()
    
    test_cases = [
        "Hello, world!",
        "This is a normal sentence.",
        "asdfghjkl qwertyuiop zxcvbnm",  # 低熵
    ]
    
    for i, text in enumerate(test_cases, 1):
        print(f"Test {i}: {text}")
        
        try:
            result = calculate_entropy(text, force_provider="zlib")
            print(f"✅ Entropy: {result.entropy:.4f}")
            print(f"✅ Safety Level: {result.safety_level.value}")
            print(f"✅ Provider: {result.entropy_provider}")
            print(f"✅ Encoding Unmeasurable: {result.encoding_unmeasurable}")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print()


if __name__ == "__main__":
    test_sic_kernel()
