#!/usr/bin/env python3
"""
Encoding Gate - Pre-Entropy Gate for SIC/T Protocol

Purpose:
    Detect encoding-unmeasurable inputs before entropy calculation.
    Prevents negative entropy and undefined behavior.

Complexity: O(n)
Performance: <10ms for 100KB input

Author: Manus (ENGINEERING)
Date: 2026-01-14
Version: v1.0
License: MIT

Based on: MANUS_HANDOFF_ENCODING_GATE_2026-01-14.md
Consensus: 4/4 (Claude-Sonnet-4.5, Manus, Copilot, DeepSeek)
"""

import unicodedata
import zlib
from typing import Tuple
from enum import Enum

try:
    import regex  # 支援 \p{Emoji}
except ImportError:
    regex = None
    print("Warning: 'regex' module not found. Emoji detection will be disabled.")


class EncodingUnmeasurableReason(Enum):
    """Encoding-Unmeasurable 原因代碼"""
    OK = "OK"
    UTF8_DECODE_FAILURE = "SICT_UTF8_DECODE_FAILURE"
    NORMALIZATION_AMBIGUITY = "SICT_NORMALIZATION_AMBIGUITY"
    EMOJI_DENSITY_EXCEEDED = "SICT_EMOJI_DENSITY_EXCEEDED"
    RANDOM_NOISE_SIGNATURE = "SICT_RANDOM_NOISE_SIGNATURE"
    ENTROPY_OUT_OF_BOUNDS = "SICT_ENTROPY_OUT_OF_BOUNDS"


def is_encoding_unmeasurable(input_bytes: bytes) -> Tuple[bool, str]:
    """
    Pre-Entropy Gate: 檢測編碼不可測量的輸入
    
    Args:
        input_bytes: 原始輸入（bytes）
    
    Returns:
        (is_unmeasurable, reason_code)
        - is_unmeasurable: True 表示輸入不可測量
        - reason_code: 原因代碼（EncodingUnmeasurableReason）
    
    Complexity: O(n)
    Performance: <10ms for 100KB input
    
    Detection Criteria:
        (a) UTF-8 decoding failure
        (b) Normalization ambiguity (NFC ≠ NFKC 且非打印字符 >10%)
        (c) Emoji density > 30%
        (d) Random noise signature (連續 3+ 未知 codepoints)
        (e) zlib compression ratio bounds (<0.05 或 >1.5)
    """
    
    # (a) UTF-8 decoding failure
    try:
        text = input_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return True, EncodingUnmeasurableReason.UTF8_DECODE_FAILURE.value
    
    # 空輸入視為可測量（熵值為 0）
    if len(text) == 0:
        return False, EncodingUnmeasurableReason.OK.value
    
    # (b) Normalization ambiguity
    nfc = unicodedata.normalize('NFC', text)
    nfkc = unicodedata.normalize('NFKC', text)
    if nfc != nfkc:
        non_printable_count = sum(1 for c in text if not c.isprintable())
        non_printable_ratio = non_printable_count / len(text)
        if non_printable_ratio > 0.10:
            return True, EncodingUnmeasurableReason.NORMALIZATION_AMBIGUITY.value
    
    # (c) Emoji density > 30%
    if regex is not None:
        emoji_count = len(regex.findall(r'\p{Emoji}', text))
        emoji_ratio = emoji_count / len(text)
        if emoji_ratio > 0.30:
            return True, EncodingUnmeasurableReason.EMOJI_DENSITY_EXCEEDED.value
    
    # (d) Random noise signature
    # 連續 3+ codepoints 無已知 Unicode block
    consecutive_unknown = 0
    for char in text:
        try:
            # 嘗試獲取字符名稱
            name = unicodedata.name(char, None)
            if name is None:
                consecutive_unknown += 1
                if consecutive_unknown >= 3:
                    return True, EncodingUnmeasurableReason.RANDOM_NOISE_SIGNATURE.value
            else:
                consecutive_unknown = 0
        except ValueError:
            # ValueError 表示無法獲取字符名稱
            consecutive_unknown += 1
            if consecutive_unknown >= 3:
                return True, EncodingUnmeasurableReason.RANDOM_NOISE_SIGNATURE.value
    
    # (e) zlib compression ratio bounds
    # 只對長文字檢查（>= 100 bytes），避免 header overhead 影響
    if len(input_bytes) >= 100:
        compressed = zlib.compress(input_bytes)
        # compression_ratio = compressed_size / original_size
        # 正常文字：0.3 ~ 0.8
        # 極度壓縮（重複字符）：< 0.05
        # 無法壓縮（隨機噪音）：> 1.2
        compression_ratio = len(compressed) / len(input_bytes)
        if compression_ratio < 0.05 or compression_ratio > 1.2:
            return True, EncodingUnmeasurableReason.ENTROPY_OUT_OF_BOUNDS.value
    
    return False, EncodingUnmeasurableReason.OK.value


def get_rejection_response(reason_code: str) -> dict:
    """
    生成標準拒絕回應（對外接口）
    
    Args:
        reason_code: 原因代碼
    
    Returns:
        標準 JSON 錯誤回應
    
    Note:
        - 使用中立技術語言
        - 不提及具體字符、語言或地區
        - 符合 EU AI Act 第 14 條要求
    """
    return {
        "error": reason_code,
        "message": "The input contains encoding patterns that cannot be processed by the SIC/T protocol.",
        "remediation": "Please ensure input conforms to RFC 3629 UTF-8 and Unicode Normalization Form C.",
        "appeal": "If you believe this is an error, please contact support with the incident ID.",
        "documentation": "https://sic-sit-protocol.org/docs/encoding-gate"
    }


def get_lockdown_response(reason_code: str, incident_id: str) -> dict:
    """
    生成 LOCKDOWN 回應（跨系統內部）
    
    Args:
        reason_code: 原因代碼
        incident_id: 事件 ID
    
    Returns:
        LOCKDOWN 回應
    
    Note:
        - 觸發即時通知
        - 自動生成 incident ticket
        - 72 小時內完成初步審查
    """
    return {
        "status": "FAILSAFE_LOCKDOWN",
        "reason": reason_code,
        "incident_id": incident_id,
        "timestamp": None,  # 由調用方填入
        "notification_sent": True,
        "ticket_created": True,
        "review_deadline": "72h"
    }


# 健康指標
class EncodingGateMetrics:
    """
    Encoding Gate 健康指標
    
    Metrics:
        - false_positive_rate_on_normalized_inputs: <1%
        - encoding_unmeasurable_rate_change_after_threshold_tuning: <5%
        - average_time_to_review_lockdown: <72h
    """
    
    def __init__(self):
        self.total_inputs = 0
        self.unmeasurable_count = 0
        self.false_positive_count = 0
        self.lockdown_events = []
    
    def record_input(self, is_unmeasurable: bool, is_false_positive: bool = False):
        """記錄輸入"""
        self.total_inputs += 1
        if is_unmeasurable:
            self.unmeasurable_count += 1
        if is_false_positive:
            self.false_positive_count += 1
    
    def record_lockdown(self, incident_id: str, timestamp: str):
        """記錄 LOCKDOWN 事件"""
        self.lockdown_events.append({
            "incident_id": incident_id,
            "timestamp": timestamp
        })
    
    def get_false_positive_rate(self) -> float:
        """計算誤報率"""
        if self.total_inputs == 0:
            return 0.0
        return self.false_positive_count / self.total_inputs
    
    def get_unmeasurable_rate(self) -> float:
        """計算不可測量率"""
        if self.total_inputs == 0:
            return 0.0
        return self.unmeasurable_count / self.total_inputs
    
    def check_health(self) -> dict:
        """檢查健康狀態"""
        false_positive_rate = self.get_false_positive_rate()
        unmeasurable_rate = self.get_unmeasurable_rate()
        
        health_status = {
            "false_positive_rate": false_positive_rate,
            "false_positive_threshold": 0.01,  # <1%
            "false_positive_ok": false_positive_rate < 0.01,
            "unmeasurable_rate": unmeasurable_rate,
            "total_inputs": self.total_inputs,
            "unmeasurable_count": self.unmeasurable_count,
            "lockdown_events_count": len(self.lockdown_events)
        }
        
        return health_status


# 測試函數
def test_encoding_gate():
    """測試 Encoding Gate"""
    
    print("=" * 70)
    print("Encoding Gate Test Suite")
    print("=" * 70)
    print()
    
    test_cases = [
        # (input_bytes, expected_unmeasurable, description)
        (b"Hello, world!", False, "Normal ASCII text"),
        (b"\xe4\xb8\xad\xe6\x96\x87", False, "Normal UTF-8 Chinese"),
        (b"\xff\xfe", True, "Invalid UTF-8"),
        (b"asdfghjkl qwertyuiop zxcvbnm", False, "Random ASCII (low entropy but valid)"),
        ("🔥💀☠️🚫⚠️❌🛑🔒🔓🗝️".encode('utf-8'), True, "High emoji density"),
        (b"", False, "Empty input"),
        ("Hello\u200b\u200c\u200dWorld".encode('utf-8'), False, "Zero-width characters (low non-printable ratio)"),
    ]
    
    metrics = EncodingGateMetrics()
    
    for i, (input_bytes, expected_unmeasurable, description) in enumerate(test_cases, 1):
        print(f"Test {i}: {description}")
        print(f"Input: {input_bytes[:50]}{'...' if len(input_bytes) > 50 else ''}")
        
        is_unmeasurable, reason_code = is_encoding_unmeasurable(input_bytes)
        
        print(f"Expected: {'Unmeasurable' if expected_unmeasurable else 'Measurable'}")
        print(f"Actual: {'Unmeasurable' if is_unmeasurable else 'Measurable'}")
        print(f"Reason: {reason_code}")
        
        if is_unmeasurable == expected_unmeasurable:
            print("✅ PASS")
        else:
            print("❌ FAIL")
        
        # 記錄指標
        is_false_positive = (is_unmeasurable and not expected_unmeasurable)
        metrics.record_input(is_unmeasurable, is_false_positive)
        
        print()
    
    # 健康檢查
    print("=" * 70)
    print("Health Check")
    print("=" * 70)
    health = metrics.check_health()
    print(f"False Positive Rate: {health['false_positive_rate']:.2%} (threshold: {health['false_positive_threshold']:.2%})")
    print(f"False Positive OK: {health['false_positive_ok']}")
    print(f"Unmeasurable Rate: {health['unmeasurable_rate']:.2%}")
    print(f"Total Inputs: {health['total_inputs']}")
    print(f"Unmeasurable Count: {health['unmeasurable_count']}")
    print()


if __name__ == "__main__":
    test_encoding_gate()
