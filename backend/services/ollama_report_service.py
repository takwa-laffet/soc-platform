import json
from datetime import datetime, timezone
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_SEC,
    LM_STUDIO_BASE_URL,
    LM_STUDIO_MODEL,
    LM_STUDIO_TIMEOUT,
    LM_STUDIO_API_KEY,
)

logger = logging.getLogger(__name__)

# Configure retry strategy for resilience
RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[502, 503, 504],
    allowed_methods=["POST"],
    raise_on_status=False
)

# Session with retry adapter
_session = requests.Session()
_session.mount("http://", HTTPAdapter(max_retries=RETRY_STRATEGY))
_session.mount("https://", HTTPAdapter(max_retries=RETRY_STRATEGY))


def _list_available_models():
    endpoint = f"{OLLAMA_BASE_URL.rstrip('/')}/api/tags"
    response = _session.get(endpoint, timeout=min(10, OLLAMA_TIMEOUT_SEC))
    response.raise_for_status()
    data = response.json() or {}
    models = []
    for item in data.get("models", []):
        name = item.get("name")
        if name:
            models.append(name)
    return models


def _resolve_model_name():
    configured_model = (OLLAMA_MODEL or "").strip()
    try:
        available_models = _list_available_models()
    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not read Ollama model list from {OLLAMA_BASE_URL}: {e}")
        return configured_model or OLLAMA_MODEL

    if configured_model and configured_model in available_models:
        return configured_model

    if available_models:
        fallback_model = available_models[0]
        if configured_model and configured_model != fallback_model:
            logger.warning(
                "Configured Ollama model '%s' is not available at %s; falling back to '%s'",
                configured_model,
                OLLAMA_BASE_URL,
                fallback_model,
            )
        return fallback_model

    raise RuntimeError(
        f"No Ollama models are available at {OLLAMA_BASE_URL}. Please pull a model before generating reports."
    )


def _build_prompt(payload):
    summary = payload.get("summary") or {}
    rows = payload.get("rows") or []
    feedback = payload.get("feedback") or {}

    compact_rows = []
    for row in rows[:40]:
        compact_rows.append(
            {
                "id": row.get("id") or row.get("alert_id") or row.get("external_alert_id") or row.get("cve_id"),
                "severity": row.get("severity_final") or row.get("priority") or "Normal",
                "attack_category": row.get("attack_category") or row.get("attack_type") or "General",
                "confidence": row.get("confidence") or row.get("attack_confidence") or row.get("priority_confidence") or 0,
                "needs_review": bool(row.get("needs_review")),
                "source": row.get("source_tool") or row.get("responseSource") or row.get("source") or "unknown",
                "rule": row.get("rule_description") or "",
                "soc_tier": row.get("soc_level_tier") or "",
            }
        )

    prompt_data = {
        "summary": summary,
        "feedback": feedback,
        "rows": compact_rows,
    }

    return (
        "You are a SOC manager assistant. Analyze the provided ML alert summary and produce a concise executive incident report. "
        "Return strict JSON only with keys: title, executive_summary, key_findings (array of strings), "
        "priority_actions (array of strings), analyst_advice (array of strings), risk_level, and report_markdown. "
        "The report_markdown must include sections: Executive Summary, Findings, Recommendations, and Next 24 Hours Plan. "
        "Do not include code blocks.\n\n"
        f"INPUT_JSON:\n{json.dumps(prompt_data, ensure_ascii=True)}"
    )


def generate_soc_report(payload):
    prompt = _build_prompt(payload)
    endpoint = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
    model_name = _resolve_model_name()

    request_body = {
        "model": model_name,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }

    try:
        response = _session.post(
            endpoint,
            json=request_body,
            timeout=OLLAMA_TIMEOUT_SEC,
        )
        # Raise specific HTTP errors
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Ollama connection error at {endpoint}: {e}")
        raise RuntimeError(
            f"Unable to connect to Ollama service at {OLLAMA_BASE_URL}. "
            "Please ensure Ollama is running and accessible from this host."
        ) from e
    except requests.exceptions.Timeout as e:
        logger.error(f"Ollama timeout error after {OLLAMA_TIMEOUT_SEC}s: {e}")
        raise RuntimeError(
            f"Ollama request timed out after {OLLAMA_TIMEOUT_SEC} seconds. "
            "The service may be overloaded or generating a large response."
        ) from e
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "unknown"
        logger.error(f"Ollama HTTP error {status_code}: {e}")
        raise RuntimeError(
            f"Ollama service returned HTTP {status_code}. "
            f"The model '{OLLAMA_MODEL}' may be unavailable or the request was malformed."
        ) from e
    except requests.exceptions.RequestException as e:
        logger.error(f"Unexpected error calling Ollama: {e}")
        raise RuntimeError(
            f"Failed to communicate with Ollama service: {e}"
        ) from e

    try:
        outer = response.json() or {}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response from Ollama: {response.text[:500]}")
        raise RuntimeError(
            "Ollama returned an invalid JSON response. "
            "The service may be malfunctioning or returning unexpected data."
        ) from e

    model_response = (outer.get("response") or "").strip()
    if not model_response:
        logger.warning("Ollama returned empty response")
        raise ValueError("Ollama returned an empty response. Please try again with different input.")

    try:
        parsed = json.loads(model_response)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Ollama response JSON: {model_response[:500]}")
        raise RuntimeError(
            "Ollama response could not be parsed as valid JSON. "
            "The model may have generated malformed output."
        ) from e

    now = datetime.now(timezone.utc).isoformat()

    return {
        "title": parsed.get("title") or "SOC ML Incident Report",
        "executive_summary": parsed.get("executive_summary") or "No summary generated.",
        "key_findings": parsed.get("key_findings") or [],
        "priority_actions": parsed.get("priority_actions") or [],
        "analyst_advice": parsed.get("analyst_advice") or [],
        "risk_level": parsed.get("risk_level") or "Unknown",
        "report_markdown": parsed.get("report_markdown") or "",
        "meta": {
            "generated_at": now,
            "model": model_name,
            "base_url": OLLAMA_BASE_URL,
        },
    }


def generate_rapport_with_qwen(payload):
    """
    Generate a SOC report using qwen model via LM Studio (OpenAI-compatible API).
    Uses qwen/qwen3-2.7B or configured LM_STUDIO_MODEL.
    
    Accepts payload with: summary, feedback, rows (all auto-predict output).
    """
    summary = payload.get("summary") or {}
    feedback = payload.get("feedback") or {}
    rows = payload.get("rows") or []

    # Build comprehensive context from ALL auto-predict output
    items_context = []
    for row in rows:
        items_context.append({
            "id": row.get("id") or row.get("alert_id") or row.get("external_alert_id") or row.get("cve_id") or "unknown",
            "type": row.get("responseType") or row.get("type") or "unknown",
            "severity": row.get("severity_final") or row.get("priority") or "Normal",
            "confidence": row.get("confidence") or row.get("attack_confidence") or row.get("priority_confidence") or row.get("confidence_final") or 0,
            "model": row.get("model_used") or "unknown",
            "needs_review": bool(row.get("needs_review")),
            "attack_category": row.get("attack_category") or row.get("attack_type") or "N/A",
            "rule": row.get("rule_description") or row.get("rule") or "",
            "source": row.get("source_tool") or row.get("responseSource") or row.get("source") or "unknown",
            "soc_tier": row.get("soc_level_tier") or "",
            "timestamp": row.get("responseTimestamp") or row.get("timestamp") or "",
        })

    # Comprehensive prompt for qwen with POV and team advice
    prompt_text = (
        "你是一位资深的SOC（安全运营中心）经理和AI分析师。请根据以下ML模型的分析结果和威胁情报数据，编写一份全面的执行事件报告。\n\n"
        "请以严格JSON格式返回结果，包含以下键：\n"
        "- title（报告标题）\n"
        "- executive_summary（执行摘要）\n"
        "- key_findings（关键发现，字符串数组）\n"
        "- priority_actions（优先行动项，字符串数组）\n"
        "- analyst_advice（分析师建议，字符串数组）\n"
        "- ml_analysis_pov（AI分析师对ML分析结果的观点和见解）\n"
        "- threat_intel_pov（AI分析师对威胁情报分析的观点和见解）\n"
        "- team_advice（针对SOC团队的具体建议和指导）\n"
        "- risk_level（风险等级：Low/Medium/High/Critical）\n"
        "- report_markdown（完整的报告Markdown文本）\n\n"
        "请特别关注：\n"
        "- 作为AI分析师，分析ML模型的准确性和可靠性\n"
        "- 评估威胁情报数据的质量和相关性\n"
        "- 为SOC团队提供可操作的战术建议\n"
        "- 识别潜在的误报和漏报模式\n\n"
        "不要包含任何代码块（不要使用```json或其他代码块标记）。\n\n"
        f"汇总信息: {json.dumps(summary, ensure_ascii=False)}\n\n"
        f"反馈统计: {json.dumps(feedback, ensure_ascii=False)}\n\n"
        f"所有ML分析结果 ({len(items_context)} 项):\n{json.dumps(items_context, ensure_ascii=False, indent=2)}\n\n"
        f"威胁情报分析摘要: {payload.get('threat_intel_summary', 'N/A')}\n\n"
        "请基于以上所有数据生成综合报告，包括你的专业观点和团队建议。"
    )

    # Determine model name
    model_name = (LM_STUDIO_MODEL or "qwen/qwen3-2.7B").strip()
    base_url = (LM_STUDIO_BASE_URL or "http://127.0.0.1:1234").rstrip("/")

    endpoint = f"{base_url}/v1/chat/completions"

    headers = {
        "Content-Type": "application/json",
    }
    if LM_STUDIO_API_KEY:
        headers["Authorization"] = f"Bearer {LM_STUDIO_API_KEY}"

    request_body = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": "You are an expert SOC manager. Generate concise, actionable security reports in both English and Chinese. Return valid JSON only."
            },
            {
                "role": "user",
                "content": prompt_text
            }
        ],
        "temperature": 0.7,
        "max_tokens": 2000,
    }

    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

    try:
        response = session.post(
            endpoint,
            json=request_body,
            headers=headers,
            timeout=LM_STUDIO_TIMEOUT,
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(
            f"无法连接到LM Studio服务 {base_url}. 请确保服务正在运行: {e}"
        )
    except requests.exceptions.Timeout as e:
        raise RuntimeError(
            f"LM Studio请求超时 ({LM_STUDIO_TIMEOUT}秒): {e}"
        )
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else "unknown"
        raise RuntimeError(
            f"LM Studio返回HTTP {status}. 模型'{model_name}'可能不可用: {e}"
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"LM Studio请求失败: {e}")

    try:
        result = response.json()
    except json.JSONDecodeError:
        raise RuntimeError(f"LM Studio返回无效JSON: {response.text[:500]}")

    # Parse OpenAI-compatible response
    choices = result.get("choices", [])
    if not choices:
        raise RuntimeError("LM Studio响应中没有choices字段")

    message_content = choices[0].get("message", {}).get("content", "").strip()
    if not message_content:
        raise ValueError("LM Studio返回空响应")

    # Try to extract JSON from the response (handle markdown code blocks)
    import re
    json_match = re.search(r'\{[^{}]*"title"[^{}]*\"executive_summary\"[^{}]*\"key_findings\"[^{}]*\"priority_actions\"[^{}]*\"analyst_advice\"[^{}]*\"ml_analysis_pov\"[^{}]*\"threat_intel_pov\"[^{}]*\"team_advice\"[^{}]*\"risk_level\"[^{}]*\"report_markdown\"[\s\S]*\}', message_content)
    if json_match:
        message_content = json_match.group(0)
    else:
        # Try to find JSON between any curly braces
        json_matches = re.findall(r'\{[\s\S]*?\}', message_content)
        for jm in json_matches:
            if '"title"' in jm and '"executive_summary"' in jm and '"ml_analysis_pov"' in jm:
                message_content = jm
                break

    try:
        parsed = json.loads(message_content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"无法解析LM Studio响应JSON: {e}\n响应内容: {message_content[:500]}")

    now = datetime.now(timezone.utc).isoformat()

    return {
        "title": parsed.get("title") or "SOC ML 事件报告",
        "executive_summary": parsed.get("executive_summary") or "无摘要",
        "key_findings": parsed.get("key_findings") or [],
        "priority_actions": parsed.get("priority_actions") or [],
        "analyst_advice": parsed.get("analyst_advice") or [],
        "ml_analysis_pov": parsed.get("ml_analysis_pov") or "未提供ML分析观点",
        "threat_intel_pov": parsed.get("threat_intel_pov") or "未提供威胁情报分析观点",
        "team_advice": parsed.get("team_advice") or "未提供团队建议",
        "risk_level": parsed.get("risk_level") or "Unknown",
        "report_markdown": parsed.get("report_markdown") or "",
        "meta": {
            "generated_at": now,
            "model": model_name,
            "base_url": base_url,
            "engine": "lm-studio",
        },
    }
