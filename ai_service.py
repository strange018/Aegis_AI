"""
Simulated AI Research Service.

Provides a deterministic Natural Language & Privacy processing pipeline.
Explicitly labeled as a simulated AI platform feature for access control demonstration.

Server-side RBAC validation is built directly into this service: execution is strictly
refused if the caller lacks the 'run_ai' permission, preventing unauthorized execution.
"""

import re
import json
import math
from typing import Dict, Any, List, Optional
from collections import Counter

from permissions import Permission, has_permission
from audit import log_event, AuditEvent
from database import insert_ai_experiment


# Sample deterministic sentiment lexicon
POSITIVE_WORDS = {"accurate", "efficient", "optimal", "fast", "secure", "robust", "intelligent", "high", "success", "great", "excellent", "clean", "improved", "strong", "positive", "safe", "privacy"}
NEGATIVE_WORDS = {"vulnerable", "slow", "error", "leak", "risk", "failure", "breach", "unsafe", "flaw", "bug", "weak", "malicious", "attack", "insecure", "latency", "overfitting"}

# Stopwords for keyword extraction
STOPWORDS = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't",
    "as", "at", "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can",
    "cannot", "could", "did", "do", "does", "doing", "down", "during", "each", "few", "for", "from", "further",
    "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how",
    "i", "if", "in", "into", "is", "it", "its", "itself", "let's", "me", "more", "most", "my", "myself", "no",
    "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", "ourselves", "out",
    "over", "own", "same", "she", "should", "so", "some", "such", "than", "that", "the", "their", "theirs",
    "them", "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too", "under",
    "until", "up", "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why",
    "with", "would", "you", "your", "yours", "yourself", "yourselves"
}


def detect_simulated_pii(text: str) -> List[Dict[str, str]]:
    """
    Simulates a privacy inspection scan for PII (emails, phone numbers, dummy credit cards).
    """
    pii_findings = []
    
    # Email pattern
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)
    for email in emails:
        pii_findings.append({"type": "Email Address", "match": email, "risk": "Medium"})

    # Phone pattern
    phones = re.findall(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", text)
    for phone in phones:
        pii_findings.append({"type": "Phone Number", "match": phone, "risk": "Medium"})

    # Dummy Card / SSN pattern
    ssns = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text)
    for ssn in ssns:
        pii_findings.append({"type": "SSN / ID Identifier", "match": ssn, "risk": "High"})

    return pii_findings


def analyze_text_deterministic(
    text: str,
    analysis_type: str = "comprehensive",
    max_keywords: int = 5
) -> Dict[str, Any]:
    """
    Deterministic text analysis simulating an AI summarization and NLP pipeline.
    """
    if not text or not text.strip():
        return {
            "error": "Input text is empty.",
            "word_count": 0,
            "char_count": 0,
            "summary": "",
            "keywords": [],
            "sentiment": "Neutral",
            "readability_score": 0.0,
            "pii_detected": []
        }

    clean_text = text.strip()
    words = re.findall(r"\b[a-zA-Z0-9'-]+\b", clean_text.lower())
    sentences = [s.strip() for s in re.split(r"[.!?]+", clean_text) if s.strip()]

    word_count = len(words)
    char_count = len(clean_text)
    sentence_count = max(1, len(sentences))

    # Keyword extraction (TF heuristic excluding stopwords)
    filtered_words = [w for w in words if w not in STOPWORDS and len(w) > 2]
    freq = Counter(filtered_words)
    top_keywords = [{"word": w, "count": c} for w, c in freq.most_common(max_keywords)]

    # Extractive summarization heuristic (rank sentences by keyword density)
    if len(sentences) <= 2:
        summary = " ".join(sentences)
    else:
        scores = []
        for s in sentences:
            s_words = set(re.findall(r"\b[a-zA-Z0-9'-]+\b", s.lower()))
            score = sum(freq.get(w, 0) for w in s_words)
            scores.append((score, s))
        scores.sort(key=lambda x: x[0], reverse=True)
        top_sentences = [s[1] for s in scores[:min(3, len(scores))]]
        summary = ". ".join(top_sentences) + "."

    # Deterministic Sentiment heuristic
    pos_score = sum(1 for w in words if w in POSITIVE_WORDS)
    neg_score = sum(1 for w in words if w in NEGATIVE_WORDS)
    if pos_score > neg_score:
        sentiment = "Positive"
        sentiment_score = round(min(1.0, 0.5 + (pos_score - neg_score) * 0.1), 2)
    elif neg_score > pos_score:
        sentiment = "Negative"
        sentiment_score = round(max(-1.0, -0.5 - (neg_score - pos_score) * 0.1), 2)
    else:
        sentiment = "Neutral"
        sentiment_score = 0.0

    # Readability heuristic (Approximated Flesch Reading Ease score)
    avg_sentence_len = word_count / sentence_count
    lexical_diversity = round((len(set(words)) / word_count) * 100, 2) if word_count > 0 else 0
    readability = round(max(10.0, min(100.0, 100.0 - (avg_sentence_len * 1.5))), 1)

    # Privacy & PII scan
    pii_findings = detect_simulated_pii(clean_text)

    return {
        "analysis_type": analysis_type,
        "word_count": word_count,
        "char_count": char_count,
        "sentence_count": sentence_count,
        "summary": summary,
        "keywords": top_keywords,
        "sentiment": sentiment,
        "sentiment_score": sentiment_score,
        "lexical_diversity_pct": lexical_diversity,
        "readability_index": readability,
        "pii_detected": pii_findings
    }


def execute_ai_research_task(
    user: Dict[str, Any],
    input_text: str,
    analysis_type: str = "Standard NLP",
    max_keywords: int = 5,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Protected AI Execution Service Entry Point.
    Enforces server-side authorization check before executing the simulated AI pipeline.
    """
    user_role = user.get("role", "")
    username = user.get("username", "anonymous")
    user_id = user.get("user_id", None)

    # 1. STRICT SERVER-SIDE AUTHORIZATION CHECK
    if not has_permission(user_role, Permission.RUN_AI.value):
        log_event(
            AuditEvent.AI_TASK_DENIED,
            f"Unauthorized AI execution attempt by user '{username}' (Role: '{user_role}')",
            user_id=user_id,
            username=username,
            status="DENIED",
            db_path=db_path
        )
        raise PermissionError(
            f"Access Denied: Role '{user_role}' is not authorized to execute AI operations. Required permission: '{Permission.RUN_AI.value}'."
        )

    # 2. RUN DETERMINISTIC SIMULATION
    result = analyze_text_deterministic(input_text, analysis_type=analysis_type, max_keywords=max_keywords)

    # 3. RECORD AUDIT EVENT
    log_event(
        AuditEvent.AI_TASK_EXECUTED,
        f"User '{username}' executed simulated AI pipeline '{analysis_type}' ({result['word_count']} words)",
        user_id=user_id,
        username=username,
        status="SUCCESS",
        db_path=db_path
    )

    # 4. PERSIST EXPERIMENT RUN IN DATABASE
    snippet = (input_text[:120] + "...") if len(input_text) > 120 else input_text
    insert_ai_experiment(
        user_id=user_id if user_id else "UNKNOWN",
        username=username,
        analysis_type=analysis_type,
        input_snippet=snippet,
        summary_output=result["summary"],
        metrics_json=json.dumps({
            "word_count": result["word_count"],
            "sentiment": result["sentiment"],
            "readability": result["readability_index"],
            "pii_count": len(result["pii_detected"])
        }),
        db_path=db_path
    )

    return result
