# rule_118_translate_codepage.py
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(title="Rule 118 — TRANSLATE with obsolete CODE PAGE", version="1.1")

# -----------------------------------------------------------------------------
# Models (same shape you’ve been using)
# -----------------------------------------------------------------------------
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    # results key added dynamically: rule118_findings

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def line_of_offset(text: str, off: int) -> int:
    """Return 1-based line number for a 0-based character offset."""
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    """Return a small context window with escaped newlines for JSON safety."""
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def strip_inline_quotes(s: str) -> str:
    """
    Remove ABAP inline comments that start with a double quote (") until EOL.
    Does not touch single quotes within literals.
    """
    return re.sub(r'".*?(?=\n|$)', '', s)

def strip_full_line_star_comments(s: str) -> str:
    """
    Remove lines that are full-line comments beginning with optional spaces then '*'.
    """
    return re.sub(r'(?m)^\s*\*.*$', '', s)

def cleaned_stmt(stmt: str) -> str:
    """
    Produce a comment-free version of a single ABAP statement for semantic checks:
    - Remove full-line '*' comments
    - Remove inline '"' comments
    """
    no_stars = strip_full_line_star_comments(stmt)
    no_inline = strip_inline_quotes(no_stars)
    return no_inline

def is_entirely_commented(stmt: str) -> bool:
    """
    True if the statement contains no non-comment code (only whitespace/comments).
    """
    # Remove full-line and inline comments, then see if anything code-like remains
    return cleaned_stmt(stmt).strip() == ""

# -----------------------------------------------------------------------------
# Detection (statement-scoped, multi-line safe, comment-aware)
# -----------------------------------------------------------------------------
# Capture ONE ABAP statement beginning with TRANSLATE and ending at period.
STMT_RE       = re.compile(r"(?is)\bTRANSLATE\b[^.]*\.", re.DOTALL)

# Within a statement (after comment cleaning) detect patterns:
HAS_CODEPAGE  = re.compile(r"(?i)\bCODE\s+PAGE\b")
LEGACY_CP     = re.compile(r"(?i)\bCODE\s+PAGE\s+(CP1|CP2)\b")
FROM_CP       = re.compile(r"(?i)\bFROM\s+CODE\s+PAGE\b")
TO_CP         = re.compile(r"(?i)\bTO\s+CODE\s+PAGE\b")

# Heuristics for non-character risk
HEX_LITERAL   = re.compile(r"(?i)\bx'[0-9a-f]+'\b")
LIKELY_XVAR   = re.compile(r"(?i)\b(lx_|xstr|xstring)\w*\b")

def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in STMT_RE.finditer(src):
        stmt_raw = m.group(0)
        start, end = m.start(), m.end()

        # Skip statements that are fully commented out
        if is_entirely_commented(stmt_raw):
            continue

        # Use comment-free version for classification; keep raw for snippet and line calc
        stmt = cleaned_stmt(stmt_raw)

        has_codepage = HAS_CODEPAGE.search(stmt) is not None
        legacy_cp    = LEGACY_CP.search(stmt) is not None
        has_from     = FROM_CP.search(stmt) is not None
        has_to       = TO_CP.search(stmt) is not None

        # Heuristic non-character risk indicators
        non_char_risk = (HEX_LITERAL.search(stmt) is not None) or (LIKELY_XVAR.search(stmt) is not None)

        # 1) Obsolete CODE PAGE usage (always warn)
        if has_codepage:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "TranslateObsoleteCodepage",
                "severity": "warning",
                "line": line_of_offset(src, start),
                "message": "TRANSLATE uses CODE PAGE option (legacy/obsolete). Prefer FROM/TO CODE PAGE or CL_ABAP_CONV_CODEPAGE.",
                "suggestion": (
                    "Example (modern):\n"
                    "  TRANSLATE lv_text FROM CODE PAGE 'UTF-8' TO CODE PAGE 'UTF-16'.\n"
                    "Or use CL_ABAP_CONV_CODEPAGE for robust conversions."
                ),
                "snippet": snippet_at(src, start, end),
            })

        # 2) CP1/CP2 legacy pages (warn) — strictly within this statement
        if legacy_cp:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "TranslateLegacyCp1Cp2",
                "severity": "warning",
                "line": line_of_offset(src, start),
                "message": "TRANSLATE references CP1/CP2 (legacy code pages).",
                "suggestion": "Use explicit Unicode pages (e.g., 'UTF-8', 'UTF-16') or CL_ABAP_CONV_CODEPAGE.",
                "snippet": snippet_at(src, start, end),
            })

        # 3) If CODE PAGE present but no FROM/TO at all (info)
        if has_codepage and not (has_from or has_to):
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "TranslateMissingFromTo",
                "severity": "info",
                "line": line_of_offset(src, start),
                "message": "TRANSLATE with CODE PAGE should specify FROM CODE PAGE and/or TO CODE PAGE explicitly.",
                "suggestion": "Add FROM CODE PAGE <src> and/or TO CODE PAGE <dst> (e.g., 'UTF-8').",
                "snippet": snippet_at(src, start, end),
            })

        # 4) Heuristic non-character operand risk (info)
        if non_char_risk:
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "TranslateNonCharacterRisk",
                "severity": "info",
                "line": line_of_offset(src, start),
                "message": "TRANSLATE appears to operate on non-character/hex-like data. Ensure character-type variables for code page conversions.",
                "suggestion": "Use character-type variables (STRING/CHAR) or convert via CL_ABAP_CONV_CODEPAGE.",
                "snippet": snippet_at(src, start, end),
            })

    obj = unit.model_dump()
    obj["rule118_findings"] = findings
    return obj

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.post("/remediate-array")
async def scan_rule(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.get("rule118_findings"):
            results.append(res)
    return results

@app.get("/health")
async def health():
    return {"ok": True, "rule": 118}
