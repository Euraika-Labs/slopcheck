from __future__ import annotations

from pathlib import Path

from slopcheck.config import AppConfig, IdorRiskConfig
from slopcheck.rules.generic.idor_risk import IdorRiskRule


def _scan(content: str, path: str = "views/api_handler.py") -> list:
    rule = IdorRiskRule()
    return rule.scan_file(
        repo_root=Path("/repo"),
        relative_path=path,
        content=content,
        config=AppConfig(),
    )


# ── Positive cases ────────────────────────────────────────────────────────────

def test_request_args_then_db_query_no_auth() -> None:
    code = (
        "def get_document(request):\n"
        "    doc_id = request.args.get('id')\n"
        "    doc = db.query(Document).filter_by(id=doc_id).first()\n"
        "    return jsonify(doc)\n"
    )
    findings = _scan(code)
    assert len(findings) == 1
    assert "IDOR" in findings[0].message or "authorization" in findings[0].message.lower()


def test_request_params_then_session_query() -> None:
    code = (
        "def view_record(request):\n"
        "    record_id = request.params['id']\n"
        "    record = session.query(Record).get(record_id)\n"
        "    return record\n"
    )
    findings = _scan(code)
    assert len(findings) == 1


def test_request_GET_then_execute() -> None:
    code = (
        "def fetch(request):\n"
        "    user_id = request.GET['user']\n"
        "    result = db.execute('SELECT * FROM users WHERE id = ?', [user_id])\n"
        "    return result\n"
    )
    findings = _scan(code)
    assert len(findings) == 1


def test_express_req_params_then_find() -> None:
    code = (
        "async function getUser(req, res) {\n"
        "  const id = req.params.id;\n"
        "  const user = await User.findById(id);\n"
        "  res.json(user);\n"
        "}\n"
    )
    findings = _scan(code, path="routes/api.ts")
    assert len(findings) == 1


# ── Negative cases ────────────────────────────────────────────────────────────

def test_request_args_with_current_user_check() -> None:
    code = (
        "def get_document(request):\n"
        "    doc_id = request.args.get('id')\n"
        "    if current_user.id != doc_id:\n"
        "        raise PermissionError()\n"
        "    doc = db.query(Document).filter_by(id=doc_id).first()\n"
        "    return doc\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_request_args_with_verify_owner() -> None:
    code = (
        "def get_item(request):\n"
        "    item_id = request.args['id']\n"
        "    verify_owner(request.user, item_id)\n"
        "    item = db.query(Item).get(item_id)\n"
        "    return item\n"
    )
    findings = _scan(code)
    assert len(findings) == 0


def test_skips_non_route_files() -> None:
    """File path does not contain route/view/handler/api."""
    code = (
        "def process(request):\n"
        "    doc_id = request.args.get('id')\n"
        "    doc = db.query(Doc).filter_by(id=doc_id).first()\n"
        "    return doc\n"
    )
    findings = _scan(code, path="services/processor.py")
    assert len(findings) == 0


def test_skips_non_supported_extension() -> None:
    code = (
        "doc_id = request.args.get('id')\n"
        "doc = db.query(Doc).filter_by(id=doc_id).first()\n"
    )
    findings = _scan(code, path="views/handler.go")
    assert len(findings) == 0


def test_disabled_rule() -> None:
    config = AppConfig()
    config.rules.idor_risk = IdorRiskConfig(enabled=False)
    rule = IdorRiskRule()
    findings = rule.scan_file(
        repo_root=Path("/repo"),
        relative_path="views/api.py",
        content=(
            "doc_id = request.args.get('id')\n"
            "doc = db.query(Doc).filter_by(id=doc_id).first()\n"
        ),
        config=config,
    )
    assert len(findings) == 0


def test_confidence_is_low() -> None:
    code = (
        "def get_document(request):\n"
        "    doc_id = request.args.get('id')\n"
        "    doc = db.query(Document).filter_by(id=doc_id).first()\n"
        "    return doc\n"
    )
    findings = _scan(code)
    assert findings[0].confidence.value == "low"
