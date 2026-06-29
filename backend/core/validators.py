"""Input sanitization + uploaded-file validation + contract validation helpers."""
import re
from typing import Optional

import bleach
import magic
from fastapi import HTTPException


def sanitize_input(value: str, max_length: int = 255, allow_html: bool = False) -> str:
    """Strip HTML/control chars, clip length — for any user-supplied text."""
    if not isinstance(value, str):
        value = str(value)
    value = value[:max_length]
    if not allow_html:
        value = bleach.clean(value, tags=[], attributes={}, strip=True)
    value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
    return value.strip()


def validate_uploaded_file(file_content: bytes, filename: str, max_size_mb: int = 10, allowed_types: list = None):
    """Validate uploaded file (size, extension, MIME type)."""
    if len(file_content) > max_size_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum {max_size_mb}MB allowed")

    allowed_extensions = {'.pdf', '.xlsx', '.xls'} if allowed_types is None else set(allowed_types)
    file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
    if f'.{file_ext}' not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type not allowed. Allowed: {allowed_extensions}")

    try:
        mime_type = magic.from_buffer(file_content[:2048], mime=True)
        expected_mimes = {
            '.pdf': 'application/pdf',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.xls': 'application/vnd.ms-excel',
        }
        expected_mime = expected_mimes.get(f'.{file_ext}')
        if expected_mime and mime_type != expected_mime:
            raise HTTPException(
                status_code=400,
                detail=f"File content doesn't match extension. Expected: {expected_mime}, Got: {mime_type}",
            )
    except HTTPException:
        raise
    except Exception:
        print(f"Warning: Could not validate MIME type for {filename}")

    return True


def is_contract_validated(contract: Optional[dict]) -> bool:
    """True iff contract PDF form fields satisfy the "Vertrag validiert" criteria.

    - Both Nutzungs-Checkboxen müssen angekreuzt sein
    - Genau eine Ausgabe-Checkbox (neu XOR gebraucht) muss angekreuzt sein
    """
    if not contract or not contract.get("form_fields"):
        return False
    fields = contract["form_fields"]
    nutzung_einhaltung = fields.get('NutzungEinhaltung') == '/Yes'
    nutzung_kenntnisnahme_field = fields.get('NutzungKenntnisnahme') or fields.get('NutzungKenntnisname', '')
    nutzung_kenntnisnahme = nutzung_kenntnisnahme_field == '/Yes' or bool(
        nutzung_kenntnisnahme_field and nutzung_kenntnisnahme_field not in ['', '/Off']
    )
    ausgabe_neu = fields.get('ausgabeNeu') == '/Yes'
    ausgabe_gebraucht = fields.get('ausgabeGebraucht') == '/Yes'
    nutzung_ok = nutzung_einhaltung and nutzung_kenntnisnahme
    ausgabe_ok = ausgabe_neu != ausgabe_gebraucht  # XOR
    return nutzung_ok and ausgabe_ok
