"""Input sanitization + uploaded-file validation + contract validation helpers."""

import io
import re
from typing import Optional

import bleach
import pandas as pd
from fastapi import HTTPException

# ``python-magic`` needs libmagic on the OS.  In production the Dockerfile
# installs ``libmagic1``; in some transient preview pods it can be missing
# and would otherwise crash the whole app on import.  We degrade gracefully:
# the extension + size guards below are the primary defense; MIME sniffing
# is an extra hardening layer that we skip when the library is unavailable.
try:
    import magic  # type: ignore

    _HAS_MAGIC = True
except (ImportError, OSError) as _magic_err:
    magic = None  # type: ignore
    _HAS_MAGIC = False
    print(
        f"WARNING: python-magic unavailable ({_magic_err}); MIME sniffing disabled, extension/size checks still active."
    )


def sanitize_input(value: str, max_length: int = 255, allow_html: bool = False) -> str:
    """Strip HTML/control chars, clip length — for any user-supplied text."""
    if not isinstance(value, str):
        value = str(value)
    value = value[:max_length]
    if not allow_html:
        value = bleach.clean(value, tags=[], attributes={}, strip=True)
    value = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", value)
    return value.strip()


def safe_str(value) -> str:
    """Coerce an Excel cell value to a trimmed string; NaN/None becomes ''."""
    if pd.isna(value) or value is None:
        return ""
    str_val = str(value).strip()
    return "" if str_val == "nan" else str_val


# Leading bytes of the two Excel container formats: OOXML (.xlsx) is a zip archive,
# legacy BIFF (.xls) an OLE2 compound document.
_ZIP_MAGIC = b"PK\x03\x04"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def read_excel_upload(contents: bytes, filename: str) -> pd.DataFrame:
    """Parse uploaded Excel bytes into a DataFrame, picking the engine by file content.

    Sniffing the content rather than trusting the extension also handles files whose
    extension doesn't match their format (e.g. an .xlsx saved under an .xls name).
    """
    if contents.startswith(_ZIP_MAGIC):
        engine = "openpyxl"
    elif contents.startswith(_OLE_MAGIC):
        engine = "xlrd"
    else:
        raise HTTPException(
            status_code=400,
            detail="Die Datei ist keine gültige Excel-Datei (.xlsx oder .xls). "
            "Bitte in Excel öffnen und erneut als Excel-Arbeitsmappe speichern.",
        )
    try:
        return pd.read_excel(io.BytesIO(contents), engine=engine)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading Excel file: {str(e)}")


def validate_uploaded_file(file_content: bytes, filename: str, max_size_mb: int = 10, allowed_types: list = None):
    """Validate uploaded file (size, extension, MIME type)."""
    if len(file_content) > max_size_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File too large. Maximum {max_size_mb}MB allowed")

    allowed_extensions = {".pdf", ".xlsx", ".xls"} if allowed_types is None else set(allowed_types)
    file_ext = filename.lower().split(".")[-1] if "." in filename else ""
    if f".{file_ext}" not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type not allowed. Allowed: {allowed_extensions}")

    # MIME sniffing is optional — only runs if libmagic is available on the host.
    if not _HAS_MAGIC:
        return True

    try:
        # OOXML (.xlsx) files are zip containers whose identifying central-directory
        # entries often sit past 2KB, so libmagic needs a bigger sniff window than a
        # PDF's %PDF- header (byte 0) does - 2048 was misidentifying valid .xlsx
        # uploads as generic application/zip and rejecting them.
        mime_type = magic.from_buffer(file_content[:8192], mime=True)
        # Excel files are accepted in either container format regardless of extension
        # (read_excel_upload picks the parser by content). libmagic reports legacy .xls
        # files as vnd.ms-excel, CDFV2 or x-ole-storage depending on its version and on
        # which program wrote the file.
        excel_mimes = {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-excel",
            "application/CDFV2",
            "application/x-ole-storage",
        }
        expected_mimes = {
            ".pdf": {"application/pdf"},
            ".xlsx": excel_mimes,
            ".xls": excel_mimes,
        }
        expected = expected_mimes.get(f".{file_ext}")
        if expected and mime_type not in expected:
            raise HTTPException(
                status_code=400,
                detail=f"File content doesn't match extension. Expected: {sorted(expected)}, Got: {mime_type}",
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
    nutzung_einhaltung = fields.get("NutzungEinhaltung") == "/Yes"
    nutzung_kenntnisnahme_field = fields.get("NutzungKenntnisnahme") or fields.get("NutzungKenntnisname", "")
    nutzung_kenntnisnahme = nutzung_kenntnisnahme_field == "/Yes" or bool(
        nutzung_kenntnisnahme_field and nutzung_kenntnisnahme_field not in ["", "/Off"]
    )
    ausgabe_neu = fields.get("ausgabeNeu") == "/Yes"
    ausgabe_gebraucht = fields.get("ausgabeGebraucht") == "/Yes"
    nutzung_ok = nutzung_einhaltung and nutzung_kenntnisnahme
    ausgabe_ok = ausgabe_neu != ausgabe_gebraucht  # XOR
    return nutzung_ok and ausgabe_ok
