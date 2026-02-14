# Backend-Version des Vertragsgenerators für die API
# Erstellt verschlüsselte ZIP-Archive mit ausgefüllten PDF-Verträgen

import os
import io
from datetime import datetime
import pandas as pd
from pypdf import PdfReader, PdfWriter
import pikepdf
import pyzipper
import logging
import tempfile
import zipfile

# Logger einrichten
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pfad zur Vorlage
TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PDF_NAME = "templates/Muster.pdf"

def get_template_path():
    """Ermittelt den Pfad zur PDF-Vorlage."""
    return os.path.join(TEMPLATE_DIR, TEMPLATE_PDF_NAME)

def create_single_contract(row_data: dict, template_bytes: bytes) -> tuple:
    """
    Erstellt einen einzelnen Vertrag als verschlüsseltes ZIP-Archiv.
    
    Args:
        row_data: Dictionary mit den Daten für den Vertrag
        template_bytes: Bytes der PDF-Vorlage
        
    Returns:
        Tuple von (zip_filename, zip_bytes) oder (None, error_message) bei Fehler
    """
    try:
        def get_val(col_name, default=''):
            val = row_data.get(col_name, default)
            if pd.isna(val) if hasattr(pd, 'isna') else val is None:
                return default
            if isinstance(val, datetime):
                return val.strftime('%d.%m.%Y')
            return str(val)
        
        # Dateiname erstellen
        sus_kl = get_val('sus_kl') or get_val('SuSKl')
        sus_nachn = get_val('sus_nachn') or get_val('SuSNachn')
        sus_vorn = get_val('sus_vorn') or get_val('SuSVorn')
        sus_geb = get_val('sus_geb') or get_val('SuSGeb')
        
        if not all([sus_kl, sus_nachn, sus_vorn]):
            return None, f"Unvollständige Daten: Klasse={sus_kl}, Nachname={sus_nachn}, Vorname={sus_vorn}"
        
        pdf_filename = f"{sus_kl}_{sus_nachn}_{sus_vorn}.pdf"
        zip_filename = f"{sus_kl}_{sus_nachn}_{sus_vorn}.zip"
        
        # PDF mit Formularfeldern füllen
        intermediate_buffer = io.BytesIO()
        reader = PdfReader(io.BytesIO(template_bytes))
        writer = PdfWriter()
        writer.append(reader)
        
        # Formularfelder auslesen und befüllen
        all_fields_map = writer.get_fields() or {}
        data_to_fill = {field_name: "" for field_name in all_fields_map.keys()}
        
        # Mapping: Excel-Spalten zu PDF-Feldern
        field_mapping = {
            'sus_vorn': 'SuSVorn',
            'sus_nachn': 'SuSNachn', 
            'sus_kl': 'SuSKl',
            'sus_geb': 'SuSGeb',
            'sus_str_hnr': 'SuSStrHNr',
            'sus_plz': 'SuSPLZ',
            'sus_ort': 'SuSOrt',
            'erz1_vorn': 'Erz1Vorn',
            'erz1_nachn': 'Erz1Nachn',
            'erz1_str_hnr': 'Erz1StrHNr',
            'erz1_plz': 'Erz1PLZ',
            'erz1_ort': 'Erz1Ort',
            'erz2_vorn': 'Erz2Vorn',
            'erz2_nachn': 'Erz2Nachn',
            'erz2_str_hnr': 'Erz2StrHNr',
            'erz2_plz': 'Erz2PLZ',
            'erz2_ort': 'Erz2Ort',
            'itnr': 'ITNr',
            'snr': 'SNr',
            'typ': 'Typ',
            'pencil': 'Pencil',
            'ansch_jahr': 'AnschJahr',
            'ausleihe_datum': 'AusleiheDatum',
        }
        
        for field_name in all_fields_map:
            field_name_lower = field_name.lower()
            # Versuche Match mit row_data (lowercase keys)
            for row_key, excel_key in field_mapping.items():
                if excel_key.lower() in field_name_lower or row_key in field_name_lower:
                    value = row_data.get(row_key, '') or row_data.get(excel_key, '')
                    if value and not (hasattr(pd, 'isna') and pd.isna(value)):
                        data_to_fill[field_name] = str(value) if not isinstance(value, datetime) else value.strftime('%d.%m.%Y')
                    break
        
        # Formularfelder aktualisieren
        for page in writer.pages:
            writer.update_page_form_field_values(page, data_to_fill, auto_regenerate=True)
        
        writer.write(intermediate_buffer)
        intermediate_buffer.seek(0)
        
        # PDF-Felder schreibschützen
        pdf_final_buffer = io.BytesIO()
        with pikepdf.Pdf.open(intermediate_buffer) as final_pdf:
            if hasattr(final_pdf.Root, 'AcroForm') and final_pdf.Root.AcroForm and hasattr(final_pdf.Root.AcroForm, 'Fields'):
                for field in final_pdf.Root.AcroForm.Fields:
                    field.Ff = 1  # Read-only flag
            final_pdf.save(pdf_final_buffer)
        
        # ZIP mit Passwort erstellen (Geburtsdatum als Passwort)
        zip_password = sus_geb
        if not zip_password:
            # Ohne Passwort erstellen wenn kein Geburtsdatum vorhanden
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(pdf_filename, pdf_final_buffer.getvalue())
            return zip_filename, zip_buffer.getvalue()
        
        # Mit AES-Verschlüsselung
        zip_buffer = io.BytesIO()
        with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(zip_password.encode('utf-8'))
            zf.writestr(pdf_filename, pdf_final_buffer.getvalue())
        
        return zip_filename, zip_buffer.getvalue()
        
    except Exception as e:
        logger.error(f"Fehler bei Vertragserstellung: {e}", exc_info=True)
        return None, str(e)


def create_contracts_from_assignments(assignments_data: list) -> tuple:
    """
    Erstellt Verträge für eine Liste von Zuordnungen.
    
    Args:
        assignments_data: Liste von Dictionaries mit Zuordnungsdaten
                         (kombinierte Student + iPad Daten)
    
    Returns:
        Tuple von (combined_zip_bytes, success_count, error_count, errors)
    """
    template_path = get_template_path()
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Die Vorlagendatei '{template_path}' wurde nicht gefunden.")
    
    with open(template_path, "rb") as f:
        template_bytes = f.read()
    
    success_count = 0
    error_count = 0
    errors = []
    created_zips = []
    
    for idx, assignment in enumerate(assignments_data):
        try:
            zip_filename, result = create_single_contract(assignment, template_bytes)
            if zip_filename:
                created_zips.append((zip_filename, result))
                success_count += 1
                logger.info(f"Vertrag erstellt: {zip_filename}")
            else:
                error_count += 1
                errors.append(f"Zeile {idx + 1}: {result}")
        except Exception as e:
            error_count += 1
            errors.append(f"Zeile {idx + 1}: {str(e)}")
            logger.error(f"Fehler bei Zeile {idx + 1}: {e}")
    
    # Alle ZIPs in ein großes ZIP packen
    combined_zip_buffer = io.BytesIO()
    with zipfile.ZipFile(combined_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as combined_zip:
        for zip_filename, zip_bytes in created_zips:
            combined_zip.writestr(zip_filename, zip_bytes)
    
    return combined_zip_buffer.getvalue(), success_count, error_count, errors


def create_contracts_from_excel(excel_bytes: bytes, filename: str) -> tuple:
    """
    Erstellt Verträge aus einer Excel-Datei.
    
    Args:
        excel_bytes: Bytes der Excel-Datei
        filename: Name der Datei für Engine-Auswahl
    
    Returns:
        Tuple von (combined_zip_bytes, success_count, error_count, errors)
    """
    # Excel einlesen
    if filename.lower().endswith('.xlsx'):
        df = pd.read_excel(io.BytesIO(excel_bytes), engine='openpyxl')
    else:
        df = pd.read_excel(io.BytesIO(excel_bytes), engine='xlrd')
    
    # DataFrame in Liste von Dicts konvertieren
    assignments_data = df.to_dict('records')
    
    return create_contracts_from_assignments(assignments_data)
