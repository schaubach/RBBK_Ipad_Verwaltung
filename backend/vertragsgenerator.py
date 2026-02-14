# HINWEIS: Dieses Skript benötigt externe Bibliotheken.
# Bitte installieren Sie diese vor der Ausführung mit dem folgenden Befehl:
# pip install ttkbootstrap pandas pypdf pikepdf pyzipper

import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
import threading
import os
import sys
import io
from datetime import datetime
import pandas as pd
from pypdf import PdfReader, PdfWriter
import pikepdf
import pyzipper
import logging # Logging-Modul importiert

# =================================================================================
# LOGGING-KONFIGURATION
# =================================================================================

def get_base_path():
    """Ermittelt den Basis-Pfad des Skripts oder der .exe-Datei."""
    if getattr(sys, 'frozen', False):
        # Pfad, wenn als .exe ausgeführt
        return os.path.dirname(sys.executable)
    else:
        # Pfad, wenn als .py-Skript ausgeführt
        return os.path.dirname(os.path.abspath(__file__))

# Logger einrichten
LOG_FILE_PATH = os.path.join(get_base_path(), "vertragsgenerator.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE_PATH, encoding='utf-8'),
        # Optional: logging.StreamHandler() # Um Logs auch in der Konsole zu sehen
    ]
)

logging.info("Anwendung gestartet.")

# --- Konstanten ---
TEMPLATE_PDF_NAME = "Muster.pdf" # Die Vorlage muss im selben Ordner wie das Skript liegen.

# =================================================================================
# VERARBEITUNGSLOGIK
# =================================================================================

def get_template_path():
    """Ermittelt den plattformunabhängigen Pfad zur PDF-Vorlage."""
    if getattr(sys, 'frozen', False):
        # Wenn das Skript als .exe ausgeführt wird, ist der Basispfad sys._MEIPASS
        return os.path.join(sys._MEIPASS, TEMPLATE_PDF_NAME)
    else:
        # Im normalen Modus ist es der Ordner der Skript-Datei
        #base_path = os.path.dirname(os.path.abspath(__file__))
        #template_path = os.path.join(base_path, "Muster.pdf")
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), TEMPLATE_PDF_NAME)

def create_and_zip_contracts(excel_file, output_folder, progress_callback):
    """Liest Excel, füllt PDFs und speichert jede PDF in einem eigenen, verschlüsselten ZIP-Archiv."""
    logging.info(f"Vertragserstellung gestartet. Excel-Datei: '{excel_file}', Speicherordner: '{output_folder}'")
    template_path = get_template_path()
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Die Vorlagendatei '{TEMPLATE_PDF_NAME}' wurde nicht gefunden.")

    with open(template_path, "rb") as f:
        template_bytes = f.read()

    df = pd.read_excel(excel_file)
    total_rows = len(df)
    logging.info(f"{total_rows} Zeilen in der Excel-Datei gefunden.")

    for index, row in df.iterrows():
        try:
            def get_val(col_name, default=''):
                val = row.get(col_name, default)
                if pd.isna(val): return default
                if isinstance(val, datetime): return val.strftime('%d.%m.%Y')
                return str(val)

            pdf_filename = f"{get_val('SuSKl')}_{get_val('SuSNachn')}_{get_val('SuSVorn')}.pdf"
            if not all([get_val('SuSKl'), get_val('SuSNachn'), get_val('SuSVorn')]):
                raise KeyError(f"Spalten für Dateinamen (SuSKl, SuSNachn, SuSVorn) in Zeile {index + 2} unvollständig.")

            base_filename = os.path.splitext(pdf_filename)[0]
            zip_filename = f"{base_filename}.zip"

            status_text = f"Verarbeite {index + 1}/{total_rows}: {zip_filename}"
            progress_callback(index + 1, total_rows, status_text)

            intermediate_buffer = io.BytesIO()
            reader = PdfReader(io.BytesIO(template_bytes))
            writer = PdfWriter()
            writer.append(reader)

            all_fields_map = writer.get_fields() or {}
            data_to_fill = {field_name: "" for field_name in all_fields_map.keys()}
            
            for field_name in all_fields_map:
                field_name_lower = field_name.lower()
                for col_header in df.columns:
                    if col_header.lower() in field_name_lower:
                        data_to_fill[field_name] = get_val(col_header)
                        break
            
            for page in writer.pages:
                writer.update_page_form_field_values(page, data_to_fill, auto_regenerate=True)

            writer.write(intermediate_buffer)
            intermediate_buffer.seek(0)
            
            pdf_final_buffer = io.BytesIO()
            with pikepdf.Pdf.open(intermediate_buffer) as final_pdf:
                for field in final_pdf.Root.AcroForm.Fields:
                    field.Ff = 1
                final_pdf.save(pdf_final_buffer)

            zip_password_str = get_val('SuSGeb')
            if not zip_password_str:
                raise KeyError(f"Passwort-Spalte 'SuSGeb' fehlt oder ist leer in Zeile {index + 2}")

            zip_password_bytes = zip_password_str.encode('utf-8')
            zip_output_path = os.path.join(output_folder, zip_filename)

            with pyzipper.AESZipFile(zip_output_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(zip_password_bytes)
                zf.writestr(pdf_filename, pdf_final_buffer.getvalue())
            
            logging.info(f"Erfolgreich erstellt: {zip_filename}")

        except Exception as e:
            logging.error(f"Fehler bei der Verarbeitung von Zeile {index + 2} der Excel-Datei.", exc_info=True)
            # Re-raise the exception to show it to the user in the messagebox
            raise e

    logging.info(f"Verarbeitung von {total_rows} Verträgen erfolgreich abgeschlossen.")
    progress_callback(total_rows, total_rows, "Verarbeitung erfolgreich abgeschlossen!")
    return total_rows, []


# =================================================================================
# BENUTZEROBERFLÄCHE (GUI-KLASSEN)
# =================================================================================

class App(ttk.Window):
    """Die Hauptanwendung, die als Controller für die Seiten dient."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Vertragsgenerator")
        self.geometry("600x380")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        container = ttk.Frame(self, padding=10)
        container.pack(fill=tk.BOTH, expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.create_page = CreatePage(parent=container, controller=self)
        self.create_page.grid(row=0, column=0, sticky="nsew")

    def on_closing(self):
        logging.info("Anwendung geschlossen.")
        self.destroy()

class ProcessingPage(ttk.Frame):
    """Eine Basisklasse für Seiten, die langlaufende Prozesse ausführen."""
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.grid_columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=3, column=0, columnspan=3, pady=20)

        self.btn_start = ttk.Button(btn_frame, text="Starten", command=self.start_process)
        self.btn_start.pack(side=tk.LEFT, padx=10)

        self.progress_frame = ttk.Frame(self)
        self.progress_frame.grid(row=4, column=0, columnspan=3, sticky='ew', padx=10)
        self.progress_frame.grid_remove()

        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5, expand=True)

        self.status_label = ttk.Label(self.progress_frame, text="Status: Bereit")
        self.status_label.pack(fill=tk.X, pady=5, expand=True)

    def update_progress(self, current, total, message):
        if total > 0:
            self.progress_bar['maximum'] = total
            self.progress_bar['value'] = current
        self.status_label.config(text=message)

    def start_process(self):
        raise NotImplementedError("Diese Methode muss in der Kindklasse überschrieben werden.")

    def _run_thread(self, target_func, success_msg, *args):
        self.btn_start.config(state="disabled")
        self.progress_frame.grid()
        self.progress_bar['value'] = 0
        try:
            total_processed, _ = target_func(*args)
            final_msg = success_msg.format(count=total_processed)
            messagebox.showinfo("Fertig", final_msg)
        except Exception as e:
            # Logge den Fehler, bevor er dem Benutzer angezeigt wird
            logging.error("Ein Fehler ist im Verarbeitungsthread aufgetreten und wurde dem Benutzer angezeigt.", exc_info=True)
            messagebox.showerror("Ein Fehler ist aufgetreten", f"Details: {str(e)}\n\nWeitere Informationen finden Sie in der Datei 'vertragsgenerator.log'.")
        finally:
            self.btn_start.config(state="normal")
            self.status_label.config(text="Status: Bereit")

class CreatePage(ProcessingPage):
    """Die Hauptseite zur Auswahl der Dateien und zum Starten des Erstellungsprozesses."""
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.excel_path = tk.StringVar()
        self.output_dir = tk.StringVar()

        self.btn_start.config(text="Erstellung starten", style="success.TButton")

        lbl_title = ttk.Label(self, text="Verträge erstellen und als ZIP verpacken", font=("-size 16 -weight bold"))
        lbl_title.grid(row=0, column=0, columnspan=3, pady=10, padx=10, sticky='w')

        lbl_excel = ttk.Label(self, text="Excel-Datei:")
        lbl_excel.grid(row=1, column=0, padx=10, pady=10, sticky='w')
        ent_excel = ttk.Entry(self, textvariable=self.excel_path, state='readonly')
        ent_excel.grid(row=1, column=1, padx=10, pady=10, sticky='ew')
        btn_excel = ttk.Button(self, text="Durchsuchen...", command=self.select_excel_file)
        btn_excel.grid(row=1, column=2, padx=10, pady=10)

        lbl_output = ttk.Label(self, text="Speicherordner:")
        lbl_output.grid(row=2, column=0, padx=10, pady=10, sticky='w')
        ent_output = ttk.Entry(self, textvariable=self.output_dir, state='readonly')
        ent_output.grid(row=2, column=1, padx=10, pady=10, sticky='ew')
        btn_output = ttk.Button(self, text="Durchsuchen...", command=self.select_output_dir)
        btn_output.grid(row=2, column=2, padx=10, pady=10)

    def select_excel_file(self):
        path = filedialog.askopenfilename(title="Excel-Datei auswählen", filetypes=(("Excel files", "*.xlsx *.xls"),))
        if path:
            self.excel_path.set(path)
            logging.info(f"Excel-Datei vom Benutzer ausgewählt: {path}")

    def select_output_dir(self):
        path = filedialog.askdirectory(title="Speicherordner auswählen")
        if path:
            self.output_dir.set(path)
            logging.info(f"Speicherordner vom Benutzer ausgewählt: {path}")

    def start_process(self):
        logging.info("Button 'Erstellung starten' geklickt.")
        if not self.excel_path.get() or not self.output_dir.get():
            messagebox.showwarning("Fehlende Eingabe", "Bitte wählen Sie eine Excel-Datei und einen Speicherordner.")
            logging.warning("Erstellung aufgrund fehlender Eingaben abgebrochen.")
            return

        thread = threading.Thread(
            target=self._run_thread,
            args=(
                create_and_zip_contracts,
                "{count} Verträge wurden erfolgreich erstellt und verpackt.",
                self.excel_path.get(),
                self.output_dir.get(),
                self.update_progress
            )
        )
        thread.start()

# =================================================================================
# ANWENDUNG STARTEN
# =================================================================================

if __name__ == "__main__":
    try:
        app = App(themename="litera")
        app.mainloop()
    except Exception as e:
        logging.critical("Ein schwerwiegender, unbehandelter Fehler ist aufgetreten, der die Anwendung beendet hat.", exc_info=True)
        # Optional: Zeige eine finale Fehlermeldung, falls die GUI abstürzt
        # messagebox.showerror("Schwerwiegender Fehler", "Ein unerwarteter Fehler hat die Anwendung beendet. Bitte prüfen Sie die Log-Datei.")