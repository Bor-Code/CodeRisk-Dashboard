import os
import urllib.request
import zipfile

BIN_DIR = "bin"
os.makedirs(BIN_DIR, exist_ok=True)

# OSV-Scanner
osv_url = (
    "https://github.com/google/osv-scanner/releases/download/v1.9.0/osv-scanner_windows_amd64.exe"
)
osv_path = os.path.join(BIN_DIR, "osv-scanner.exe")
if not os.path.exists(osv_path):
    print("Downloading OSV-Scanner...")
    urllib.request.urlretrieve(osv_url, osv_path)
    print("OSV-Scanner downloaded.")

# Gitleaks
gitleaks_zip = os.path.join(BIN_DIR, "gitleaks.zip")
gitleaks_exe = os.path.join(BIN_DIR, "gitleaks.exe")
gitleaks_url = (
    "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_windows_x64.zip"
)

if not os.path.exists(gitleaks_exe):
    print("Downloading Gitleaks...")
    urllib.request.urlretrieve(gitleaks_url, gitleaks_zip)
    print("Extracting Gitleaks...")
    with zipfile.ZipFile(gitleaks_zip, "r") as zip_ref:
        zip_ref.extract("gitleaks.exe", BIN_DIR)
    os.remove(gitleaks_zip)
    print("Gitleaks extracted.")

print("Engines installed successfully.")
