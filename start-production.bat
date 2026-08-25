@echo off
echo ==============================================
echo 🚀 CodeRisk Canli (Production) Ortami Baslatiliyor
echo ==============================================

REM Check if Docker is installed
docker --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [HATA] Docker bilgisayarinizda yuklu degil veya calismiyor!
    echo Lutfen https://docs.docker.com/desktop/install/windows-install/ adresinden Docker Desktop kurun.
    pause
    exit /b 1
)

REM Copy .env.production to .env if it doesn't exist
IF NOT EXIST ".env" (
    echo .env dosyasi bulunamadi. .env.production kopyalaniyor...
    copy .env.production .env
)

echo.
echo 📦 Docker Compose ile veritabani ve sunucular kaldiriliyor...
docker compose up -d --build

echo.
echo ✅ Sistem basariyla calistirildi!
echo Frontend erisimi: http://localhost:8080
echo Backend API erisimi: http://localhost:8000
echo Sunuculari durdurmak icin: docker compose down
pause
