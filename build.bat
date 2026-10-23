
@echo off
setlocal
title Rust EXE Builder
color 0B

echo ========================================
echo       RUST TO EXE - AUTO BUILDER
echo ========================================
echo.

:: Pastikan Cargo.toml tersedia
if not exist "Cargo.toml" (
    echo [ERROR] Cargo.toml tidak ditemukan!
    echo Simpan file BAT ini di folder proyek Rust.
    goto :error
)

:: Muat environment Rust jika tersedia
if exist "%USERPROFILE%\.cargo\env.bat" (
    call "%USERPROFILE%\.cargo\env.bat"
)

:: Periksa Cargo
where cargo >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Rust/Cargo belum terdeteksi.
    echo Install Rust dari https://rustup.rs/
    goto :error
)

echo [1/3] Memeriksa konfigurasi proyek...
cargo metadata --no-deps --format-version 1 >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Konfigurasi proyek tidak valid.
    echo Periksa Cargo.toml dan struktur src.
    goto :error
)

echo.
echo [2/3] Building EXE mode RELEASE...
echo Mohon tunggu, proses pertama bisa lebih lama.
echo.

cargo build --release
if errorlevel 1 (
    echo.
    echo [ERROR] Build gagal. Periksa pesan error di atas.
    goto :error
)

echo.
echo [3/3] Build berhasil!
echo.

:: Cari nama binary dari konfigurasi Cargo
for /f "delims=" %%I in ('cargo metadata --no-deps --format-version 1 ^| powershell -NoProfile -Command "$input | ConvertFrom-Json | ForEach-Object { $_.packages | Where-Object { $_.source -eq $null -and $_.manifest_path -like ('*' + [IO.Path]::DirectorySeparatorChar + 'Cargo.toml') } | Select-Object -First 1 -ExpandProperty targets | Where-Object { $_.kind -contains 'bin' } | Select-Object -First 1 -ExpandProperty name }"') do set "BIN_NAME=%%I"

if defined BIN_NAME (
    if exist "target\release\%BIN_NAME%.exe" (
        echo File EXE:
        echo %CD%\target\release\%BIN_NAME%.exe
        echo.
        explorer /select,"%CD%\target\release\%BIN_NAME%.exe"
        goto :success
    )
)

echo Build selesai, tetapi file EXE tidak ditemukan di lokasi default.
echo Periksa folder target\release.
goto :success

:success
echo ========================================
echo             SELESAI
echo ========================================
pause
exit /b 0

:error
echo.
pause
exit /b 1
