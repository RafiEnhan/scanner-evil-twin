# ============================================================
#  cleanup_tshark.ps1
#  Membersihkan folder bin/tshark/ dari file yang tidak
#  dibutuhkan oleh tshark.exe dalam mode CLI packet capture.
#
#  Penggunaan:
#    .\cleanup_tshark.ps1           -> Preview saja (DRY RUN)
#    .\cleanup_tshark.ps1 -Execute  -> Hapus sungguhan
# ============================================================

param(
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tsharkDir = Join-Path $scriptDir "bin\tshark"

if (-not (Test-Path $tsharkDir)) {
    Write-Host "[ERROR] Folder tidak ditemukan: $tsharkDir" -ForegroundColor Red
    exit 1
}

# Ukuran awal
$sizeBefore = (Get-ChildItem $tsharkDir -Recurse -File | Measure-Object -Property Length -Sum).Sum

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TSHARK FOLDER CLEANUP - Evil Twin Scanner" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Target    : $tsharkDir" -ForegroundColor White
Write-Host "  Mode      : $(if ($Execute) { 'HAPUS SUNGGUHAN' } else { 'DRY RUN (preview)' })" -ForegroundColor $(if ($Execute) { 'Yellow' } else { 'Green' })
Write-Host "  Ukuran awal: $([math]::Round($sizeBefore / 1MB, 1)) MB" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$totalDeleted = 0
$deletedCount = 0

function Remove-Item-Safe {
    param([string]$Path, [string]$Reason)
    if (Test-Path $Path) {
        $size = 0
        if (Test-Path $Path -PathType Container) {
            $size = (Get-ChildItem $Path -Recurse -File | Measure-Object -Property Length -Sum).Sum
        } else {
            $size = (Get-Item $Path).Length
        }
        $sizeKB = [math]::Round($size / 1KB, 0)
        
        Write-Host "  [HAPUS] $(Split-Path $Path -Leaf) ($sizeKB KB) -- $Reason" -ForegroundColor Red
        
        if ($Execute) {
            if (Test-Path $Path -PathType Container) {
                Remove-Item $Path -Recurse -Force
            } else {
                Remove-Item $Path -Force
            }
        }
        $script:totalDeleted += $size
        $script:deletedCount++
    }
}

# ============================================================
# 1. GUI EXECUTABLES -- tidak dipakai (CLI only)
# ============================================================
Write-Host "--- [1] GUI Executables ---" -ForegroundColor Yellow
Remove-Item-Safe "$tsharkDir\Wireshark.exe"    "GUI Wireshark -- tidak dipakai"
Remove-Item-Safe "$tsharkDir\Stratoshark.exe"  "GUI Stratoshark -- tidak dipakai"
Remove-Item-Safe "$tsharkDir\strato.exe"       "CLI Stratoshark -- tidak dipakai"

# ============================================================
# 2. TOOL EXECUTABLES LAIN -- tidak dipanggil dari kode
# ============================================================
Write-Host ""
Write-Host "--- [2] Tool Executables Lain ---" -ForegroundColor Yellow
$unusedExes = @(
    "capinfos.exe", "captype.exe", "editcap.exe", "mergecap.exe",
    "reordercap.exe", "randpkt.exe", "rawshark.exe", "sharkd.exe",
    "text2pcap.exe", "mmdbresolve.exe", "test_epan.exe", "test_wsutil.exe"
)
foreach ($exe in $unusedExes) {
    Remove-Item-Safe "$tsharkDir\$exe" "Tool tidak digunakan dalam proyek"
}

# ============================================================
# 3. EXTCAP EXECUTABLES -- remote capture, tidak dipakai
# ============================================================
Write-Host ""
Write-Host "--- [3] Extcap Executables ---" -ForegroundColor Yellow
$extcapExes = @(
    "androiddump.exe", "ciscodump.exe", "etwdump.exe",
    "randpktdump.exe", "sshdump.exe", "udpdump.exe", "wifidump.exe"
)
foreach ($exe in $extcapExes) {
    Remove-Item-Safe "$tsharkDir\extcap\$exe" "Extcap remote capture -- tidak dipakai"
}

# ============================================================
# 4. Qt6 DLLs -- hanya untuk GUI Wireshark
# ============================================================
Write-Host ""
Write-Host "--- [4] Qt6 DLLs (GUI only) ---" -ForegroundColor Yellow
$qt6Dlls = @(
    "Qt6Core.dll", "Qt6Core5Compat.dll", "Qt6Gui.dll",
    "Qt6Multimedia.dll", "Qt6Network.dll", "Qt6PrintSupport.dll",
    "Qt6Svg.dll", "Qt6Widgets.dll", "WinSparkle.dll"
)
foreach ($dll in $qt6Dlls) {
    Remove-Item-Safe "$tsharkDir\$dll" "Qt6 GUI library -- tidak dipakai"
}

# ============================================================
# 5. DirectX & OpenGL DLLs -- hanya untuk Qt GUI rendering
# ============================================================
Write-Host ""
Write-Host "--- [5] DirectX / OpenGL DLLs ---" -ForegroundColor Yellow
$dxDlls = @("d3dcompiler_47.dll", "opengl32sw.dll", "dxcompiler.dll", "dxil.dll")
foreach ($dll in $dxDlls) {
    Remove-Item-Safe "$tsharkDir\$dll" "DirectX/OpenGL rendering -- Qt GUI only"
}

# ============================================================
# 6. FFmpeg DLLs -- audio/video, bukan packet capture
# ============================================================
Write-Host ""
Write-Host "--- [6] FFmpeg / Audio-Video DLLs ---" -ForegroundColor Yellow
$avDlls = @(
    "avcodec-61.dll", "avformat-61.dll", "avutil-59.dll",
    "swresample-5.dll", "swscale-8.dll"
)
foreach ($dll in $avDlls) {
    Remove-Item-Safe "$tsharkDir\$dll" "FFmpeg audio/video -- VoIP playback only"
}

# ============================================================
# 7. Audio Codec DLLs -- VoIP playback GUI only
# ============================================================
Write-Host ""
Write-Host "--- [7] Audio Codec DLLs ---" -ForegroundColor Yellow
$audioDlls = @(
    "libbcg729.dll", "libilbc-2.dll", "libopencore-amrnb-0.dll",
    "libsbc-1.dll", "libspandsp-2.dll", "libspeexdsp.dll", "opus.dll"
)
foreach ($dll in $audioDlls) {
    Remove-Item-Safe "$tsharkDir\$dll" "Audio codec -- VoIP playback GUI only"
}

# ============================================================
# 8. Qt Subfolder -- GUI plugins
# ============================================================
Write-Host ""
Write-Host "--- [8] Qt Subfolder (GUI only) ---" -ForegroundColor Yellow
$qtFolders = @(
    "iconengines", "imageformats", "multimedia",
    "networkinformation", "platforms", "styles", "translations"
)
foreach ($folder in $qtFolders) {
    Remove-Item-Safe "$tsharkDir\$folder" "Qt GUI plugin folder -- tidak dipakai"
}

# ============================================================
# 9. Falco Plugins -- cloud/container event, tidak relevan
# ============================================================
Write-Host ""
Write-Host "--- [9] Falco Plugins ---" -ForegroundColor Yellow
Remove-Item-Safe "$tsharkDir\plugins\falco"                      "Falco cloud/container plugins -- tidak relevan"
Remove-Item-Safe "$tsharkDir\plugins\4.6\epan\falco-events.dll"  "Falco events dissector -- tidak relevan"

# ============================================================
# 10. Audio Codec Plugins (plugins/4.6/codecs/)
# ============================================================
Write-Host ""
Write-Host "--- [10] Audio Codec Plugins ---" -ForegroundColor Yellow
Remove-Item-Safe "$tsharkDir\plugins\4.6\codecs" "Audio codec plugins -- VoIP playback only"

# ============================================================
# 11. Dokumentasi & File HTML
# ============================================================
Write-Host ""
Write-Host "--- [11] Dokumentasi & HTML ---" -ForegroundColor Yellow
$docFiles = @(
    "COPYING.txt", "README.txt", "README.xml-output",
    "pdml2html.xsl", "ws.css",
    "Wireshark Release Notes.html", "Stratoshark Release Notes.html",
    "tshark.html", "wireshark.html", "wireshark-filter.html",
    "dumpcap.html", "capinfos.html", "captype.html",
    "editcap.html", "mergecap.html", "reordercap.html",
    "randpkt.html", "randpktdump.html", "rawshark.html",
    "sharkd.html", "text2pcap.html", "mmdbresolve.html",
    "androiddump.html", "ciscodump.html", "etwdump.html",
    "falcodump.html", "ipmap.html", "sshdig.html",
    "sshdump.html", "strato.html", "stratoshark.html",
    "udpdump.html", "wifidump.html"
)
foreach ($doc in $docFiles) {
    Remove-Item-Safe "$tsharkDir\$doc" "Dokumentasi -- tidak dibutuhkan runtime"
}
Remove-Item-Safe "$tsharkDir\Wireshark User's Guide" "Folder dokumentasi GUI"

# ============================================================
# SUMMARY
# ============================================================
$totalDeletedMB = [math]::Round($totalDeleted / 1MB, 1)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  File/folder ditandai  : $deletedCount item" -ForegroundColor White
Write-Host "  Estimasi penghematan  : $totalDeletedMB MB" -ForegroundColor White

if ($Execute) {
    $sizeAfter = (Get-ChildItem $tsharkDir -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $sizeAfterMB = [math]::Round($sizeAfter / 1MB, 1)
    $savedMB = [math]::Round(($sizeBefore - $sizeAfter) / 1MB, 1)
    Write-Host "  Ukuran sebelum        : $([math]::Round($sizeBefore / 1MB, 1)) MB" -ForegroundColor White
    Write-Host "  Ukuran setelah        : $sizeAfterMB MB" -ForegroundColor Green
    Write-Host "  Total terhapus        : $savedMB MB" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [SELESAI] Cleanup berhasil!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  INI ADALAH DRY RUN -- tidak ada yang dihapus." -ForegroundColor Green
    Write-Host "  Jalankan dengan flag -Execute untuk menghapus:" -ForegroundColor White
    Write-Host "    .\cleanup_tshark.ps1 -Execute" -ForegroundColor Cyan
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
