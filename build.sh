#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="crashtool"
OUT_EXE="CrashTool.exe"

rm -rf "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR"

cat << 'EOF' > go.mod
module crashtool

go 1.21
EOF

# Standard Windows manifest for UAC elevation, Common Controls v6, and PerMonitorV2 DPI
cat << 'EOF' > app.manifest
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="CrashTool" type="win32"/>
  <description>CrashTool Registry and Dump Utility</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
EOF

# Resource definition for go-winres
cat << 'EOF' > winres.json
{
  "RT_MANIFEST": {
    "#1": {
      "0409": "app.manifest"
    }
  }
}
EOF

# 1. Registry management logic
cat << 'EOF' > registry.go
//go:build windows

package main

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

type RegSetting struct {
	SubKey        string
	ValueName     string
	FriendlyDesc  string
	CustomValue   uint32
	DeleteOnReset bool
	DefaultValue  uint32
	PreSelect     bool
	Hwnd          syscall.Handle
}

var settings = []RegSetting{
	{
		SubKey:        `SYSTEM\CurrentControlSet\Control\GraphicsDrivers`,
		ValueName:     "TdrLevel",
		FriendlyDesc:  "TdrLevel = 1 (Disable GPU TDR recovery)",
		CustomValue:   1,
		DeleteOnReset: true,
		PreSelect:     true,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "CrashDumpEnabled",
		FriendlyDesc: "CrashDumpEnabled = 2 (Kernel memory dump)",
		CustomValue:  2,
		DefaultValue: 7,
		PreSelect:    true,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "AutoReboot",
		FriendlyDesc: "AutoReboot = 1 (Automatically restart on BSOD)",
		CustomValue:  1,
		DefaultValue: 1,
		PreSelect:    false,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "Overwrite",
		FriendlyDesc: "Overwrite = 1 (Overwrite existing dump file)",
		CustomValue:  1,
		DefaultValue: 1,
		PreSelect:    false,
	},
}

func (s RegSetting) applyCustom() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, s.SubKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open/create %s: %w", s.SubKey, err)
	}
	defer k.Close()

	if err := k.SetDWordValue(s.ValueName, s.CustomValue); err != nil {
		return fmt.Errorf("failed to set %s: %w", s.ValueName, err)
	}
	return nil
}

func (s RegSetting) applyDefault() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, s.SubKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open %s: %w", s.SubKey, err)
	}
	defer k.Close()

	if s.DeleteOnReset {
		if err := k.DeleteValue(s.ValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("failed to delete %s: %w", s.ValueName, err)
		}
		return nil
	}

	if err := k.SetDWordValue(s.ValueName, s.DefaultValue); err != nil {
		return fmt.Errorf("failed to restore %s: %w", s.ValueName, err)
	}
	return nil
}

func (s RegSetting) queryStatus() (badge string, isCustom bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, s.SubKey, registry.QUERY_VALUE)
	if err != nil {
		return "[Windows Default]", false
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(s.ValueName)
	if err != nil {
		return "[Windows Default]", false
	}

	v := uint32(val)
	switch {
	case v == s.CustomValue:
		return "[Custom Applied]", true
	case !s.DeleteOnReset && v == s.DefaultValue:
		return fmt.Sprintf("[Windows Default: %d]", s.DefaultValue), false
	default:
		return fmt.Sprintf("[Current: %d]", v), false
	}
}

func applySelectedSettings() error {
	for _, s := range settings {
		if isChecked(s.Hwnd) {
			if err := s.applyCustom(); err != nil {
				return err
			}
		} else {
			if err := s.applyDefault(); err != nil {
				return err
			}
		}
	}
	return nil
}

func restoreAllDefaults() error {
	for _, s := range settings {
		if err := s.applyDefault(); err != nil {
			return err
		}
	}
	return nil
}
EOF

# 2. Crash dump scanning, Save As dialog, and ZIP export logic
cat << 'EOF' > dumps.go
//go:build windows

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	memoryDmpPath = `C:\Windows\MEMORY.DMP`
	minidumpDir   = `C:\Windows\Minidump`

	OFN_OVERWRITEPROMPT = 0x00000002
	OFN_PATHMUSTEXIST   = 0x00000800
	OFN_NOCHANGEDIR     = 0x00000008
)

var (
	comdlg32            = syscall.NewLazyDLL("comdlg32.dll")
	procGetSaveFileName = comdlg32.NewProc("GetSaveFileNameW")
)

type OPENFILENAMEW struct {
	LStructSize       uint32
	HwndOwner         syscall.Handle
	HInstance         syscall.Handle
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        unsafe.Pointer
	DwReserved        uint32
	FlagsEx           uint32
}

type zipResult struct {
	title   string
	message string
	flags   uintptr
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func inspectMemoryDump() (label string, exists bool) {
	info, err := os.Stat(memoryDmpPath)
	if err != nil || info.IsDir() {
		return fmt.Sprintf("Kernel Memory Dump — %s  (Not found)", memoryDmpPath), false
	}
	return fmt.Sprintf(
		"Kernel Memory Dump — %s  (%s, %s)",
		memoryDmpPath,
		formatBytes(info.Size()),
		info.ModTime().Format("2006-01-02 15:04"),
	), true
}

func inspectMinidumps() (label string, exists bool) {
	entries, err := os.ReadDir(minidumpDir)
	if err != nil {
		return fmt.Sprintf("Small Memory Dump (Minidump) — %s\\  (No .dmp files found)", minidumpDir), false
	}

	var count int
	var totalSize int64
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
			count++
			if fi, err := e.Info(); err == nil {
				totalSize += fi.Size()
			}
		}
	}

	if count == 0 {
		return fmt.Sprintf("Small Memory Dump (Minidump) — %s\\  (No .dmp files found)", minidumpDir), false
	}

	return fmt.Sprintf(
		"Small Memory Dump (Minidump) — %s\\  (%d files, %s)",
		minidumpDir,
		count,
		formatBytes(totalSize),
	), true
}

func promptSaveZipPath(owner syscall.Handle) (string, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = `C:\`
	}
	initialDir := filepath.Join(homeDir, "Desktop")
	if _, err := os.Stat(initialDir); err != nil {
		initialDir = homeDir
	}

	defaultName := fmt.Sprintf("CrashDumps_%s.zip", time.Now().Format("20060102_150405"))

	fileBuf := make([]uint16, 32768)
	defaultNameUTF16, _ := syscall.UTF16FromString(defaultName)
	copy(fileBuf, defaultNameUTF16)

	// Double-null terminated filter string
	filterUTF16 := utf16Filter("ZIP Archives (*.zip)", "*.zip", "All Files (*.*)", "*.*")

	ofn := OPENFILENAMEW{
		LStructSize:     uint32(unsafe.Sizeof(OPENFILENAMEW{})),
		HwndOwner:       owner,
		LpstrFilter:     &filterUTF16[0],
		NFilterIndex:    1,
		LpstrFile:       &fileBuf[0],
		NMaxFile:        uint32(len(fileBuf)),
		LpstrInitialDir: utf16Ptr(initialDir),
		LpstrTitle:      utf16Ptr("Save Crash Dumps Archive"),
		Flags:           OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
		LpstrDefExt:     utf16Ptr("zip"),
	}

	ret, _, _ := procGetSaveFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return "", false
	}

	return syscall.UTF16ToString(fileBuf), true
}

func utf16Filter(pairs ...string) []uint16 {
	var out []uint16
	for _, s := range pairs {
		u, _ := syscall.UTF16FromString(s)
		out = append(out, u...)
	}
	out = append(out, 0)
	return out
}

func addFileToZip(zw *zip.Writer, srcPath, zipEntryName string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = zipEntryName
	header.Method = zip.Deflate

	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, f)
	return err
}

func buildCrashDumpZip(zipPath string, includeMemDmp, includeMinidump bool) zipResult {
	outFile, err := os.Create(zipPath)
	if err != nil {
		return zipResult{
			title:   "Compression Error",
			message: fmt.Sprintf("Failed to create zip file:\n%v", err),
			flags:   MB_ICONERROR,
		}
	}

	zw := zip.NewWriter(outFile)
	filesAdded := 0

	cleanupAndFail := func(msg string) zipResult {
		zw.Close()
		outFile.Close()
		os.Remove(zipPath)
		return zipResult{
			title:   "Compression Error",
			message: msg,
			flags:   MB_ICONERROR,
		}
	}

	if includeMemDmp {
		if err := addFileToZip(zw, memoryDmpPath, "MEMORY.DMP"); err != nil {
			return cleanupAndFail(fmt.Sprintf("Failed adding MEMORY.DMP:\n%v", err))
		}
		filesAdded++
	}

	if includeMinidump {
		entries, err := os.ReadDir(minidumpDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
					fullPath := filepath.Join(minidumpDir, e.Name())
					entryPath := filepath.Join("Minidump", e.Name())
					if err := addFileToZip(zw, fullPath, entryPath); err != nil {
						return cleanupAndFail(fmt.Sprintf("Failed adding %s:\n%v", e.Name(), err))
					}
					filesAdded++
				}
			}
		}
	}

	zw.Close()
	outFile.Close()

	if filesAdded == 0 {
		os.Remove(zipPath)
		return zipResult{
			title:   "Nothing Compressed",
			message: "No dump files were found to compress.",
			flags:   MB_ICONWARNING,
		}
	}

	var zipSize string
	if fi, err := os.Stat(zipPath); err == nil {
		zipSize = formatBytes(fi.Size())
	}

	return zipResult{
		title:   "Compression Complete",
		message: fmt.Sprintf("Successfully compressed %d file(s) (%s).\n\nSaved to:\n%s", filesAdded, zipSize, zipPath),
		flags:   MB_ICONINFORMATION,
	}
}
EOF

# 3. Win32 GUI and application entry point
cat << 'EOF' > main.go
//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")

	procRegisterClassExW          = user32.NewProc("RegisterClassExW")
	procCreateWindowExW           = user32.NewProc("CreateWindowExW")
	procDefWindowProcW            = user32.NewProc("DefWindowProcW")
	procGetMessageW               = user32.NewProc("GetMessageW")
	procTranslateMessage          = user32.NewProc("TranslateMessage")
	procDispatchMessageW          = user32.NewProc("DispatchMessageW")
	procPostQuitMessage           = user32.NewProc("PostQuitMessage")
	procSendMessageW              = user32.NewProc("SendMessageW")
	procPostMessageW              = user32.NewProc("PostMessageW")
	procSetWindowTextW            = user32.NewProc("SetWindowTextW")
	procEnableWindow              = user32.NewProc("EnableWindow")
	procMessageBoxW               = user32.NewProc("MessageBoxW")
	procGetDpiForSystem           = user32.NewProc("GetDpiForSystem")
	procAdjustWindowRectEx        = user32.NewProc("AdjustWindowRectEx")
	procSetProcessDpiAwarenessCtx = user32.NewProc("SetProcessDpiAwarenessContext")

	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procMulDiv           = kernel32.NewProc("MulDiv")

	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")

	procInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	WS_OVERLAPPED  = 0x00000000
	WS_CAPTION     = 0x00C00000
	WS_SYSMENU     = 0x00080000
	WS_MINIMIZEBOX = 0x00020000
	WS_VISIBLE     = 0x10000000
	WS_CHILD       = 0x40000000
	WS_TABSTOP     = 0x00010000

	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001
	BS_AUTOCHECKBOX  = 0x00000003
	SS_LEFT          = 0x00000000
	SS_ETCHEDHORZ    = 0x00000010

	WM_DESTROY        = 0x0002
	WM_COMMAND        = 0x0111
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLORBTN    = 0x0135
	WM_SETFONT        = 0x0030
	WM_APP_ZIP_DONE   = 0x8001

	BM_GETCHECK   = 0x00F0
	BM_SETCHECK   = 0x00F1
	BST_UNCHECKED = 0x0000
	BST_CHECKED   = 0x0001

	MB_YESNO           = 0x00000004
	MB_ICONERROR       = 0x00000010
	MB_ICONWARNING     = 0x00000030
	MB_ICONINFORMATION = 0x00000040
	IDYES              = 6

	CW_USEDEFAULT = 0x80000000

	CLEARTYPE_QUALITY = 5
	TRANSPARENT       = 1

	DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ^uintptr(3) // -4

	ID_BTN_APPLY       = 101
	ID_BTN_DEFAULTS    = 102
	ID_BTN_REFRESH     = 103
	ID_BTN_RESTART     = 104
	ID_BTN_SELECT_ALL  = 105
	ID_BTN_SELECT_NONE = 106
	ID_CHK_MEMORYDMP   = 107
	ID_CHK_MINIDUMP    = 108
	ID_BTN_ZIP         = 109
	ID_CHK_REG_BASE    = 200
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type POINT struct{ X, Y int32 }
type RECT struct{ Left, Top, Right, Bottom int32 }

type MSG struct {
	HWnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

var (
	hMainWnd     syscall.Handle
	hChkMemDmp   syscall.Handle
	hChkMinidump syscall.Handle
	hBtnZip      syscall.Handle
	hBgBrush     syscall.Handle
	dpiScale     float64 = 1.0

	lastZipMu  sync.Mutex
	lastZipRes zipResult
)

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func scale(px int32) int32 {
	return int32(float64(px) * dpiScale)
}

func showAlert(hwnd syscall.Handle, title, text string, flags uintptr) uintptr {
	ret, _, _ := procMessageBoxW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(utf16Ptr(text))),
		uintptr(unsafe.Pointer(utf16Ptr(title))),
		flags,
	)
	return ret
}

func setText(hwnd syscall.Handle, text string) {
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16Ptr(text))))
}

func setEnabled(hwnd syscall.Handle, enabled bool) {
	var flag uintptr
	if enabled {
		flag = 1
	}
	procEnableWindow.Call(uintptr(hwnd), flag)
}

func isChecked(hwnd syscall.Handle) bool {
	ret, _, _ := procSendMessageW.Call(uintptr(hwnd), BM_GETCHECK, 0, 0)
	return ret == BST_CHECKED
}

func setChecked(hwnd syscall.Handle, checked bool) {
	state := uintptr(BST_UNCHECKED)
	if checked {
		state = uintptr(BST_CHECKED)
	}
	procSendMessageW.Call(uintptr(hwnd), BM_SETCHECK, state, 0)
}

func initUI() {
	procSetProcessDpiAwarenessCtx.Call(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)

	if dpi, _, _ := procGetDpiForSystem.Call(); dpi > 0 {
		dpiScale = float64(dpi) / 96.0
	}

	icc := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00004000 | 0x00000008, // ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
}

func createModernFont(face string, ptSize, weight int32) syscall.Handle {
	dpi := int32(96 * dpiScale)
	height, _, _ := procMulDiv.Call(uintptr(-ptSize), uintptr(dpi), 72)
	hFont, _, _ := procCreateFontW.Call(
		height, 0, 0, 0,
		uintptr(weight),
		0, 0, 0, 1, 0, 0,
		CLEARTYPE_QUALITY, 0,
		uintptr(unsafe.Pointer(utf16Ptr(face))),
	)
	return syscall.Handle(hFont)
}

func refreshDisplay(usePreSelect bool) {
	for _, s := range settings {
		if s.Hwnd == 0 {
			continue
		}
		badge, isCustom := s.queryStatus()
		setText(s.Hwnd, fmt.Sprintf("%s   —   %s", s.FriendlyDesc, badge))
		if usePreSelect {
			setChecked(s.Hwnd, isCustom || s.PreSelect)
		} else {
			setChecked(s.Hwnd, isCustom)
		}
	}

	if hChkMemDmp != 0 {
		label, ok := inspectMemoryDump()
		setText(hChkMemDmp, label)
		if !ok {
			setChecked(hChkMemDmp, false)
		}
		setEnabled(hChkMemDmp, ok)
	}

	if hChkMinidump != 0 {
		label, ok := inspectMinidumps()
		setText(hChkMinidump, label)
		if !ok {
			setChecked(hChkMinidump, false)
		}
		setEnabled(hChkMinidump, ok)
	}
}

func startAsyncCompression(zipPath string, includeMemDmp, includeMinidump bool) {
	setEnabled(hBtnZip, false)
	setText(hBtnZip, "Compressing...")

	go func() {
		res := buildCrashDumpZip(zipPath, includeMemDmp, includeMinidump)
		lastZipMu.Lock()
		lastZipRes = res
		lastZipMu.Unlock()
		procPostMessageW.Call(uintptr(hMainWnd), WM_APP_ZIP_DONE, 0, 0)
	}()
}

func restartComputer(hwnd syscall.Handle) {
	ret := showAlert(
		hwnd,
		"Confirm Restart",
		"Are you sure you want to restart Windows immediately?\nAny unsaved work will be lost.",
		MB_YESNO|MB_ICONWARNING,
	)
	if ret != IDYES {
		return
	}

	cmd := exec.Command("shutdown", "-r", "-t", "0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		showAlert(hwnd, "Restart Error", fmt.Sprintf("Failed to trigger restart:\n%v", err), MB_ICONERROR)
	}
}

func wndProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case WM_CTLCOLORSTATIC, WM_CTLCOLORBTN:
		hdc := syscall.Handle(wparam)
		procSetBkMode.Call(uintptr(hdc), TRANSPARENT)
		procSetTextColor.Call(uintptr(hdc), 0x001E1E1E)
		return uintptr(hBgBrush)

	case WM_APP_ZIP_DONE:
		setText(hBtnZip, "Zip Selected Dumps")
		setEnabled(hBtnZip, true)

		lastZipMu.Lock()
		res := lastZipRes
		lastZipMu.Unlock()

		showAlert(hwnd, res.title, res.message, res.flags)
		return 0

	case WM_COMMAND:
		switch uint16(wparam & 0xFFFF) {
		case ID_BTN_APPLY:
			if err := applySelectedSettings(); err != nil {
				showAlert(hwnd, "Registry Error", err.Error(), MB_ICONERROR)
			} else {
				refreshDisplay(false)
				showAlert(
					hwnd,
					"Applied",
					"Custom settings applied for checked items (unchecked items set to Windows defaults).\nRestart Windows for changes to take effect.",
					MB_ICONINFORMATION,
				)
			}

		case ID_BTN_DEFAULTS:
			if err := restoreAllDefaults(); err != nil {
				showAlert(hwnd, "Registry Error", err.Error(), MB_ICONERROR)
			} else {
				refreshDisplay(false)
				showAlert(
					hwnd,
					"Defaults Restored",
					"All settings restored to Windows defaults.\nRestart Windows for changes to take effect.",
					MB_ICONINFORMATION,
				)
			}

		case ID_BTN_SELECT_ALL:
			for _, s := range settings {
				setChecked(s.Hwnd, true)
			}

		case ID_BTN_SELECT_NONE:
			for _, s := range settings {
				setChecked(s.Hwnd, false)
			}

		case ID_BTN_REFRESH:
			refreshDisplay(false)

		case ID_BTN_RESTART:
			restartComputer(hwnd)

		case ID_BTN_ZIP:
			incMem := isChecked(hChkMemDmp)
			incMini := isChecked(hChkMinidump)
			if !incMem && !incMini {
				showAlert(hwnd, "No Selection", "Please check at least one crash dump option first.", MB_ICONWARNING)
				return 0
			}
			zipPath, ok := promptSaveZipPath(hwnd)
			if !ok {
				return 0
			}
			startAsyncCompression(zipPath, incMem, incMini)
		}
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wparam, lparam)
	return ret
}

func createControl(parent, hInst, hFont syscall.Handle, class, text string, style uintptr, id int, x, y, w, h int32) syscall.Handle {
	var textPtr uintptr
	if text != "" {
		textPtr = uintptr(unsafe.Pointer(utf16Ptr(text)))
	}
	ret, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		textPtr,
		style,
		uintptr(scale(x)), uintptr(scale(y)), uintptr(scale(w)), uintptr(scale(h)),
		uintptr(parent),
		uintptr(id),
		uintptr(hInst),
		0,
	)
	ctrl := syscall.Handle(ret)
	if hFont != 0 {
		procSendMessageW.Call(uintptr(ctrl), WM_SETFONT, uintptr(hFont), 1)
	}
	return ctrl
}

func addLabel(parent, hInst, hFont syscall.Handle, text string, x, y, w, h int32) syscall.Handle {
	return createControl(parent, hInst, hFont, "STATIC", text, WS_CHILD|WS_VISIBLE|SS_LEFT, 0, x, y, w, h)
}

func addButton(parent, hInst, hFont syscall.Handle, text string, id int, x, y, w, h int32, isDefault bool) syscall.Handle {
	style := uintptr(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON)
	if isDefault {
		style = uintptr(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON)
	}
	return createControl(parent, hInst, hFont, "BUTTON", text, style, id, x, y, w, h)
}

func addCheckbox(parent, hInst, hFont syscall.Handle, text string, id int, x, y, w, h int32) syscall.Handle {
	return createControl(parent, hInst, hFont, "BUTTON", text, WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_AUTOCHECKBOX, id, x, y, w, h)
}

func main() {
	runtime.LockOSThread()
	initUI()

	bgBrushRet, _, _ := procCreateSolidBrush.Call(0x00F6F6F6)
	hBgBrush = syscall.Handle(bgBrushRet)

	hInstRet, _, _ := procGetModuleHandleW.Call(0)
	hInst := syscall.Handle(hInstRet)

	className := utf16Ptr("CrashToolModernClass")
	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInst,
		HbrBackground: hBgBrush,
		LpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	style := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE)
	rc := RECT{0, 0, scale(700), scale(510)}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), uintptr(style), 0, 0)

	hwndRet, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(utf16Ptr("CrashTool"))),
		uintptr(style),
		CW_USEDEFAULT, CW_USEDEFAULT,
		uintptr(rc.Right-rc.Left), uintptr(rc.Bottom-rc.Top),
		0, 0,
		uintptr(hInst),
		0,
	)
	hMainWnd = syscall.Handle(hwndRet)

	cornerPref := uint32(2) // DWMWCP_ROUND
	procDwmSetWindowAttribute.Call(uintptr(hMainWnd), 33, uintptr(unsafe.Pointer(&cornerPref)), unsafe.Sizeof(cornerPref))

	fontTitle := createModernFont("Segoe UI Variable Display", 15, 600)
	fontSection := createModernFont("Segoe UI", 10, 600)
	fontKeyPath := createModernFont("Segoe UI", 9, 600)
	fontBody := createModernFont("Segoe UI", 9, 400)
	fontSmall := createModernFont("Segoe UI", 8, 400)

	// Header
	addLabel(hMainWnd, hInst, fontTitle, "Windows Crash && TDR Configuration", 24, 18, 480, 30)
	addButton(hMainWnd, hInst, fontBody, "Restart PC", ID_BTN_RESTART, 566, 18, 110, 30, false)

	// Registry Section Header
	addLabel(hMainWnd, hInst, fontSection, "Registry Settings", 24, 62, 300, 22)
	addButton(hMainWnd, hInst, fontSmall, "Check All", ID_BTN_SELECT_ALL, 518, 58, 75, 24, false)
	addButton(hMainWnd, hInst, fontSmall, "Uncheck All", ID_BTN_SELECT_NONE, 601, 58, 75, 24, false)

	// Grouped Registry Checkboxes
	yPos := int32(90)
	lastSubKey := ""
	for i := range settings {
		if settings[i].SubKey != lastSubKey {
			if lastSubKey != "" {
				yPos += 10
			}
			addLabel(hMainWnd, hInst, fontKeyPath, `HKLM\`+settings[i].SubKey, 24, yPos, 652, 20)
			yPos += 24
			lastSubKey = settings[i].SubKey
		}

		settings[i].Hwnd = addCheckbox(hMainWnd, hInst, fontBody, settings[i].FriendlyDesc, ID_CHK_REG_BASE+i, 36, yPos, 640, 24)
		yPos += 27
	}

	// Registry Action Buttons
	btnY := yPos + 14
	addButton(hMainWnd, hInst, fontBody, "Apply", ID_BTN_APPLY, 24, btnY, 130, 34, true)
	addButton(hMainWnd, hInst, fontBody, "Defaults", ID_BTN_DEFAULTS, 164, btnY, 130, 34, false)
	addButton(hMainWnd, hInst, fontBody, "Refresh Status", ID_BTN_REFRESH, 546, btnY, 130, 34, false)

	// Horizontal Divider
	divY := btnY + 52
	createControl(hMainWnd, hInst, 0, "STATIC", "", WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ, 0, 24, divY, 652, 2)

	// Crash Dump Export Section
	expY := divY + 14
	addLabel(hMainWnd, hInst, fontSection, "Export Crash Dumps", 24, expY, 652, 22)
	hChkMemDmp = addCheckbox(hMainWnd, hInst, fontBody, `Kernel Memory Dump — C:\Windows\MEMORY.DMP`, ID_CHK_MEMORYDMP, 36, expY+28, 640, 24)
	hChkMinidump = addCheckbox(hMainWnd, hInst, fontBody, `Small Memory Dump (Minidump) — C:\Windows\Minidump\`, ID_CHK_MINIDUMP, 36, expY+56, 640, 24)
	hBtnZip = addButton(hMainWnd, hInst, fontBody, "Zip Selected Dumps", ID_BTN_ZIP, 24, expY+92, 180, 34, false)

	refreshDisplay(true)

	var msg MSG
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
EOF

echo "Fetching dependencies..."
go get golang.org/x/sys/windows/registry
go mod tidy

echo "Generating Windows resource (.syso)..."
go run github.com/tc-hib/go-winres@latest make --in winres.json --arch amd64

echo "Building $OUT_EXE..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H windowsgui" -o "../$OUT_EXE" .

cd ..
echo "Done! Built $(pwd)/$OUT_EXE"
