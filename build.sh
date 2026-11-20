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

# Standard Windows application manifest:
# - UAC requireAdministrator
# - Common Controls v6 (modern visual styles)
# - PerMonitorV2 DPI awareness
cat << 'EOF' > app.manifest
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="amd64" name="CrashTool" type="win32"/>
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

cat << 'EOF' > winres.json
{
  "RT_MANIFEST": {
    "#1": {
      "0409": "app.manifest"
    }
  }
}
EOF

# 1. Registry configuration & operations
cat << 'EOF' > registry.go
//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type RegSetting struct {
	SubKey        string
	ValueName     string
	Description   string
	CustomValue   uint32
	DeleteOnReset bool
	DefaultValue  uint32

	CheckboxHwnd windows.HWND
	StatusHwnd   windows.HWND
	Enabled      bool
}

var regSettings = []RegSetting{
	{
		SubKey:        `SYSTEM\CurrentControlSet\Control\GraphicsDrivers`,
		ValueName:     "TdrLevel",
		Description:   "TdrLevel = 1 (Disable GPU TDR recovery)",
		CustomValue:   1,
		DeleteOnReset: true,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "CrashDumpEnabled",
		Description:  "CrashDumpEnabled = 2 (Kernel memory dump)",
		CustomValue:  2,
		DefaultValue: 7,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "AutoReboot",
		Description:  "AutoReboot = 1 (Automatically restart on BSOD)",
		CustomValue:  1,
		DefaultValue: 1,
	},
	{
		SubKey:       `SYSTEM\CurrentControlSet\Control\CrashControl`,
		ValueName:    "Overwrite",
		Description:  "Overwrite = 1 (Overwrite existing dump file)",
		CustomValue:  1,
		DefaultValue: 1,
	},
}

func (s RegSetting) applyCustom() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, s.SubKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open/create %s: %w", s.SubKey, err)
	}
	defer k.Close()

	if err := k.SetDWordValue(s.ValueName, s.CustomValue); err != nil {
		return fmt.Errorf("set %s: %w", s.ValueName, err)
	}
	return nil
}

func (s RegSetting) applyDefault() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, s.SubKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open %s: %w", s.SubKey, err)
	}
	defer k.Close()

	if s.DeleteOnReset {
		if err := k.DeleteValue(s.ValueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("delete %s: %w", s.ValueName, err)
		}
		return nil
	}

	if err := k.SetDWordValue(s.ValueName, s.DefaultValue); err != nil {
		return fmt.Errorf("restore %s: %w", s.ValueName, err)
	}
	return nil
}

func (s RegSetting) isCustomApplied() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, s.SubKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(s.ValueName)
	return err == nil && uint32(val) == s.CustomValue
}

func (s RegSetting) isDefaultChecked() bool {
	if s.DeleteOnReset {
		return false
	}
	return s.DefaultValue == s.CustomValue
}

func applyCheckedRegistrySettings() error {
	for _, s := range regSettings {
		if isChecked(s.CheckboxHwnd) {
			if err := s.applyCustom(); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyAllRegistrySettings() error {
	for _, s := range regSettings {
		if err := s.applyCustom(); err != nil {
			return err
		}
	}
	return nil
}

func restoreDefaultRegistrySettings() error {
	for _, s := range regSettings {
		if err := s.applyDefault(); err != nil {
			return err
		}
	}
	return nil
}
EOF

# 2. Crash dump discovery and ZIP creation
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
	"time"

	"golang.org/x/sys/windows"
)

const (
	memoryDmpPath = `C:\Windows\MEMORY.DMP`
	minidumpDir   = `C:\Windows\Minidump`
)

type zipOutcome struct {
	title   string
	message string
	flags   uint32
	zipPath string
	success bool
}

func humanBytes(b int64) string {
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

func checkMemoryDump() (label string, available bool) {
	info, err := os.Stat(memoryDmpPath)
	if err != nil || info.IsDir() {
		return fmt.Sprintf("Kernel Memory Dump — %s  (Not found)", memoryDmpPath), false
	}
	return fmt.Sprintf(
		"Kernel Memory Dump — %s  (%s, %s)",
		memoryDmpPath,
		humanBytes(info.Size()),
		info.ModTime().Format("2006-01-02 15:04"),
	), true
}

func checkMinidumps() (label string, available bool) {
	entries, err := os.ReadDir(minidumpDir)
	if err != nil {
		return fmt.Sprintf("Small Memory Dump (Minidump) — %s\\  (No .dmp files found)", minidumpDir), false
	}

	var count int
	var totalBytes int64
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
			count++
			if fi, err := e.Info(); err == nil {
				totalBytes += fi.Size()
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
		humanBytes(totalBytes),
	), true
}

func defaultAppZipPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to resolve application directory: %w", err)
	}
	appDir := filepath.Dir(exePath)
	fileName := fmt.Sprintf("CrashDumps_%s.zip", time.Now().Format("20060102_150405"))
	return filepath.Join(appDir, fileName), nil
}

func writeZipEntry(zw *zip.Writer, srcPath, entryName string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	hdr, err := zip.FileInfoHeader(fi)
	if err != nil {
		return err
	}
	hdr.Name = entryName
	hdr.Method = zip.Deflate

	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, f)
	return err
}

func createCrashDumpArchive(zipPath string, includeMemDmp, includeMinidump bool) zipOutcome {
	outFile, err := os.Create(zipPath)
	if err != nil {
		return zipOutcome{
			title:   "Compression Error",
			message: fmt.Sprintf("Failed to create zip file:\n%v", err),
			flags:   windows.MB_ICONERROR,
		}
	}

	zw := zip.NewWriter(outFile)
	added := 0

	abort := func(msg string) zipOutcome {
		zw.Close()
		outFile.Close()
		os.Remove(zipPath)
		return zipOutcome{
			title:   "Compression Error",
			message: msg,
			flags:   windows.MB_ICONERROR,
		}
	}

	if includeMemDmp {
		if err := writeZipEntry(zw, memoryDmpPath, "MEMORY.DMP"); err != nil {
			return abort(fmt.Sprintf("Failed adding MEMORY.DMP:\n%v", err))
		}
		added++
	}

	if includeMinidump {
		entries, err := os.ReadDir(minidumpDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
					src := filepath.Join(minidumpDir, e.Name())
					dst := filepath.Join("Minidump", e.Name())
					if err := writeZipEntry(zw, src, dst); err != nil {
						return abort(fmt.Sprintf("Failed adding %s:\n%v", e.Name(), err))
					}
					added++
				}
			}
		}
	}

	zw.Close()
	outFile.Close()

	if added == 0 {
		os.Remove(zipPath)
		return zipOutcome{
			title:   "Nothing Compressed",
			message: "No dump files were found to compress.",
			flags:   windows.MB_ICONWARNING,
		}
	}

	var sizeText string
	if fi, err := os.Stat(zipPath); err == nil {
		sizeText = humanBytes(fi.Size())
	}

	return zipOutcome{
		title:   "Compression Complete",
		message: fmt.Sprintf("Successfully compressed %d file(s) (%s).\n\nSaved to:\n%s", added, sizeText, zipPath),
		flags:   windows.MB_ICONINFORMATION,
		zipPath: zipPath,
		success: true,
	}
}
EOF

# 3. Win32 API bindings, DPI scaling, tooltips, clipboard file copy, and control builders
cat << 'EOF' > win32.go
//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	comctl32 = windows.NewLazySystemDLL("comctl32.dll")
	dwmapi   = windows.NewLazySystemDLL("dwmapi.dll")

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
	procInvalidateRect            = user32.NewProc("InvalidateRect")
	procGetDpiForSystem           = user32.NewProc("GetDpiForSystem")
	procAdjustWindowRectEx        = user32.NewProc("AdjustWindowRectEx")
	procSetProcessDpiAwarenessCtx = user32.NewProc("SetProcessDpiAwarenessContext")
	procOpenClipboard             = user32.NewProc("OpenClipboard")
	procCloseClipboard            = user32.NewProc("CloseClipboard")
	procEmptyClipboard            = user32.NewProc("EmptyClipboard")
	procSetClipboardData          = user32.NewProc("SetClipboardData")

	procMulDiv           = kernel32.NewProc("MulDiv")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procCreateFontW      = gdi32.NewProc("CreateFontW")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procSetBkMode        = gdi32.NewProc("SetBkMode")
	procSetTextColor     = gdi32.NewProc("SetTextColor")

	procInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
)

const (
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabStop     = 0x00010000
	wsPopup       = 0x80000000

	wsExTopmost = 0x00000008

	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckbox  = 0x00000003
	ssLeft          = 0x00000000
	ssRight         = 0x00000002
	ssEtchedHorz    = 0x00000010

	ttsAlwaysTip = 0x01
	ttsNoPrefix  = 0x02
	ttfIdIsHwnd  = 0x0001
	ttfSubclass  = 0x0010
	ttmAddToolW  = 0x0400 + 50

	wmDestroy        = 0x0002
	wmCommand        = 0x0111
	wmCtlColorStatic = 0x0138
	wmCtlColorBtn    = 0x0135
	wmSetFont        = 0x0030
	wmAppZipDone     = 0x8001

	bmGetCheck   = 0x00F0
	bmSetCheck   = 0x00F1
	bstUnchecked = 0x0000
	bstChecked   = 0x0001

	idYes = 6

	cfHDrop      = 15
	gmemMoveable = 0x0002
	gmemZeroInit = 0x0040
	ghnd         = gmemMoveable | gmemZeroInit

	cwUseDefault     = 0x80000000
	clearTypeQuality = 5
	transparentMode  = 1

	// COLORREF (0x00BBGGRR)
	colorBgSurface   = 0x00F6F6F6
	colorTextDefault = 0x001E1E1E
	colorGreen       = 0x00107C10 // #107C10
	colorRed         = 0x001C2BC4 // #C42B1C

	dpiAwarenessPerMonitorV2 = ^uintptr(3) // -4
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

type point struct{ x, y int32 }
type rect struct{ left, top, right, bottom int32 }

type msg struct {
	hwnd    windows.HWND
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type initCommonControlsEx struct {
	dwSize uint32
	dwICC  uint32
}

type dropFiles struct {
	pFiles uint32
	pt     point
	fNC    int32
	fWide  int32
}

type toolInfoW struct {
	cbSize   uint32
	uFlags   uint32
	hwnd     windows.HWND
	uId      uintptr
	rect     rect
	hinst    windows.Handle
	lpszText *uint16
	lParam   uintptr
	lpReserved unsafe.Pointer
}

var dpiScale = 1.0

func px(v int32) int32 {
	return int32(float64(v) * dpiScale)
}

func mustUTF16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func initWin32() {
	procSetProcessDpiAwarenessCtx.Call(dpiAwarenessPerMonitorV2)
	if dpi, _, _ := procGetDpiForSystem.Call(); dpi > 0 {
		dpiScale = float64(dpi) / 96.0
	}

	icc := initCommonControlsEx{
		dwSize: uint32(unsafe.Sizeof(initCommonControlsEx{})),
		dwICC:  0x00004000 | 0x00000008 | 0x00000004, // ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES | ICC_BAR_CLASSES
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
}

func makeFont(face string, ptSize, weight int32) windows.Handle {
	dpi := int32(96 * dpiScale)
	height, _, _ := procMulDiv.Call(uintptr(-ptSize), uintptr(dpi), 72)
	h, _, _ := procCreateFontW.Call(
		height, 0, 0, 0,
		uintptr(weight),
		0, 0, 0, 1, 0, 0,
		clearTypeQuality, 0,
		uintptr(unsafe.Pointer(mustUTF16(face))),
	)
	return windows.Handle(h)
}

func alert(hwnd windows.HWND, title, body string, flags uint32) int32 {
	ret, _ := windows.MessageBox(hwnd, mustUTF16(body), mustUTF16(title), flags)
	return ret
}

func setControlText(hwnd windows.HWND, text string) {
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(mustUTF16(text))))
}

func setControlEnabled(hwnd windows.HWND, enabled bool) {
	var flag uintptr
	if enabled {
		flag = 1
	}
	procEnableWindow.Call(uintptr(hwnd), flag)
}

func isChecked(hwnd windows.HWND) bool {
	ret, _, _ := procSendMessageW.Call(uintptr(hwnd), bmGetCheck, 0, 0)
	return ret == bstChecked
}

func setChecked(hwnd windows.HWND, checked bool) {
	state := uintptr(bstUnchecked)
	if checked {
		state = uintptr(bstChecked)
	}
	procSendMessageW.Call(uintptr(hwnd), bmSetCheck, state, 0)
}

func copyFileToClipboard(owner windows.HWND, filePath string) error {
	utf16Path, err := windows.UTF16FromString(filePath)
	if err != nil {
		return err
	}
	// CF_HDROP requires a double-null terminated list of UTF-16 strings
	utf16Path = append(utf16Path, 0)

	headerSize := unsafe.Sizeof(dropFiles{})
	pathBytes := uintptr(len(utf16Path) * 2)
	totalSize := headerSize + pathBytes

	hMem, _, _ := procGlobalAlloc.Call(ghnd, totalSize)
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc failed")
	}

	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("GlobalLock failed")
	}

	df := (*dropFiles)(unsafe.Pointer(ptr))
	df.pFiles = uint32(headerSize)
	df.fWide = 1

	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr+headerSize)), len(utf16Path))
	copy(dst, utf16Path)
	procGlobalUnlock.Call(hMem)

	if ok, _, _ := procOpenClipboard.Call(uintptr(owner)); ok == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("failed to open Windows clipboard")
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()
	if res, _, _ := procSetClipboardData.Call(cfHDrop, hMem); res == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("failed to set clipboard file data")
	}
	return nil
}

type uiBuilder struct {
	parent windows.HWND
	hInst  windows.Handle
}

func (b uiBuilder) control(class, text string, style uintptr, id int, x, y, w, h int32, font windows.Handle) windows.HWND {
	var textPtr uintptr
	if text != "" {
		textPtr = uintptr(unsafe.Pointer(mustUTF16(text)))
	}
	ret, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(mustUTF16(class))),
		textPtr,
		style,
		uintptr(px(x)), uintptr(px(y)), uintptr(px(w)), uintptr(px(h)),
		uintptr(b.parent),
		uintptr(id),
		uintptr(b.hInst),
		0,
	)
	hwnd := windows.HWND(ret)
	if font != 0 {
		procSendMessageW.Call(uintptr(hwnd), wmSetFont, uintptr(font), 1)
	}
	return hwnd
}

func (b uiBuilder) label(text string, x, y, w, h int32, font windows.Handle) windows.HWND {
	return b.control("STATIC", text, wsChild|wsVisible|ssLeft, 0, x, y, w, h, font)
}

func (b uiBuilder) rightLabel(text string, x, y, w, h int32, font windows.Handle) windows.HWND {
	return b.control("STATIC", text, wsChild|wsVisible|ssRight, 0, x, y, w, h, font)
}

func (b uiBuilder) button(text string, id int, x, y, w, h int32, font windows.Handle, primary bool) windows.HWND {
	style := uintptr(wsChild | wsVisible | wsTabStop | bsPushButton)
	if primary {
		style = uintptr(wsChild | wsVisible | wsTabStop | bsDefPushButton)
	}
	return b.control("BUTTON", text, style, id, x, y, w, h, font)
}

func (b uiBuilder) checkbox(text string, id int, x, y, w, h int32, font windows.Handle) windows.HWND {
	return b.control("BUTTON", text, wsChild|wsVisible|wsTabStop|bsAutoCheckbox, id, x, y, w, h, font)
}

func (b uiBuilder) divider(x, y, w int32) {
	b.control("STATIC", "", wsChild|wsVisible|ssEtchedHorz, 0, x, y, w, 2, 0)
}

func (b uiBuilder) addTooltip(target windows.HWND, text string) {
	tipHwnd, _, _ := procCreateWindowExW.Call(
		wsExTopmost,
		uintptr(unsafe.Pointer(mustUTF16("tooltips_class32"))),
		0,
		wsPopup|ttsNoPrefix|ttsAlwaysTip,
		cwUseDefault, cwUseDefault, cwUseDefault, cwUseDefault,
		uintptr(b.parent),
		0,
		uintptr(b.hInst),
		0,
	)
	if tipHwnd == 0 {
		return
	}

	ti := toolInfoW{
		cbSize:   uint32(unsafe.Sizeof(toolInfoW{})),
		uFlags:   ttfIdIsHwnd | ttfSubclass,
		hwnd:     b.parent,
		uId:      uintptr(target),
		hinst:    b.hInst,
		lpszText: mustUTF16(text),
	}
	procSendMessageW.Call(tipHwnd, ttmAddToolW, 0, uintptr(unsafe.Pointer(&ti)))
}
EOF

# 4. Main window, state synchronization, and event loop
cat << 'EOF' > main.go
//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	idBtnApply     = 101
	idBtnApplyAll  = 105
	idBtnDefaults  = 102
	idBtnRestart   = 104
	idChkMemoryDmp = 107
	idChkMinidump  = 108
	idBtnZip       = 109
	idBtnCopyZip   = 110
	idChkRegBase   = 200
)

type checkSyncMode int

const (
	checkKeep checkSyncMode = iota
	checkAll
	checkRegAll
	checkDefaults
)

var (
	mainWnd     windows.HWND
	chkMemDmp   windows.HWND
	chkMinidump windows.HWND
	btnZip      windows.HWND
	btnCopyZip  windows.HWND
	bgBrush     windows.Handle

	zipMu       sync.Mutex
	lastZipRes  zipOutcome
	lastZipPath string
)

func syncUIState(mode checkSyncMode) {
	for i := range regSettings {
		s := &regSettings[i]
		if s.CheckboxHwnd == 0 {
			continue
		}

		s.Enabled = s.isCustomApplied()
		if s.StatusHwnd != 0 {
			if s.Enabled {
				setControlText(s.StatusHwnd, "Enabled")
			} else {
				setControlText(s.StatusHwnd, "Not Enabled")
			}
			procInvalidateRect.Call(uintptr(s.StatusHwnd), 0, 1)
		}

		switch mode {
		case checkAll, checkRegAll:
			setChecked(s.CheckboxHwnd, true)
		case checkDefaults:
			setChecked(s.CheckboxHwnd, s.isDefaultChecked())
		}
	}

	if chkMemDmp != 0 {
		label, ok := checkMemoryDump()
		setControlText(chkMemDmp, label)
		setControlEnabled(chkMemDmp, ok)
		if mode == checkAll {
			setChecked(chkMemDmp, ok)
		} else if !ok {
			setChecked(chkMemDmp, false)
		}
	}

	if chkMinidump != 0 {
		label, ok := checkMinidumps()
		setControlText(chkMinidump, label)
		setControlEnabled(chkMinidump, ok)
		if mode == checkAll {
			setChecked(chkMinidump, ok)
		} else if !ok {
			setChecked(chkMinidump, false)
		}
	}
}

func startZipWorker(zipPath string, incMem, incMini bool) {
	setControlEnabled(btnZip, false)
	setControlText(btnZip, "Compressing...")

	go func() {
		outcome := createCrashDumpArchive(zipPath, incMem, incMini)
		zipMu.Lock()
		lastZipRes = outcome
		zipMu.Unlock()
		procPostMessageW.Call(uintptr(mainWnd), wmAppZipDone, 0, 0)
	}()
}

func triggerSystemRestart(hwnd windows.HWND) {
	ans := alert(
		hwnd,
		"Confirm Restart",
		"Are you sure you want to restart Windows immediately?\nAny unsaved work will be lost.",
		windows.MB_YESNO|windows.MB_ICONWARNING,
	)
	if ans != idYes {
		return
	}

	cmd := exec.Command("shutdown", "-r", "-t", "0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		alert(hwnd, "Restart Error", fmt.Sprintf("Failed to trigger restart:\n%v", err), windows.MB_ICONERROR)
	}
}

func wndProc(hwnd windows.HWND, uMsg uint32, wParam, lParam uintptr) uintptr {
	switch uMsg {
	case wmCtlColorStatic, wmCtlColorBtn:
		hdc := windows.Handle(wParam)
		ctrl := windows.HWND(lParam)
		procSetBkMode.Call(uintptr(hdc), transparentMode)

		color := uintptr(colorTextDefault)
		for _, s := range regSettings {
			if s.StatusHwnd != 0 && s.StatusHwnd == ctrl {
				if s.Enabled {
					color = colorGreen
				} else {
					color = colorRed
				}
				break
			}
		}

		procSetTextColor.Call(uintptr(hdc), color)
		return uintptr(bgBrush)

	case wmAppZipDone:
		setControlText(btnZip, "Zip Selected Dumps")
		setControlEnabled(btnZip, true)

		zipMu.Lock()
		res := lastZipRes
		zipMu.Unlock()

		if res.success && res.zipPath != "" {
			lastZipPath = res.zipPath
			setControlEnabled(btnCopyZip, true)
		}

		alert(hwnd, res.title, res.message, res.flags)
		return 0

	case wmCommand:
		switch uint16(wParam & 0xFFFF) {
		case idBtnApply:
			if err := applyCheckedRegistrySettings(); err != nil {
				alert(hwnd, "Registry Error", err.Error(), windows.MB_ICONERROR)
			} else {
				syncUIState(checkKeep)
				alert(
					hwnd,
					"Applied",
					"Custom settings applied for checked items.\nRestart Windows for changes to take effect.",
					windows.MB_ICONINFORMATION,
				)
			}

		case idBtnApplyAll:
			if err := applyAllRegistrySettings(); err != nil {
				alert(hwnd, "Registry Error", err.Error(), windows.MB_ICONERROR)
			} else {
				syncUIState(checkRegAll)
				alert(
					hwnd,
					"All Settings Applied",
					"All custom registry settings have been applied.\nRestart Windows for changes to take effect.",
					windows.MB_ICONINFORMATION,
				)
			}

		case idBtnDefaults:
			if err := restoreDefaultRegistrySettings(); err != nil {
				alert(hwnd, "Registry Error", err.Error(), windows.MB_ICONERROR)
			} else {
				syncUIState(checkDefaults)
				alert(
					hwnd,
					"Defaults Restored",
					"All settings and checkboxes restored to Windows defaults.\nRestart Windows for changes to take effect.",
					windows.MB_ICONINFORMATION,
				)
			}

		case idBtnRestart:
			triggerSystemRestart(hwnd)

		case idBtnZip:
			incMem := isChecked(chkMemDmp)
			incMini := isChecked(chkMinidump)
			if !incMem && !incMini {
				alert(hwnd, "No Selection", "Please check at least one crash dump option first.", windows.MB_ICONWARNING)
				return 0
			}
			zipPath, err := defaultAppZipPath()
			if err != nil {
				alert(hwnd, "Path Error", err.Error(), windows.MB_ICONERROR)
				return 0
			}
			startZipWorker(zipPath, incMem, incMini)

		case idBtnCopyZip:
			if lastZipPath == "" {
				alert(hwnd, "No Archive", "Please create a crash dump zip archive first.", windows.MB_ICONWARNING)
				return 0
			}
			if _, err := os.Stat(lastZipPath); err != nil {
				setControlEnabled(btnCopyZip, false)
				alert(hwnd, "File Not Found", fmt.Sprintf("The archive no longer exists at:\n%s", lastZipPath), windows.MB_ICONERROR)
				return 0
			}
			if err := copyFileToClipboard(hwnd, lastZipPath); err != nil {
				alert(hwnd, "Clipboard Error", err.Error(), windows.MB_ICONERROR)
			} else {
				alert(hwnd, "Copied to Clipboard", fmt.Sprintf("Copied file to clipboard:\n%s", lastZipPath), windows.MB_ICONINFORMATION)
			}
		}
		return 0

	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(uMsg), wParam, lParam)
	return ret
}

func main() {
	runtime.LockOSThread()
	initWin32()

	brushRet, _, _ := procCreateSolidBrush.Call(colorBgSurface)
	bgBrush = windows.Handle(brushRet)

	var hInst windows.Handle
	_ = windows.GetModuleHandleEx(0, nil, &hInst)

	className := mustUTF16("CrashToolModernClass")
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     hInst,
		hbrBackground: bgBrush,
		lpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	style := uint32(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsVisible)
	rc := rect{0, 0, px(700), px(510)}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), uintptr(style), 0, 0)

	hwndRet, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(mustUTF16("CrashTool"))),
		uintptr(style),
		cwUseDefault, cwUseDefault,
		uintptr(rc.right-rc.left), uintptr(rc.bottom-rc.top),
		0, 0,
		uintptr(hInst),
		0,
	)
	mainWnd = windows.HWND(hwndRet)

	cornerPref := uint32(2) // DWMWCP_ROUND
	procDwmSetWindowAttribute.Call(uintptr(mainWnd), 33, uintptr(unsafe.Pointer(&cornerPref)), unsafe.Sizeof(cornerPref))

	fontTitle := makeFont("Segoe UI Variable Display", 15, 600)
	fontSection := makeFont("Segoe UI", 10, 600)
	fontBold := makeFont("Segoe UI", 9, 600)
	fontBody := makeFont("Segoe UI", 9, 400)

	ui := uiBuilder{parent: mainWnd, hInst: hInst}

	// Header
	ui.label("Windows Crash && TDR Configuration", 24, 18, 480, 30, fontTitle)
	ui.button("Restart PC", idBtnRestart, 566, 18, 110, 30, fontBody, false)

	// Registry Section
	ui.label("Registry Settings", 24, 62, 460, 22, fontSection)
	ui.rightLabel("Current Registry Status", 496, 62, 180, 22, fontBold)

	y := int32(90)
	lastKey := ""
	for i := range regSettings {
		if regSettings[i].SubKey != lastKey {
			if lastKey != "" {
				y += 10
			}
			ui.label(`HKLM\`+regSettings[i].SubKey, 24, y, 652, 20, fontBold)
			y += 24
			lastKey = regSettings[i].SubKey
		}

		regSettings[i].CheckboxHwnd = ui.checkbox(regSettings[i].Description, idChkRegBase+i, 36, y, 490, 24, fontBody)
		regSettings[i].StatusHwnd = ui.rightLabel("Not Enabled", 536, y+3, 140, 20, fontBold)
		y += 27
	}

	// Registry Action Bar
	y += 14
	btnApply := ui.button("Apply", idBtnApply, 24, y, 115, 34, fontBody, true)
	ui.addTooltip(btnApply, "Apply checked")
	ui.button("Apply All", idBtnApplyAll, 149, y, 115, 34, fontBody, false)
	ui.button("Defaults", idBtnDefaults, 274, y, 115, 34, fontBody, false)

	// Divider
	y += 52
	ui.divider(24, y, 652)

	// Crash Dump Export Section
	y += 14
	ui.label("Export Crash Dumps", 24, y, 652, 22, fontSection)
	chkMemDmp = ui.checkbox(`Kernel Memory Dump — C:\Windows\MEMORY.DMP`, idChkMemoryDmp, 36, y+28, 640, 24, fontBody)
	chkMinidump = ui.checkbox(`Small Memory Dump (Minidump) — C:\Windows\Minidump\`, idChkMinidump, 36, y+56, 640, 24, fontBody)
	btnZip = ui.button("Zip Selected Dumps", idBtnZip, 24, y+92, 180, 34, fontBody, false)
	btnCopyZip = ui.button("Copy .zip to Clipboard", idBtnCopyZip, 214, y+92, 180, 34, fontBody, false)
	setControlEnabled(btnCopyZip, false)

	syncUIState(checkAll)

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}
EOF

echo "Fetching dependencies..."
go get golang.org/x/sys/windows
go get golang.org/x/sys/windows/registry
go mod tidy

echo "Generating Windows resource (.syso)..."
go run github.com/tc-hib/go-winres@latest make --in winres.json --arch amd64

echo "Building $OUT_EXE..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H windowsgui" -o "../$OUT_EXE" .

cd ..
echo "Done! Built $(pwd)/$OUT_EXE"
