//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	idBtnApply     = 101
	idBtnDefaults  = 102
	idBtnRefresh   = 103
	idBtnRestart   = 104
	idChkMemoryDmp = 107
	idChkMinidump  = 108
	idBtnZip       = 109
	idChkRegBase   = 200
)

type checkSyncMode int

const (
	checkKeep checkSyncMode = iota
	checkAll
	checkDefaults
)

var (
	mainWnd     windows.HWND
	chkMemDmp   windows.HWND
	chkMinidump windows.HWND
	btnZip      windows.HWND
	bgBrush     windows.Handle

	zipMu      sync.Mutex
	lastZipRes zipOutcome
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
		case checkAll:
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

		case idBtnRefresh:
			syncUIState(checkKeep)

		case idBtnRestart:
			triggerSystemRestart(hwnd)

		case idBtnZip:
			incMem := isChecked(chkMemDmp)
			incMini := isChecked(chkMinidump)
			if !incMem && !incMini {
				alert(hwnd, "No Selection", "Please check at least one crash dump option first.", windows.MB_ICONWARNING)
				return 0
			}
			if zipPath, ok := promptSaveZip(hwnd); ok {
				startZipWorker(zipPath, incMem, incMini)
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
	ui.button("Apply", idBtnApply, 24, y, 130, 34, fontBody, true)
	ui.button("Defaults", idBtnDefaults, 164, y, 130, 34, fontBody, false)
	ui.button("Refresh Status", idBtnRefresh, 546, y, 130, 34, fontBody, false)

	// Divider
	y += 52
	ui.divider(24, y, 652)

	// Crash Dump Export Section
	y += 14
	ui.label("Export Crash Dumps", 24, y, 652, 22, fontSection)
	chkMemDmp = ui.checkbox(`Kernel Memory Dump — C:\Windows\MEMORY.DMP`, idChkMemoryDmp, 36, y+28, 640, 24, fontBody)
	chkMinidump = ui.checkbox(`Small Memory Dump (Minidump) — C:\Windows\Minidump\`, idChkMinidump, 36, y+56, 640, 24, fontBody)
	btnZip = ui.button("Zip Selected Dumps", idBtnZip, 24, y+92, 180, 34, fontBody, false)

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
