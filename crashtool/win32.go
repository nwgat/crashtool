//go:build windows

package main

import (
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

	procMulDiv           = kernel32.NewProc("MulDiv")
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

	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckbox  = 0x00000003
	ssLeft          = 0x00000000
	ssRight         = 0x00000002
	ssEtchedHorz    = 0x00000010

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
		dwICC:  0x00004000 | 0x00000008, // ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES
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
