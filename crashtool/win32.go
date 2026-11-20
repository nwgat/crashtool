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
