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
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	memoryDmpPath = `C:\Windows\MEMORY.DMP`
	minidumpDir   = `C:\Windows\Minidump`

	ofnOverwritePrompt = 0x00000002
	ofnNoChangeDir     = 0x00000008
	ofnPathMustExist   = 0x00000800
)

var (
	comdlg32             = windows.NewLazySystemDLL("comdlg32.dll")
	procGetSaveFileNameW = comdlg32.NewProc("GetSaveFileNameW")
)

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         windows.HWND
	hInstance         windows.Handle
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        unsafe.Pointer
	dwReserved        uint32
	flagsEx           uint32
}

type zipOutcome struct {
	title   string
	message string
	flags   uint32
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

func promptSaveZip(owner windows.HWND) (string, bool) {
	initialDir, err := os.UserHomeDir()
	if err != nil {
		initialDir = `C:\`
	}
	if desktop := filepath.Join(initialDir, "Desktop"); dirExists(desktop) {
		initialDir = desktop
	}

	defaultName := fmt.Sprintf("CrashDumps_%s.zip", time.Now().Format("20060102_150405"))
	buf := make([]uint16, 32768)
	if u, err := windows.UTF16FromString(defaultName); err == nil {
		copy(buf, u)
	}

	filter := encodeFileFilter("ZIP Archives (*.zip)", "*.zip", "All Files (*.*)", "*.*")
	dirPtr, _ := windows.UTF16PtrFromString(initialDir)
	titlePtr, _ := windows.UTF16PtrFromString("Save Crash Dumps Archive")
	extPtr, _ := windows.UTF16PtrFromString("zip")

	ofn := openFileNameW{
		lStructSize:     uint32(unsafe.Sizeof(openFileNameW{})),
		hwndOwner:       owner,
		lpstrFilter:     &filter[0],
		nFilterIndex:    1,
		lpstrFile:       &buf[0],
		nMaxFile:        uint32(len(buf)),
		lpstrInitialDir: dirPtr,
		lpstrTitle:      titlePtr,
		flags:           ofnOverwritePrompt | ofnPathMustExist | ofnNoChangeDir,
		lpstrDefExt:     extPtr,
	}

	ret, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func encodeFileFilter(pairs ...string) []uint16 {
	var out []uint16
	for _, s := range pairs {
		if u, err := windows.UTF16FromString(s); err == nil {
			out = append(out, u...)
		}
	}
	return append(out, 0)
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
	}
}
