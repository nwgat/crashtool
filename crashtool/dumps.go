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
