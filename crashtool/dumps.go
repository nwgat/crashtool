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
