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
