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

func restoreDefaultRegistrySettings() error {
	for _, s := range regSettings {
		if err := s.applyDefault(); err != nil {
			return err
		}
	}
	return nil
}
