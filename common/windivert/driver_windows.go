//go:build windows

package windivert

import (
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/internal/winmutex"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	driverServiceName          = "WinDivert"
	driverDeviceName           = `\\.\WinDivert`
	driverInstallMutexName     = "WinDivertDriverInstallMutex"
	driverInstallMutexTimeout  = 90 * time.Second
	driverReadyTimeout         = 60 * time.Second
	driverUnloadTimeout        = 60 * time.Second
	driverStateRefreshInterval = 50 * time.Millisecond
)

var driverDevName, _ = windows.UTF16PtrFromString(driverDeviceName)

func acquireDevice() (windows.Handle, error) {
	device, err := openDevice()
	if err == nil {
		return device, nil
	}
	fatalErr := driverOpenFatal(err)
	if fatalErr != nil {
		return 0, fatalErr
	}
	if runtime.GOARCH == "386" {
		var isWow64 bool
		err = windows.IsWow64Process(windows.CurrentProcess(), &isWow64)
		if err == nil && isWow64 {
			return 0, E.New("windivert: 386 build detected running under WOW64 on a 64-bit kernel; use the amd64 build")
		}
	}
	device, err = winmutex.WithLock(driverInstallMutexName, driverInstallMutexTimeout, installAndOpenDevice)
	if err != nil && device != 0 {
		closeErr := windows.CloseHandle(device)
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "windivert: close device after install lock failure")
		}
		return 0, E.Errors(err, closeErr)
	}
	return device, err
}

func driverOpenFatal(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return E.Cause(err, "windivert: open device (administrator required)")
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_NO_SUCH_DEVICE) {
		return nil
	}
	return E.Cause(err, "windivert: open device")
}

func installAndOpenDevice() (windows.Handle, error) {
	device, err := openDevice()
	if err == nil {
		return device, nil
	}
	fatalErr := driverOpenFatal(err)
	if fatalErr != nil {
		return 0, fatalErr
	}

	sysPath, sysFile, err := openVerifiedDriver()
	if err != nil {
		return 0, err
	}
	defer sysFile.Close()
	sysPathW, err := windows.UTF16PtrFromString(sysPath)
	if err != nil {
		return 0, E.Cause(err, "windivert: utf16 driver path")
	}

	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return 0, E.Cause(err, "windivert: open SCM")
	}
	defer windows.CloseServiceHandle(manager)

	serviceNameW, _ := windows.UTF16PtrFromString(driverServiceName)
	deadline := time.Now().Add(driverReadyTimeout)
	for {
		serviceErr := tryInstallService(manager, serviceNameW, sysPathW)
		if serviceErr != nil && !driverServiceTransient(serviceErr) {
			return 0, serviceErr
		}
		device, err = openDevice()
		if err == nil {
			return device, nil
		}
		fatalErr = driverOpenFatal(err)
		if fatalErr != nil {
			return 0, fatalErr
		}
		if time.Now().After(deadline) {
			openErr := E.Cause(err, "windivert: open device after driver readiness timeout")
			if serviceErr != nil {
				return 0, E.Errors(serviceErr, openErr)
			}
			return 0, openErr
		}
		time.Sleep(driverStateRefreshInterval)
	}
}

func driverServiceTransient(err error) bool {
	return errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) ||
		errors.Is(err, windows.ERROR_SERVICE_DISABLED) ||
		errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS)
}

func tryInstallService(manager windows.Handle, serviceNameW, sysPathW *uint16) error {
	service, err := openOrCreateService(manager, serviceNameW, sysPathW)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	err = windows.StartService(service, 0, nil)
	if err == nil {
		// Upstream WinDivert.dll marks the service for deletion only in the
		// process whose StartService succeeded; one that finds it already
		// running leaves the deletion to that owner.
		_ = windows.DeleteService(service)
		return nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_DISABLED) {
		// StartService on a running service that is marked for deletion
		// reports ERROR_SERVICE_DISABLED, not ERROR_SERVICE_ALREADY_RUNNING.
		var status windows.SERVICE_STATUS
		queryErr := windows.QueryServiceStatus(service, &status)
		if queryErr == nil && status.CurrentState == windows.SERVICE_RUNNING {
			return nil
		}
	}
	return E.Cause(err, "windivert: start service")
}

func openOrCreateService(manager windows.Handle, serviceNameW, sysPathW *uint16) (windows.Handle, error) {
	service, err := windows.OpenService(manager, serviceNameW, windows.SERVICE_ALL_ACCESS)
	if err == nil {
		return service, nil
	}
	service, err = windows.CreateService(
		manager,
		serviceNameW,
		serviceNameW,
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START,
		windows.SERVICE_ERROR_NORMAL,
		sysPathW,
		nil, nil, nil, nil, nil,
	)
	if err == nil {
		return service, nil
	}
	if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
		service, err = windows.OpenService(manager, serviceNameW, windows.SERVICE_ALL_ACCESS)
		if err == nil {
			return service, nil
		}
	}
	return 0, wrapDriverInstallError(err)
}

func wrapDriverInstallError(err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return E.Cause(err, "windivert: installing the kernel driver requires Administrator privileges")
	}
	return E.Cause(err, "windivert: create service")
}

func openDriverFile(path string) (*os.File, error) {
	pathW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathW,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// The driver does not unload when the last handle closes, and the memory
// manager keeps its backing image write-locked for a while after the service
// reaches SERVICE_STOPPED.
func Uninstall() error {
	if driverAssetName == "" {
		return nil
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return E.Cause(err, "windivert: open SCM")
	}
	defer windows.CloseServiceHandle(manager)
	serviceNameW, err := windows.UTF16PtrFromString(driverServiceName)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, serviceNameW, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS|windows.DELETE)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return waitDriverFileUnloaded()
		}
		return E.Cause(err, "windivert: open service")
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS
	err = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &status)
	if err != nil && !E.IsMulti(err, windows.ERROR_SERVICE_NOT_ACTIVE, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
		return E.Cause(err, "windivert: stop service")
	}
	var deleteErr error
	err = windows.DeleteService(service)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		deleteErr = E.Cause(err, "windivert: delete service")
	}
	return E.Errors(deleteErr, waitDriverFileUnloaded())
}

func waitDriverFileUnloaded() error {
	target, err := driverFilePath()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(driverUnloadTimeout)
	for {
		file, openErr := os.OpenFile(target, os.O_WRONLY, 0)
		if openErr == nil {
			file.Close()
			return nil
		}
		if os.IsNotExist(openErr) {
			return nil
		}
		if !E.IsMulti(openErr, windows.ERROR_SHARING_VIOLATION, windows.ERROR_USER_MAPPED_FILE) {
			return E.Cause(openErr, "windivert: open ", target)
		}
		if time.Now().After(deadline) {
			return E.Cause(openErr, "windivert: wait for driver image unload")
		}
		time.Sleep(driverStateRefreshInterval)
	}
}
