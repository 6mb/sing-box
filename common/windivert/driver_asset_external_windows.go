//go:build windows && with_external_windivert

package windivert

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"

	E "github.com/sagernet/sing/common/exceptions"
)

func driverFilePath() (string, error) {
	if driverAssetName == "" {
		return "", E.New("windivert: unsupported architecture ", runtime.GOARCH)
	}
	executablePath, err := os.Executable()
	if err != nil {
		return "", E.Cause(err, "windivert: locate executable")
	}
	return filepath.Join(filepath.Dir(executablePath), driverAssetName), nil
}

func openVerifiedDriver() (string, *os.File, error) {
	target, err := driverFilePath()
	if err != nil {
		return "", nil, err
	}
	sysFile, err := openDriverFile(target)
	if err != nil {
		return "", nil, E.Cause(err, "windivert: open ", target)
	}
	digest := sha256.New()
	_, err = io.Copy(digest, sysFile)
	if err != nil {
		sysFile.Close()
		return "", nil, E.Cause(err, "windivert: read ", target)
	}
	if hex.EncodeToString(digest.Sum(nil)) != driverAssetDigest {
		sysFile.Close()
		return "", nil, E.New("windivert: driver file ", target, " does not match the WinDivert ", AssetVersion, " asset")
	}
	return target, sysFile, nil
}
