// Copyright (c) 2018-2019, Sylabs Inc. All rights reserved.
// This software is licensed under a 3-clause BSD license. Please consult the
// LICENSE.md file distributed with the sources of this project regarding your
// rights to use or distribute this software.

package crypt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/sylabs/singularity/internal/pkg/sylog"
	"github.com/sylabs/singularity/pkg/util/fs/lock"
	"github.com/sylabs/singularity/pkg/util/loop"
	"golang.org/x/crypto/ssh/terminal"
)

// Device is
type Device struct {
	MaxDevices int
}

type errCryptDeviceUnavailable struct {
	message string
}

func newCryptDevUnailable(msg string) *errCryptDeviceUnavailable {
	return &errCryptDeviceUnavailable{
		message: msg,
	}
}

func (e *errCryptDeviceUnavailable) Error() string {
	return e.message
}

func createLoop(file *os.File, offset, size uint64) (string, error) {
	loopDev := &loop.Device{
		MaxLoopDevices: 256,
		Shared:         true,
		Info: &loop.Info64{
			SizeLimit: size,
			Offset:    offset,
			Flags:     loop.FlagsAutoClear,
		},
	}
	idx := 0
	if err := loopDev.AttachFromFile(file, os.O_RDWR, &idx); err != nil {
		return "", fmt.Errorf("failed to attach image %s: %s", file.Name(), err)
	}
	return fmt.Sprintf("/dev/loop%d", idx), nil
}

// DeleteCryptDevice closes the crypt device
func (crypt *Device) DeleteCryptDevice(path string) error {

	cryptExec, err := exec.LookPath("cryptsetup")
	if err != nil {
		sylog.Debugf("Unable to find cryptsetup in PATH")
		return err
	}

	cmd := exec.Command(cryptExec, "luksClose", path)
	cmd.Dir = "/dev/mapper"
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	fd, err := lock.Exclusive("/dev/mapper")
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	if err != nil {
		sylog.Debugf("Unable to delete the crypt device %s", err)
		return err
	}
	err = lock.Release(fd)
	if err != nil {
		sylog.Debugf("Unable to release the lock on /dev/mapper")
		return err
	}

	return nil
}

// FormatCryptDevice allocates a loop device, encrypts, and returns the loop device name, and encrypted device name
func (crypt *Device) FormatCryptDevice(path string) (string, string, error) {

	// Read the password from terminal
	fmt.Print("Enter a password to encrypt the filesystem: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		sylog.Fatalf("Error parsing the password: %s", err)
	}
	input := string(password)

	fmt.Print("\nConfirm the password: ")
	password2, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		sylog.Fatalf("Error parsing the password: %s", err)
	}
	input2 := string(password2)
	fmt.Println()

	if input != input2 {
		return "", "", errors.New("Passwords don't match")
	}

	fileName := fmt.Sprintf("%s/sparse_fs.loop", path)
	// Create a sparse file in tmp dir
	f, err := os.Create(fileName)
	if err != nil {
		sylog.Debugf("Unable to create sparse file required for encryption")
		return "", "", err
	}

	// Create a 500MB sparse file
	err = f.Truncate(5 * 1e8)
	if err != nil {

		return "", "", err
	}

	file, err := os.OpenFile(fileName, os.O_RDWR, 0755)
	defer file.Close()

	// Associate the above created file with a loop device
	loop, err := createLoop(file, 0, 5*1e8)

	cryptExec, err := exec.LookPath("cryptsetup")
	if err != nil {
		sylog.Debugf("Unable to find cryptsetup in PATH")
		return "", "", err
	}

	sp := strings.Split(loop, "/")
	loopdev := sp[len(sp)-1]
	cmd := exec.Command(cryptExec, "luksFormat", loopdev)
	cmd.Dir = "/dev"
	stdin, err := cmd.StdinPipe()

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, input)
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		sylog.Verbosef("Out is %s, err is %s", out, err)
		return "", "", err
	}

	fd, err := lock.Exclusive("/dev/mapper")
	if err != nil {
		sylog.Debugf("Unable to acquire lock on /dev/mapper")
		return "", "", err
	}
	nextCrypt := getNextAvailableCryptDevice(crypt.MaxDevices)
	cmd = exec.Command(cryptExec, "luksOpen", loopdev, nextCrypt)
	cmd.Dir = "/dev"
	stdin, err = cmd.StdinPipe()

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, input)
	}()

	out, err = cmd.CombinedOutput()
	if err != nil {
		sylog.Verbosef("Out is %s, err is %s", out, err)
		return "", "", err
	}
	err = lock.Release(fd)
	if err != nil {
		sylog.Debugf("Unable to release lock on /dev/mapper")
		return "", "", err
	}

	return loop, nextCrypt, err
}

func getNextAvailableCryptDevice(max int) string {
	for i := 0; i < max; i++ {
		retStr := fmt.Sprintf("singularity_crypt_%d", i)
		device := fmt.Sprintf("/dev/mapper/%s", retStr)
		if _, err := os.Stat(device); os.IsNotExist(err) {
			return retStr
		}
	}
	return ""
}

// GetCryptDevice returns the next available device in /dev/mapper for encryption/decryption
func (crypt *Device) GetCryptDevice(loopDev string) (string, error) {
	// Return the next available crypt device
	sylog.Debugf("loopdev is %s", loopDev)

	fmt.Print("Enter the password to decrypt the File System: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		sylog.Fatalf("Error parsing input: %s", err)
	}
	fmt.Println()

	fd, err := lock.Exclusive("/dev/mapper")
	if err != nil {
		sylog.Debugf("Unable to acquire lock on /dev/mapper while decrypting")
		return "", err
	}
	defer lock.Release(fd)

	maxRetries := 3 // Arbitrary number of retries.

retry:
	numRetries := 0
	nextCrypt := getNextAvailableCryptDevice(crypt.MaxDevices)
	if nextCrypt == "" {
		return "", newCryptDevUnailable("Crypt Device not available")
	}

	cryptExec, err := exec.LookPath("cryptsetup")
	if err != nil {
		fmt.Printf("cryptExec is %s", cryptExec)
		sylog.Debugf("Unable to find cryptsetup in PATH")
		return "", err
	}

	cmd := exec.Command(cryptExec, "luksOpen", loopDev, nextCrypt)
	cmd.Dir = "/dev"
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	stdin, err := cmd.StdinPipe()

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, string(password))
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "No key available") == true {
			sylog.Debugf("Invalid password")
		}
		if strings.Contains(string(out), "Device already exists") == true {
			numRetries++
			if numRetries < maxRetries {
				goto retry
			}
		}
		return "", err
	}
	sylog.Debugf("Decrypted the FS successfully")

	return nextCrypt, nil
}
