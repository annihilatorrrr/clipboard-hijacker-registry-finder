package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Common registry locations where malware hides
var autostartKeys = []struct {
	Root registry.Key
	Path string
	Name string
}{
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "HKCU Run"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU RunOnce"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`, "HKCU Startup Approved"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`, "HKLM Startup Approved"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, "HKCU Shell Folders"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, "HKLM Shell Folders"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "HKCU Winlogon"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, "HKLM Winlogon"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "HKCU Policies Run"},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "HKLM Policies Run"},
}

func scanRegistryKey(root registry.Key, path string, locationName string, logger *log.Logger) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		msg := fmt.Sprintf("\n📍 Checking: %s\n   Registry Path: %s\n   ⚠️  Cannot access (may not exist or no permission)\n", locationName, path)
		fmt.Print(msg)
		logger.Print(msg)
		return
	}
	defer key.Close()

	// Get all value names
	names, err := key.ReadValueNames(0)
	if err != nil {
		msg := fmt.Sprintf("\n📍 Checking: %s\n   Registry Path: %s\n   ⚠️  Cannot read values\n", locationName, path)
		fmt.Print(msg)
		logger.Print(msg)
		return
	}

	headerMsg := fmt.Sprintf("\n📍 Checking: %s\n   Registry Path: %s\n", locationName, path)
	fmt.Print(headerMsg)
	logger.Print(headerMsg)

	foundSuspicious := false
	for _, name := range names {
		value, _, err := key.GetStringValue(name)
		if err != nil {
			continue
		}

		// Check for suspicious patterns
		suspicious := false
		reasons := []string{}

		lowerValue := strings.ToLower(value)
		lowerName := strings.ToLower(name)

		// Suspicious locations
		if strings.Contains(lowerValue, "appdata\\roaming") {
			suspicious = true
			reasons = append(reasons, "Hidden in AppData\\Roaming")
		}
		if strings.Contains(lowerValue, "appdata\\local\\temp") {
			suspicious = true
			reasons = append(reasons, "Hidden in Temp folder")
		}
		if strings.Contains(lowerValue, "programdata") {
			suspicious = true
			reasons = append(reasons, "Hidden in ProgramData")
		}
		if strings.Contains(lowerValue, "\\temp\\") {
			suspicious = true
			reasons = append(reasons, "Running from Temp")
		}

		// Suspicious file types and patterns
		if strings.Contains(lowerValue, ".vbs") || strings.Contains(lowerValue, ".js") || 
		   strings.Contains(lowerValue, ".bat") || strings.Contains(lowerValue, ".cmd") {
			suspicious = true
			reasons = append(reasons, "Script file (VBS/JS/BAT)")
		}

		// Suspicious keywords
		if strings.Contains(lowerName, "update") || strings.Contains(lowerName, "service") ||
		   strings.Contains(lowerName, "svc") || strings.Contains(lowerName, "system") {
			if !strings.Contains(lowerValue, "microsoft") && !strings.Contains(lowerValue, "windows") {
				suspicious = true
				reasons = append(reasons, "Suspicious name mimicking system")
			}
		}

		// Random-looking names
		if len(name) > 10 && strings.IndexFunc(name, func(r rune) bool {
			return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		}) == -1 {
			suspicious = true
			reasons = append(reasons, "Random-looking name")
		}

		if suspicious {
			foundSuspicious = true
			suspiciousMsg := fmt.Sprintf("\n   🚨 SUSPICIOUS ENTRY FOUND!\n   Name: %s\n   Value: %s\n   Reasons: %s\n", 
				name, value, strings.Join(reasons, ", "))
			fmt.Print(suspiciousMsg)
			logger.Print(suspiciousMsg)
		} else {
			// Still show it but mark as normal
			normalMsg := fmt.Sprintf("   ✓ %s = %s\n", name, value)
			fmt.Print(normalMsg)
			logger.Print(normalMsg)
		}
	}

	if !foundSuspicious {
		okMsg := "   ✅ No suspicious entries found\n"
		fmt.Print(okMsg)
		logger.Print(okMsg)
	}
}

func main() {
	fmt.Println("========================================")
	fmt.Println("Registry Autostart Scanner")
	fmt.Println("Detecting Clipboard Hijacker Malware")
	fmt.Println("========================================\n")

	logFile, err := os.Create("registry_scan_log.txt")
	if err != nil {
		fmt.Printf("Warning: Could not create log file: %v\n", err)
		return
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	
	startMsg := "========================================\nRegistry Autostart Scanner\nDetecting Clipboard Hijacker Malware\n========================================\n\n"
	logger.Print(startMsg)
	
	fmt.Println("📝 Logging results to: registry_scan_log.txt\n")
	logger.Print("📝 Logging all results to this file\n")

	scanMsg := "🔍 Scanning common autostart registry locations...\n"
	fmt.Print(scanMsg)
	logger.Print(scanMsg)

	for _, location := range autostartKeys {
		scanRegistryKey(location.Root, location.Path, location.Name, logger)
	}

	summaryMsg := "\n========================================\n✅ Scan Complete!\n========================================\n"
	fmt.Print(summaryMsg)
	logger.Print(summaryMsg)
	
	nextStepsMsg := `
Next steps if suspicious entries found:
1. Note the registry path and name
2. Run regedit.exe as Administrator
3. Navigate to the suspicious registry key
4. Delete the suspicious entry
5. Delete the file it points to
6. Run full antivirus scan
`
	fmt.Println(nextStepsMsg)
	logger.Print(nextStepsMsg)

	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}
