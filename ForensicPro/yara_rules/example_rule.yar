// Basic YARA rules for detecting suspicious files and activity on a Kali Linux system

// Rule to detect suspicious file extensions commonly used in Linux
rule SuspiciousLinuxFileExtensions
{
    meta:
        description = "Detect suspicious file extensions on Linux systems"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $sh_extension = ".sh"           // Detect shell scripts (.sh) which may be used for malicious scripts
        $py_extension = ".py"           // Detect Python scripts (.py) that could be used for malware or exploitation
        $elf_extension = ".elf"         // ELF executable files (.elf) which are native to Linux

    condition:
        // This rule matches files with extensions .sh, .py, or .elf which are often used in malicious activity
        any of ($sh_extension, $py_extension, $elf_extension)
}

// Rule to detect suspicious strings commonly associated with Linux malware or exploits
rule SuspiciousLinuxStrings
{
    meta:
        description = "Detect suspicious strings in Linux system files"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $wget = "wget"                   // Commonly used for downloading malicious files or payloads
        $curl = "curl"                   // Another tool often used to fetch malicious payloads from the internet
        $bash = "bash"                   // Bash is frequently used to execute malicious scripts
        $nc = "nc"                       // Netcat (nc) is a common tool used for reverse shells or data exfiltration
        $root = "root"                   // The presence of "root" string may suggest privilege escalation or rootkit activity

    condition:
        // This rule matches the appearance of these suspicious strings which are common in malicious scripts
        any of ($wget, $curl, $bash, $nc, $root)
}

// Rule to detect common Linux hacking tools
rule LinuxHackingTools
{
    meta:
        description = "Detect the presence of common Linux hacking tools"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $metasploit = "msfconsole"         // Metasploit console, commonly used for exploitation
        $hydra = "hydra"                   // Hydra, a brute force tool
        $john = "john"                     // John the Ripper, a password cracking tool
        $nmap = "nmap"                     // Nmap, a network scanning tool often used for reconnaissance
        $netcat = "nc"                     // Netcat, a networking utility commonly used in reverse shells

    condition:
        // This rule matches the presence of common penetration testing tools often used by attackers
        any of ($metasploit, $hydra, $john, $nmap, $netcat)
}

// Rule to detect ELF (Executable and Linkable Format) files commonly used in Linux
rule SuspiciousELFFiles
{
    meta:
        description = "Detect suspicious ELF files on a Linux system"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $elf_header = { 7F 45 4C 46 }     // ELF header ('7F 45 4C 46' is the magic number of ELF files)

    condition:
        // This rule detects files that begin with the ELF magic number, indicating a potential ELF executable
        $elf_header at 0
}

// Rule to detect suspicious network activity (e.g., using `wget`, `curl`, `nc` commands)
rule SuspiciousNetworkActivity
{
    meta:
        description = "Detect suspicious network activity like wget, curl, and netcat"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $wget = "wget"                     // Wget, used for downloading files over HTTP or FTP, common in payload delivery
        $curl = "curl"                     // Curl, used for similar purposes as wget
        $nc = "nc"                         // Netcat, often used to establish reverse shells or data exfiltration
        $ssh = "ssh"                       // SSH, commonly used for remote access, may be exploited for unauthorized access

    condition:
        // This rule detects suspicious network-related commands that could indicate an attacker is communicating with an external server
        any of ($wget, $curl, $nc, $ssh)
}

// Rule to detect packed files (often used to obfuscate malware)
rule PackedFiles
{
    meta:
        description = "Detect packed files often used to obfuscate malware"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $upx = "UPX"                       // UPX, a popular executable packer used to compress and obfuscate malicious files
        $aspack = "ASPack"                  // ASPack, another packer that can be used to hide the true nature of the file

    condition:
        // This rule matches the presence of the UPX or ASPack signature, which could indicate the file is packed to avoid detection
        any of ($upx, $aspack)
}

// Rule to detect suspicious file operations (e.g., creating files or writing to unusual directories)
rule SuspiciousFileOperations
{
    meta:
        description = "Detect suspicious file operations like creating or modifying files in sensitive directories"
        author = "YourName"
        date = "2024-11-29"
        version = "1.0"

    strings:
        $etc_passwd = "/etc/passwd"           // This is a critical system file and its modification could indicate a compromise
        $etc_shadow = "/etc/shadow"           // The shadow file contains encrypted password hashes; tampering may indicate privilege escalation

    condition:
        // This rule detects attempts to access or modify critical files such as `/etc/passwd` and `/etc/shadow`
        any of ($etc_passwd, $etc_shadow)
}

