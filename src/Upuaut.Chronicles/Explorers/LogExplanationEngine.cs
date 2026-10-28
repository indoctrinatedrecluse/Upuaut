using System.Text.RegularExpressions;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Explorers;

public class LogExplanationEngine
{
    private static readonly Regex StatusCodeRegex = new(@"0x[0-9A-Fa-f]{8}", RegexOptions.Compiled);

    private static readonly Dictionary<string, (string Name, string Meaning)> KnownStatusCodes = new(StringComparer.OrdinalIgnoreCase)
    {
        // NTSTATUS
        { "0xC0000005", ("STATUS_ACCESS_VIOLATION", "The software attempted to read or write to an invalid memory address.") },
        { "0xC0000008", ("STATUS_INVALID_HANDLE", "An invalid handle was passed to a system call.") },
        { "0xC000001D", ("STATUS_ILLEGAL_INSTRUCTION", "An attempt was made to execute an illegal processor instruction.") },
        { "0xC00000FD", ("STATUS_STACK_OVERFLOW", "A new guard page for the stack cannot be allocated (thread stack overflow).") },
        { "0xC0000374", ("STATUS_HEAP_CORRUPTION", "A process has corrupted its own heap memory structure.") },
        { "0xC00000BB", ("STATUS_NOT_SUPPORTED", "The requested command or hardware feature is not supported by the firmware or driver.") },
        { "0xC0000001", ("STATUS_UNSUCCESSFUL", "The requested operation did not succeed.") },
        { "0xC000000D", ("STATUS_INVALID_PARAMETER", "An invalid parameter was passed to a service or function.") },
        { "0xC0000017", ("STATUS_NO_MEMORY", "Insufficient virtual memory is available for the operating system to complete the operation.") },
        { "0xC0000022", ("STATUS_ACCESS_DENIED", "A process attempted an operation without the required security privileges.") },
        { "0xC0000034", ("STATUS_OBJECT_NAME_NOT_FOUND", "The specified object or file was not found.") },
        { "0xC0000043", ("STATUS_SHARING_VIOLATION", "A file cannot be accessed because it is locked by another process.") },
        { "0xC000006A", ("STATUS_WRONG_PASSWORD", "Logon failure: the specified user password is incorrect.") },
        { "0xC000006E", ("STATUS_NO_SUCH_USER", "Logon failure: the specified user account does not exist.") },
        { "0xC000006F", ("STATUS_INVALID_LOGON_HOURS", "Logon failure: user is not permitted to log on at this time.") },
        { "0xC0000072", ("STATUS_ACCOUNT_DISABLED", "Logon failure: the account is currently disabled.") },
        { "0xC0000234", ("STATUS_ACCOUNT_LOCKED_OUT", "Logon failure: user account is locked out due to excessive failed attempts.") },
        { "0xC000009A", ("STATUS_INSUFFICIENT_RESOURCES", "System resource exhaustion (pool memory, handles, or threads).") },
        { "0xC0000135", ("STATUS_DLL_NOT_FOUND", "The application failed to launch because a required DLL library could not be located.") },
        { "0xC0000142", ("STATUS_DLL_INIT_FAILED", "The application failed to initialize a required DLL properly.") },
        { "0xC000021A", ("STATUS_SYSTEM_PROCESS_TERMINATED", "A critical system process (e.g. csrss.exe or winlogon.exe) unexpectedly stopped.") },
        { "0xC0000409", ("STATUS_STACK_BUFFER_OVERRUN", "The system detected an overrun of a stack-based buffer, terminating the process to prevent security compromise.") },

        // HRESULT & Win32
        { "0x80070005", ("E_ACCESSDENIED", "Access is denied. The calling account does not possess necessary ACL permissions.") },
        { "0x80070002", ("ERROR_FILE_NOT_FOUND", "The system cannot find the file specified.") },
        { "0x80070003", ("ERROR_PATH_NOT_FOUND", "The system cannot find the path specified.") },
        { "0x8007007E", ("ERROR_MOD_NOT_FOUND", "The specified DLL module could not be found.") },
        { "0x800700C1", ("ERROR_BAD_EXE_FORMAT", "%1 is not a valid Win32 application (32-bit vs 64-bit architecture mismatch).") },
        { "0x80070422", ("ERROR_SERVICE_DISABLED", "The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.") },
        { "0x80070424", ("ERROR_SERVICE_DOES_NOT_EXIST", "The specified service does not exist as an installed service.") },
        { "0x80070643", ("ERROR_INSTALL_FAILURE", "Fatal error during Windows Installer (MSI) installation.") },
        { "0x800F081F", ("CBS_E_SOURCE_NOT_FOUND", "The source files could not be found for a Windows component or DISM repair operation.") },
        { "0x8007000E", ("E_OUTOFMEMORY", "Ran out of available memory.") },
        { "0x80070057", ("E_INVALIDARG", "One or more arguments are invalid.") },
        { "0x80004005", ("E_FAIL", "Unspecified general failure.") },
        { "0x800704C7", ("ERROR_CANCELLED", "The operation was cancelled by the user or an administrative policy.") },
        { "0x800706BA", ("RPC_S_SERVER_UNAVAILABLE", "The RPC server is unavailable or not listening.") },
        { "0x80040154", ("REGDB_E_CLASSNOTREG", "COM Class not registered. The requested COM server registration is missing from the Windows registry.") }
    };

    public LogExplanation Explain(LogRecord log)
    {
        // 1. Check curated event knowledge base
        var curated = GetCuratedExplanation(log);
        if (curated != null)
        {
            return curated;
        }

        // 2. Decode status code if present in the message or XML
        string? statusCode = null;
        string? statusMeaning = null;

        var match = StatusCodeRegex.Match(log.Message);
        if (match.Success && KnownStatusCodes.TryGetValue(match.Value, out var statusInfo))
        {
            statusCode = $"{match.Value} ({statusInfo.Name})";
            statusMeaning = statusInfo.Meaning;
        }

        // 3. Fallback to smart heuristic synthesis
        return SynthesizeGenericExplanation(log, statusCode, statusMeaning);
    }

    private LogExplanation? GetCuratedExplanation(LogRecord log)
    {
        // DistributedCOM (DCOM 10016)
        if (log.ProviderName.Contains("DistributedCOM", StringComparison.OrdinalIgnoreCase) && log.EventId == 10016)
        {
            return new LogExplanation
            {
                Summary = "A Windows background component or application tried to activate an internal COM service, but was not explicitly granted local activation permissions in Component Services.",
                TriageRating = TriageSeverity.BenignNoise,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Internal Windows components (such as ShellExperienceHost, RuntimeBroker, or Cortana) attempting to communicate with system services without explicit registration.",
                    "Normal Windows 10/11 operating system activity."
                },
                RecommendedActions = new[]
                {
                    "No action required. Microsoft officially documents this event as normal system behavior by design that does not impair application stability.",
                    "Modifying DCOM permissions in dcomcnfg is not recommended as it rarely solves issues and can introduce unintended security flaws."
                },
                TechnicalDetails = new[]
                {
                    "Event ID: 10016 (DCOM)",
                    "Subsystem: Distributed Component Object Model (DCOM)",
                    "Microsoft Advisory: KB4022522"
                }
            };
        }

        // Kernel-Power Event 41
        if (log.ProviderName.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase) && log.EventId == 41)
        {
            return new LogExplanation
            {
                Summary = "The computer rebooted without cleanly shutting down first. This occurs when power was suddenly lost, the machine froze completely, or the power button was held down.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Sudden power loss or failing Power Supply Unit (PSU).",
                    "Overheating of CPU, GPU, or motherboard voltage regulator modules (VRMs).",
                    "Unstable CPU/RAM overclock, undervolt, or faulty RAM sticks.",
                    "Kernel deadlock or hard freeze where Windows cannot write a blue-screen dump."
                },
                RecommendedActions = new[]
                {
                    "Check power cables, wall outlet, and surge protector.",
                    "Inspect thermal sensors using HWMonitor or HWiNFO during high load.",
                    "Run Windows Memory Diagnostic or MemTest86 to verify RAM integrity.",
                    "Inspect C:\\Windows\\Minidump or C:\\Windows\\MEMORY.DMP if any dump was recorded."
                },
                TechnicalDetails = new[]
                {
                    "Event ID: 41 (Kernel-Power Task 63)",
                    "BugcheckCode in Event XML details whether a crash preceded the shutdown."
                }
            };
        }

        // BugCheck (Event 1001) - Blue Screen of Death (BSOD)
        if (log.ProviderName.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) && log.EventId == 1001)
        {
            return new LogExplanation
            {
                Summary = "Windows encountered an unrecoverable kernel stop error (Blue Screen of Death / BSOD) and generated a memory crash dump.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Faulty or outdated hardware device driver (graphics, network, storage controller).",
                    "Failing physical memory (RAM) or corrupt storage sectors.",
                    "System file corruption in the Windows kernel or drivers."
                },
                RecommendedActions = new[]
                {
                    "Analyze the crash dump located in C:\\Windows\\Minidump using WinDbg or BlueScreenView.",
                    "Update third-party drivers, especially GPU, chipset, and network adapters.",
                    "Run 'sfc /scannow' and 'DISM /Online /Cleanup-Image /RestoreHealth' in an elevated terminal."
                },
                TechnicalDetails = new[]
                {
                    "Subsystem: Windows Crash Dumper (BugCheck)",
                    "Examine Parameter 1 through Parameter 4 in the event details."
                }
            };
        }

        // Microsoft-Windows-HAL (Event 20, 21)
        if (log.ProviderName.Contains("HAL", StringComparison.OrdinalIgnoreCase) && (log.EventId == 20 || log.EventId == 21))
        {
            return new LogExplanation
            {
                Summary = "The Hardware Abstraction Layer (HAL) could not query or set the ACPI Time and Alarm Device (TAD) hardware clock, falling back to the standard CMOS Real-Time Clock.",
                TriageRating = TriageSeverity.BenignNoise,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "The motherboard BIOS/UEFI firmware does not implement the optional ACPI TAD specification (Status: 0xC00000BB - STATUS_NOT_SUPPORTED).",
                    "Common on modern custom-built desktop motherboards and virtual machines."
                },
                RecommendedActions = new[]
                {
                    "No action required. Windows automatically maintains accurate time using standard RTC and Network Time Protocol (W32Time).",
                    "If clock desynchronization occurs, check motherboard CMOS battery."
                },
                TechnicalDetails = new[]
                {
                    "Event ID: 20/21 (HAL)",
                    "Status: 0xC00000BB (STATUS_NOT_SUPPORTED)"
                }
            };
        }

        // Service Control Manager (Event 7000, 7001, 7009, 7023, 7031, 7034)
        if (log.ProviderName.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
        {
            return log.EventId switch
            {
                7000 => new LogExplanation
                {
                    Summary = "A Windows background service failed to start because its executable could not be launched or returned an initialization error.",
                    TriageRating = TriageSeverity.High,
                    IsCuratedKnowledge = true,
                    ProbableCauses = new[]
                    {
                        "The service executable path does not exist (uninstalled program left service registration).",
                        "The service account lacks the 'Log on as a service' user right.",
                        "Missing software dependencies or corrupted configuration files."
                    },
                    RecommendedActions = new[]
                    {
                        "Open services.msc and locate the affected service name mentioned in the message.",
                        "Verify the executable path under the service properties.",
                        "Check if the service belongs to software that was recently removed; if so, delete the orphaned service via 'sc delete <service>'."
                    }
                },
                7009 => new LogExplanation
                {
                    Summary = "A service took longer than the configured timeout period (default 30 seconds) to connect and start.",
                    TriageRating = TriageSeverity.Medium,
                    IsCuratedKnowledge = true,
                    ProbableCauses = new[]
                    {
                        "High disk or CPU utilization during boot, causing the service startup to lag.",
                        "The service is waiting on network or DNS resources that are not yet available."
                    },
                    RecommendedActions = new[]
                    {
                        "Change the service startup type to 'Automatic (Delayed Start)' in services.msc.",
                        "Inspect disk health and startup programs to reduce boot congestion."
                    }
                },
                7031 or 7034 => new LogExplanation
                {
                    Summary = "A background Windows service terminated unexpectedly (crashed).",
                    TriageRating = TriageSeverity.High,
                    IsCuratedKnowledge = true,
                    ProbableCauses = new[]
                    {
                        "Unhandled software exception or memory access violation inside the service process.",
                        "Failure communicating with an external database or network endpoint."
                    },
                    RecommendedActions = new[]
                    {
                        "Cross-reference this timestamp with 'Application Error' (Event 1000) in the Application log.",
                        "Reinstall or update the application that provides this service."
                    }
                },
                _ => null
            };
        }

        // DNS Client (Event 1014)
        if (log.ProviderName.Contains("DNS-Client", StringComparison.OrdinalIgnoreCase) && log.EventId == 1014)
        {
            return new LogExplanation
            {
                Summary = "Windows attempted to resolve a domain name to an IP address, but the configured DNS servers did not respond before the query timed out.",
                TriageRating = TriageSeverity.Medium,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Primary DNS server (router or ISP DNS) is temporarily slow or unreachable.",
                    "Local Wi-Fi or Ethernet connection experienced packet loss or disconnection.",
                    "VPN or firewall software blocking outbound UDP port 53 traffic."
                },
                RecommendedActions = new[]
                {
                    "Verify your internet connection and router connectivity.",
                    "Configure reliable public DNS servers (e.g. 1.1.1.1 or 8.8.8.8) on your network adapter.",
                    "Run 'ipconfig /flushdns' in Command Prompt to clear the local DNS resolver cache."
                },
                TechnicalDetails = new[]
                {
                    "Subsystem: Windows DNS Resolver Client",
                    "Event ID: 1014"
                }
            };
        }

        // Storage / Disk (Event 7, 11, 15, 51)
        if (log.ProviderName.Equals("Disk", StringComparison.OrdinalIgnoreCase))
        {
            return log.EventId switch
            {
                7 => new LogExplanation
                {
                    Summary = "The storage device has a bad block. The drive was unable to read or write data in one or more physical sectors.",
                    TriageRating = TriageSeverity.Critical,
                    IsCuratedKnowledge = true,
                    ProbableCauses = new[]
                    {
                        "Physical disk degradation, deteriorating NAND flash, or failing magnetic platter sectors.",
                        "Imminent storage drive failure."
                    },
                    RecommendedActions = new[]
                    {
                        "IMMEDIATE ACTION: Back up critical personal data from this drive immediately.",
                        "Check drive S.M.A.R.T. health using CrystalDiskInfo or drive manufacturer diagnostic tools.",
                        "Replace the affected drive before permanent data loss occurs."
                    }
                },
                11 => new LogExplanation
                {
                    Summary = "The disk driver detected a hardware controller error communicating with the drive.",
                    TriageRating = TriageSeverity.High,
                    IsCuratedKnowledge = true,
                    ProbableCauses = new[]
                    {
                        "Loose or faulty SATA cable, or oxidized M.2 NVMe slot connection.",
                        "Outdated storage controller chipset driver.",
                        "Power fluctuation to the drive."
                    },
                    RecommendedActions = new[]
                    {
                        "Reseat the drive's data and power cable (or reseat the M.2 NVMe drive).",
                        "Update motherboard chipset and storage controller drivers."
                    }
                },
                _ => null
            };
        }

        // Application Error (Event 1000)
        if (log.ProviderName.Contains("Application Error", StringComparison.OrdinalIgnoreCase) && log.EventId == 1000)
        {
            return new LogExplanation
            {
                Summary = "An application crashed due to an unhandled exception or critical runtime fault.",
                TriageRating = TriageSeverity.High,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Memory corruption or access violation (0xC0000005) inside the program.",
                    "Corrupt configuration file, outdated visual runtime (VC++ Redistributables), or faulty third-party plugin/hook."
                },
                RecommendedActions = new[]
                {
                    "Check the faulting application name and module name in the details below.",
                    "Reinstall or update the crashing application.",
                    "Install the latest Microsoft Visual C++ Redistributable packages."
                }
            };
        }

        // .NET Runtime (Event 1026)
        if (log.ProviderName.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase) && log.EventId == 1026)
        {
            return new LogExplanation
            {
                Summary = "A managed .NET application terminated abruptly due to an unhandled exception escaping the runtime.",
                TriageRating = TriageSeverity.High,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Unhandled NullReferenceException, InvalidOperationException, or OutOfMemoryException.",
                    "Missing external DLL dependency or target framework mismatch."
                },
                RecommendedActions = new[]
                {
                    "Inspect the exception message and managed stack trace within the event description.",
                    "Check if the application requires a newer .NET Runtime installation (e.g. .NET 8 or .NET 10 LTS)."
                },
                TechnicalDetails = new[]
                {
                    "Subsystem: Common Language Runtime (.NET CLR)",
                    "Event ID: 1026"
                }
            };
        }

        // NTFS / Filesystem Corruption (Event 55, 98)
        if (log.ProviderName.Contains("Ntfs", StringComparison.OrdinalIgnoreCase) && (log.EventId == 55 || log.EventId == 98))
        {
            return new LogExplanation
            {
                Summary = "The NTFS filesystem detected metadata corruption on a disk volume. The filesystem structure is compromised.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Sudden power outage or hard reset while disk writes were pending in cache.",
                    "Failing storage media with unreadable metadata sectors.",
                    "Buggy storage filter driver."
                },
                RecommendedActions = new[]
                {
                    "Schedule and run a full disk check by executing 'chkdsk /f /r X:' (replace X: with affected drive).",
                    "Back up important files from this volume immediately before repairing.",
                    "Check drive S.M.A.R.T. telemetry for reallocated sectors."
                },
                TechnicalDetails = new[]
                {
                    "Subsystem: Windows NTFS Driver",
                    $"Event ID: {log.EventId}"
                }
            };
        }

        // ESENT Database Error (Event 455)
        if (log.ProviderName.Contains("ESENT", StringComparison.OrdinalIgnoreCase) && log.EventId == 455)
        {
            return new LogExplanation
            {
                Summary = "The Extensible Storage Engine (ESENT) failed to open its database log file because the specified logging directory does not exist.",
                TriageRating = TriageSeverity.Medium,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Windows Update or cleanup tools removed the 'TileDataLayer\\Database' folder in %LocalAppData%\\TileDataLayer.",
                    "Common benign Windows 10/11 system glitch that doesn't cause operational impact."
                },
                RecommendedActions = new[]
                {
                    "Create the folder 'C:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\TileDataLayer\\Database' manually to silence the warning.",
                    "Alternatively, ignore this event as it does not affect system stability."
                }
            };
        }

        // Winlogon (Event 4005)
        if (log.ProviderName.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) && log.EventId == 4005)
        {
            return new LogExplanation
            {
                Summary = "The Windows logon process terminated unexpectedly, forcing the session to disconnect or reset.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Third-party credential provider or antivirus hook crashing winlogon.exe.",
                    "Corrupted user profile registry hive (NTUSER.DAT).",
                    "System file corruption in authui.dll or logoncli.dll."
                },
                RecommendedActions = new[]
                {
                    "Boot into Safe Mode to check if third-party software is causing the crash.",
                    "Run 'sfc /scannow' to verify Windows logon system files.",
                    "Inspect Event 1000 in Application log to identify any crashing DLL loaded into winlogon."
                }
            };
        }

        // WHEA-Logger (Hardware Error)
        if (log.ProviderName.Contains("WHEA-Logger", StringComparison.OrdinalIgnoreCase))
        {
            return new LogExplanation
            {
                Summary = "Windows Hardware Error Architecture (WHEA) recorded a physical hardware error reported by the CPU or motherboard chipset.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "CPU cache hierarchy error or core voltage instability (often due to unstable overclocking or undervolting).",
                    "Failing PCIe bus connection (e.g. graphics card or NVMe drive throwing correctable or uncorrectable bus errors).",
                    "Degraded processor silicon or inadequate cooling."
                },
                RecommendedActions = new[]
                {
                    "Reset BIOS/UEFI settings to default clocks and voltages.",
                    "Update motherboard BIOS firmware to the latest stable release.",
                    "Monitor CPU package temperatures under load."
                }
            };
        }

        // Security Event 4625 (Failed Logon)
        if (log.EventId == 4625 || (log.Channel.Equals("Security", StringComparison.OrdinalIgnoreCase) && log.EventId == 4625))
        {
            var subStatusMatch = StatusCodeRegex.Match(log.Message);
            string subStatusReason = "Authentication failed.";
            if (subStatusMatch.Success && KnownStatusCodes.TryGetValue(subStatusMatch.Value, out var statusInfo))
            {
                subStatusReason = $"{statusInfo.Name}: {statusInfo.Meaning}";
            }

            return new LogExplanation
            {
                Summary = $"A user account failed to log on. Substatus reason: {subStatusReason}",
                TriageRating = TriageSeverity.High,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "User mistyped their password or username.",
                    "An automated script or expired mapped drive credential is repeatedly attempting to authenticate.",
                    "Potential brute-force or password spraying attack targeting local or domain credentials."
                },
                RecommendedActions = new[]
                {
                    "Inspect the 'Account Name' and 'Source Network Address' fields in the Technical Details below.",
                    "If the source IP is external or unexpected, check firewall logs and consider blocking the remote host.",
                    "Check Credential Manager on the source machine for outdated cached credentials."
                },
                TechnicalDetails = new[]
                {
                    "Event ID: 4625 (Security Audit Failure)",
                    $"Status: {subStatusReason}"
                }
            };
        }

        // Schannel (TLS / SSL Handshake Fatal Alert)
        if (log.ProviderName.Contains("Schannel", StringComparison.OrdinalIgnoreCase))
        {
            return new LogExplanation
            {
                Summary = "A secure TLS/SSL handshake between this computer and a remote host failed.",
                TriageRating = TriageSeverity.Medium,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Client and server do not share a common cipher suite or TLS protocol version (e.g. legacy TLS 1.0/1.1 disabled on Windows).",
                    "The remote server's SSL certificate has expired, has an untrusted Root CA, or has a mismatched hostname.",
                    "Local Windows Schannel registry configurations have disabled required cryptographic algorithms."
                },
                RecommendedActions = new[]
                {
                    "Verify the validity of the remote server's SSL certificate using an SSL checker or browser.",
                    "Ensure TLS 1.2 and TLS 1.3 are enabled on both endpoints.",
                    "Check whether local group policies or security baselines restricted cipher suites."
                },
                TechnicalDetails = new[]
                {
                    "Subsystem: Microsoft Schannel (Secure Channel SSP)",
                    $"Event ID: {log.EventId}"
                }
            };
        }

        // NTFS File System Corruption (Event 55)
        if (log.ProviderName.Contains("Ntfs", StringComparison.OrdinalIgnoreCase) && log.EventId == 55)
        {
            return new LogExplanation
            {
                Summary = "The file system structure on a disk volume is corrupt and unusable. Self-healing was unable to resolve the inconsistency.",
                TriageRating = TriageSeverity.Critical,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "Improper shutdown or power interruption while the operating system was writing to the Master File Table (MFT).",
                    "Underlying physical bad sectors on the storage media.",
                    "Failing storage controller or corrupted disk cache."
                },
                RecommendedActions = new[]
                {
                    "IMMEDIATE: Run 'chkdsk <DriveLetter>: /f /r' from an elevated Command Prompt.",
                    "Back up accessible files from the volume before initiating intensive repair operations.",
                    "Check drive S.M.A.R.T. telemetry using CrystalDiskInfo to ensure disk is not failing physically."
                },
                TechnicalDetails = new[]
                {
                    "Event ID: 55 (NTFS Volume Corruption)",
                    "Subsystem: Windows NT File System Driver"
                }
            };
        }

        // User Profile Service (Event 1500, 1509, 1530)
        if (log.ProviderName.Contains("User Profile Service", StringComparison.OrdinalIgnoreCase))
        {
            return new LogExplanation
            {
                Summary = "Windows cannot log on with the specified user profile, or background processes leaked registry keys preventing clean unload.",
                TriageRating = TriageSeverity.Medium,
                IsCuratedKnowledge = true,
                ProbableCauses = new[]
                {
                    "The user's NTUSER.DAT registry hive is corrupted or locked by security software / antivirus.",
                    "Insufficient file permissions on C:\\Users\\<Username> folder.",
                    "A background application or service failed to release registry handles during logout."
                },
                RecommendedActions = new[]
                {
                    "Restart the computer and attempt logging in again.",
                    "Verify disk permissions on the user's directory in C:\\Users.",
                    "Temporarily exclude NTUSER.DAT from real-time antivirus scans."
                }
            };
        }

        return null;
    }

    private LogExplanation SynthesizeGenericExplanation(LogRecord log, string? statusCode, string? statusMeaning)
    {
        var causes = new List<string>();
        var actions = new List<string>();
        var details = new List<string>();

        if (!string.IsNullOrEmpty(statusCode))
        {
            details.Add($"Status Code: {statusCode}");
            if (!string.IsNullOrEmpty(statusMeaning))
            {
                details.Add($"Meaning: {statusMeaning}");
                causes.Add(statusMeaning);
            }
        }

        var message = log.Message.ToLowerInvariant();
        var rating = log.Level switch
        {
            LogSeverityLevel.Critical => TriageSeverity.Critical,
            LogSeverityLevel.Error => TriageSeverity.High,
            LogSeverityLevel.Warning => TriageSeverity.Medium,
            _ => TriageSeverity.Low
        };

        // Keyword analysis
        if (message.Contains("timeout") || message.Contains("timed out"))
        {
            causes.Add("The operation exceeded the allocated waiting duration before the remote service or hardware responded.");
            actions.Add("Check network latency, server availability, and disk load during the timestamp.");
        }
        else if (message.Contains("access denied") || message.Contains("permission"))
        {
            causes.Add("The process or user account attempted an action without sufficient Windows ACL permissions or security token.");
            actions.Add("Verify whether the initiating process was running with elevated administrator rights.");
        }
        else if (message.Contains("not found") || message.Contains("cannot find"))
        {
            causes.Add("A requested file, registry key, network endpoint, or system component was missing.");
            actions.Add("Verify file paths and registry keys referenced in the event details.");
        }
        else if (message.Contains("corrupt") || message.Contains("integrity"))
        {
            causes.Add("Data structure or file verification detected checksum inconsistency or corruption.");
            actions.Add("Run 'sfc /scannow' or 'chkdsk' to verify system files and storage health.");
            rating = TriageSeverity.High;
        }

        if (causes.Count == 0)
        {
            causes.Add($"The component '{log.ProviderName}' logged an issue with Event ID {log.EventId}.");
        }

        if (actions.Count == 0)
        {
            actions.Add("Inspect the Raw XML and full message details below for parameters passed during the event.");
            actions.Add("Check surrounding events around this timestamp in the unified timeline.");
        }

        var summary = !string.IsNullOrEmpty(statusMeaning)
            ? $"The provider '{log.ProviderName}' reported an error: {statusMeaning}"
            : $"The component '{log.ProviderName}' encountered a {log.Level.ToString().ToLowerInvariant()} condition (Event ID {log.EventId}).";

        return new LogExplanation
        {
            Summary = summary,
            TriageRating = rating,
            IsCuratedKnowledge = false,
            DecodedStatusCode = statusCode,
            StatusMeaning = statusMeaning,
            ProbableCauses = causes,
            RecommendedActions = actions,
            TechnicalDetails = details
        };
    }
}
