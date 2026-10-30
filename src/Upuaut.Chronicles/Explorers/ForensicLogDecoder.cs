using System.Globalization;
using System.Text.RegularExpressions;
using Upuaut.Core.Models;

namespace Upuaut.Chronicles.Explorers;

/// <summary>
/// Deep forensic decoder for Critical and Error events in Windows Event Log.
/// Translates cryptic hex codes, raw bugcheck parameters, logon types, and module offsets
/// into plain-English diagnostics and actionable remediation instructions.
/// </summary>
public static class ForensicLogDecoder
{
    private static readonly Regex StatusCodeRegex = new(@"0x[0-9A-Fa-f]{8}", RegexOptions.Compiled);
    private static readonly Regex HexAddressRegex = new(@"0x[0-9A-Fa-f]{4,16}", RegexOptions.Compiled);

    private static readonly Dictionary<long, (string Name, string Description, string CommonCause)> BugcheckDatabase = new()
    {
        { 0x116, ("VIDEO_TDR_FAILURE", "The display driver failed to respond in time and was reset by Windows Timeout Detection and Recovery (TDR).", "Outdated GPU driver, unstable GPU overclock, or overheating graphics card.") },
        { 0x0A,  ("IRQL_NOT_LESS_OR_EQUAL", "Kernel process attempted to access pageable memory at an elevated Interrupt Request Level (IRQL).", "Faulty device driver referencing invalid memory addresses, or corrupted system memory (RAM).") },
        { 0x3B,  ("SYSTEM_SERVICE_EXCEPTION", "An unhandled exception occurred while executing a system service routine.", "Outdated graphics or network drivers, or corrupted system DLLs.") },
        { 0x50,  ("PAGE_FAULT_IN_NONPAGED_AREA", "Invalid system memory was referenced by a driver or kernel thread.", "Defective physical RAM, damaged L2/L3 CPU cache, or buggy anti-cheat/antivirus filter driver.") },
        { 0x1E,  ("KMODE_EXCEPTION_NOT_HANDLED", "A kernel-mode process generated an unhandled exception.", "Third-party device driver crash, hardware incompatibility, or corrupted kernel binaries.") },
        { 0x124, ("WHEA_UNCORRECTABLE_ERROR", "A fatal physical hardware error occurred, reported by the processor or PCIe bus.", "CPU overheating, unstable core undervolt/overclock, failing NVMe SSD, or motherboard VRM failure.") },
        { 0xD1,  ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A device driver accessed an invalid pageable memory address at high IRQL.", "Buggy network adapter driver, wireless Wi-Fi driver, or audio DAC driver.") },
        { 0x9F,  ("DRIVER_POWER_STATE_FAILURE", "A driver failed or took too long to complete a power state transition (sleep, wake, or shutdown).", "Outdated Bluetooth, Wi-Fi, or chipset driver hanging during power transitions.") },
        { 0x1A,  ("MEMORY_MANAGEMENT", "A severe memory management error occurred in the Windows memory manager.", "Failing physical RAM module or corrupted pagefile on disk.") },
        { 0x7E,  ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread generated an exception that the error handler did not catch.", "Incompatible device driver or hardware mismatch.") },
        { 0x7F,  ("UNEXPECTED_KERNEL_MODE_TRAP", "The CPU generated a hardware trap that the kernel was not prepared to handle (e.g. double fault or stack exhaustion).", "Hardware failure, CPU overclocking instability, or corrupted kernel stack.") },
        { 0xC2,  ("BAD_POOL_CALLER", "The current thread made an illegal pool memory allocation or deallocation request.", "Driver memory leak, corrupted memory pool header, or buggy filter driver.") },
        { 0x133, ("DPC_WATCHDOG_VIOLATION", "The DPC watchdog detected a single long-running Deferred Procedure Call (DPC) hanging the system.", "Outdated SSD firmware (especially NVMe drivers) or graphics driver DPC latency spikes.") },
        { 0x139, ("KERNEL_SECURITY_CHECK_FAILURE", "The kernel detected corruption of a critical operating system data structure.", "Corrupt memory, malicious rootkit modification, or severe driver bug.") },
        { 0x19,  ("BAD_POOL_HEADER", "A memory pool header was corrupted by an invalid write operation.", "Faulty third-party driver overwriting memory buffer boundaries.") }
    };

    private static readonly Dictionary<int, (string Name, string Description)> ServiceErrorCodes = new()
    {
        { 5,    ("ERROR_ACCESS_DENIED", "The account configuring or starting the service lacks administrative permissions.") },
        { 1053, ("ERROR_SERVICE_REQUEST_TIMEOUT", "The service process did not connect or respond to the Service Control Manager within 30 seconds.") },
        { 1060, ("ERROR_SERVICE_DOES_NOT_EXIST", "The specified service is not registered in the Windows Service Control database.") },
        { 1068, ("ERROR_SERVICE_DEPENDENCY_FAIL", "A dependency service or service group failed to start prior to this service.") },
        { 1069, ("ERROR_SERVICE_LOGON_FAILED", "The service account password has expired or the account lacks 'Log on as a service' rights.") },
        { 1075, ("ERROR_DEPENDENCY_NOT_FOUND", "The dependency service does not exist or has been marked for deletion.") },
        { 1077, ("ERROR_SERVICE_NEVER_STARTED", "No attempts to start the service have been made since the last system boot.") }
    };

    private static readonly Dictionary<string, (string Type, string Description)> WellKnownModules = new(StringComparer.OrdinalIgnoreCase)
    {
        { "ntdll.dll", ("Windows NT Native Layer", "Core kernel-mode system call dispatcher and NT native API runtime.") },
        { "kernelbase.dll", ("Windows Base Kernel API", "Core Win32 subsystem API implementation for process, thread, and file management.") },
        { "kernel32.dll", ("Win32 Subsystem", "Standard Windows Win32 memory and execution environment.") },
        { "ucrtbase.dll", ("Universal C Runtime", "Microsoft C/C++ standard library runtime implementation.") },
        { "clr.dll", (".NET Core / CLR Runtime", "Common Language Runtime virtual machine and garbage collector.") },
        { "coreclr.dll", (".NET Core Runtime Engine", "High-performance .NET Core / .NET 10 CLR runtime engine.") },
        { "d3d11.dll", ("DirectX 11 Graphics", "Direct3D 11 graphics pipeline and rendering engine.") },
        { "d3d12.dll", ("DirectX 12 Low-Level Graphics", "Direct3D 12 explicit GPU command list and resource pipeline.") },
        { "dxgi.dll", ("DirectX Graphics Infrastructure", "Manages display adapters, swap chains, and fullscreen monitor handoffs.") },
        { "nvwgf2umx.dll", ("NVIDIA GPU User Driver", "NVIDIA GeForce / Quadro DirectX graphics driver module.") },
        { "amdxx64.dll", ("AMD Radeon GPU Driver", "AMD Radeon Adrenalin DirectX graphics driver module.") },
        { "igd10iumd64.dll", ("Intel Graphics Driver", "Intel Iris Xe / Arc graphics driver user-mode driver.") },
        { "msvcrt.dll", ("Microsoft Visual C++ Runtime", "Legacy C runtime library used by older Win32 applications.") }
    };

    public static LogExplanation EnrichForensics(LogRecord log, LogExplanation baseExplanation)
    {
        var decoded = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? subsystem = baseExplanation.Subsystem;
        string? impact = baseExplanation.ImpactAssessment;
        string? fixCmd = baseExplanation.ForensicFixCommand;
        var causes = new List<string>(baseExplanation.ProbableCauses);
        var actions = new List<string>(baseExplanation.RecommendedActions);
        var details = new List<string>(baseExplanation.TechnicalDetails);

        // 1. BSOD & Crash Dumper (BugCheck 1001, WER 1001, Kernel-Power 41)
        if ((log.EventId == 1001 && (log.ProviderName.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
                                     log.ProviderName.Contains("WER", StringComparison.OrdinalIgnoreCase) ||
                                     log.ProviderName.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase) ||
                                     log.EventData.ContainsKey("BugcheckCode"))) ||
            (log.EventId == 41 && log.ProviderName.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase)))
        {
            subsystem = "Windows Kernel & Crash Dumper";
            impact = "Fatal: Unrecoverable kernel stop error resulting in immediate OS reboot";
            fixCmd = "sfc /scannow; DISM /Online /Cleanup-Image /RestoreHealth";

            // Extract bugcheck code from EventData or Message
            long bugcheckCode = 0;
            if (log.EventData.TryGetValue("BugcheckCode", out var codeStr))
            {
                if (codeStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    long.TryParse(codeStr[2..], NumberStyles.HexNumber, null, out bugcheckCode);
                else
                    long.TryParse(codeStr, out bugcheckCode);
            }
            else
            {
                var match = StatusCodeRegex.Match(log.Message);
                if (match.Success)
                    long.TryParse(match.Value[2..], NumberStyles.HexNumber, null, out bugcheckCode);
            }

            if (bugcheckCode != 0)
            {
                var hexCode = $"0x{bugcheckCode:X8}";
                decoded["BugCheck Code"] = hexCode;

                if (BugcheckDatabase.TryGetValue(bugcheckCode, out var bcInfo) ||
                    BugcheckDatabase.TryGetValue(bugcheckCode & 0xFFFF, out bcInfo))
                {
                    decoded["Stop Error Name"] = bcInfo.Name;
                    decoded["Meaning"] = bcInfo.Description;
                    decoded["Primary Cause"] = bcInfo.CommonCause;

                    causes.Insert(0, $"BSOD {bcInfo.Name}: {bcInfo.CommonCause}");
                    actions.Insert(0, $"Investigate memory dump using WinDbg targeting stop code {bcInfo.Name} ({hexCode}).");
                }
            }

            // Capture Dump File location
            if (log.EventData.TryGetValue("DumpFile", out var dump) && !string.IsNullOrWhiteSpace(dump))
            {
                decoded["Dump File Location"] = dump;
                actions.Add($"Analyze saved crash dump file: {dump}");
            }
            else
            {
                decoded["Dump File Expected"] = @"C:\Windows\Minidump or C:\Windows\MEMORY.DMP";
            }
        }

        // 2. Application Error (Event 1000)
        else if (log.EventId == 1000 && log.ProviderName.Contains("Application Error", StringComparison.OrdinalIgnoreCase))
        {
            subsystem = "Application Execution Environment (Win32 / Native)";
            impact = "Process Termination: Crashing program was aborted to prevent memory corruption";

            if (log.EventData.TryGetValue("FaultingApplicationName", out var appName) && !string.IsNullOrWhiteSpace(appName))
            {
                decoded["Crashing App"] = appName;
            }
            if (log.EventData.TryGetValue("FaultingModuleName", out var modName) && !string.IsNullOrWhiteSpace(modName))
            {
                decoded["Faulting Module"] = modName;
                if (WellKnownModules.TryGetValue(modName, out var modInfo))
                {
                    decoded["Module Identity"] = $"{modInfo.Type} — {modInfo.Description}";
                }
            }
            if (log.EventData.TryGetValue("ExceptionCode", out var exCode) && !string.IsNullOrWhiteSpace(exCode))
            {
                decoded["Exception Code"] = exCode;
                var meaning = DecodeExceptionCode(exCode);
                decoded["Exception Meaning"] = meaning;
                causes.Insert(0, $"Process crashed with {exCode} ({meaning}).");
            }
            if (log.EventData.TryGetValue("FaultOffset", out var offset) && !string.IsNullOrWhiteSpace(offset))
            {
                decoded["Instruction Offset"] = offset;
            }
            if (log.EventData.TryGetValue("FaultingApplicationPath", out var appPath) && !string.IsNullOrWhiteSpace(appPath))
            {
                decoded["Application Path"] = appPath;
                fixCmd = $"Get-Process -Name \"{Path.GetFileNameWithoutExtension(appName ?? "app")}\" -ErrorAction SilentlyContinue";
            }
        }

        // 3. .NET Runtime (Event 1026)
        else if (log.EventId == 1026 && log.ProviderName.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase))
        {
            subsystem = "Common Language Runtime (.NET CLR)";
            impact = "Managed Process Abort: Unhandled exception escaped all try/catch handlers";
            fixCmd = "dotnet --info";

            if (log.EventData.TryGetValue("Param1", out var p1))
            {
                decoded["Managed Context"] = p1;
            }
            if (log.EventData.TryGetValue("Param2", out var p2))
            {
                decoded["Runtime Version"] = p2;
            }
            if (log.EventData.TryGetValue("Param3", out var p3))
            {
                decoded["Exception Trace"] = p3;
            }

            causes.Insert(0, "A managed exception was thrown and not intercepted by the application's top-level error handler.");
            actions.Insert(0, "Review the managed stack trace above for the exact method and line number that threw.");
        }

        // 4. Service Control Manager (7000, 7001, 7009, 7023, 7031, 7034)
        else if (log.ProviderName.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
        {
            subsystem = "Windows Service Control Manager (SCM)";
            impact = "Background Service Degradation: Scheduled tasks or background daemons unavailable";

            string? serviceName = null;
            if (log.EventData.TryGetValue("param1", out var s1) || log.EventData.TryGetValue("ServiceName", out s1))
            {
                serviceName = s1;
                decoded["Service Identifier"] = serviceName;
                fixCmd = $"sc.exe query \"{serviceName}\"; sc.exe qc \"{serviceName}\"";
            }

            if (log.EventData.TryGetValue("param2", out var s2))
            {
                decoded["Service Param / State"] = s2;
                if (int.TryParse(s2, out var exitCode) && ServiceErrorCodes.TryGetValue(exitCode, out var scInfo))
                {
                    decoded["SCM Error Code"] = $"{exitCode} ({scInfo.Name})";
                    decoded["Error Description"] = scInfo.Description;
                    causes.Insert(0, $"Service failed with exit code {exitCode}: {scInfo.Description}");
                }
            }

            actions.Add($"Run 'services.msc' and locate '{serviceName ?? "the service"}' to inspect Startup Type and Log On account.");
        }

        // 5. Security Audit 4625 (Failed Logon)
        else if (log.EventId == 4625)
        {
            subsystem = "Local Security Authority (LSASS / Kerberos / NTLM)";
            impact = "Access Denied: Credential rejected or unauthorized access attempt blocked";
            fixCmd = "net user";

            if (log.EventData.TryGetValue("TargetUserName", out var targetUser))
                decoded["Target Account"] = targetUser;
            if (log.EventData.TryGetValue("TargetDomainName", out var targetDomain))
                decoded["Target Domain"] = targetDomain;
            if (log.EventData.TryGetValue("WorkstationName", out var wsName))
                decoded["Client Workstation"] = wsName;
            if (log.EventData.TryGetValue("IpAddress", out var ip) && !string.IsNullOrWhiteSpace(ip) && ip != "-")
            {
                decoded["Source IP Address"] = ip;
                if (log.EventData.TryGetValue("IpPort", out var port))
                    decoded["Source Port"] = port;
            }

            if (log.EventData.TryGetValue("LogonType", out var logonTypeStr) && int.TryParse(logonTypeStr, out var logonType))
            {
                decoded["Logon Type"] = DecodeLogonType(logonType);
            }

            if (log.EventData.TryGetValue("SubStatus", out var subStatus))
            {
                decoded["SubStatus Code"] = subStatus;
                decoded["SubStatus Explanation"] = DecodeSubStatus(subStatus);
            }
        }

        // 6. Disk (7, 11) & NTFS (55, 98)
        else if (log.ProviderName.Contains("Disk", StringComparison.OrdinalIgnoreCase) ||
                 log.ProviderName.Contains("Ntfs", StringComparison.OrdinalIgnoreCase))
        {
            subsystem = "Storage Controller & NTFS Filesystem";
            impact = "Data Integrity Risk: Physical sector defect or filesystem metadata inconsistency";
            // The event may refer to a non-system volume. Do not prescribe an
            // offline, modifying repair against C: without identifying its target.
            fixCmd = null;

            foreach (var kv in log.EventData)
            {
                decoded[kv.Key] = kv.Value;
            }

            causes.Insert(0, "Storage driver detected bad physical sectors or corrupted filesystem indices.");
            actions.Insert(0, "Identify the affected disk or volume from the event and its neighboring records, secure a current backup, then choose a targeted read-only or repair scan appropriate to that volume.");
        }

        // 7. General Error / Critical Fallback
        else
        {
            subsystem ??= $"{log.ProviderName} Component";
            impact ??= log.Level == LogSeverityLevel.Critical
                ? "Severe: System component encountered an unrecoverable fault"
                : "Operational Error: Process or subsystem reported failure state";

            foreach (var kv in log.EventData.Take(8))
            {
                decoded[kv.Key] = kv.Value;
            }
        }

        return baseExplanation with
        {
            Subsystem = subsystem,
            ImpactAssessment = impact,
            ForensicFixCommand = fixCmd,
            DecodedFields = decoded,
            ProbableCauses = causes.Distinct().ToList(),
            RecommendedActions = actions.Distinct().ToList(),
            TechnicalDetails = details.Distinct().ToList()
        };
    }

    private static string DecodeExceptionCode(string code) => code.ToUpperInvariant() switch
    {
        "0XC0000005" => "STATUS_ACCESS_VIOLATION — Memory read/write to unmapped address",
        "0XC0000409" => "STATUS_STACK_BUFFER_OVERRUN — Security /GS guard check failed",
        "0XE0434352" => "EXCEPTION_MSVC_CLR — Managed .NET exception terminated the process",
        "0XC000001D" => "STATUS_ILLEGAL_INSTRUCTION — Processor instruction not supported by CPU",
        "0XC00000FD" => "STATUS_STACK_OVERFLOW — Thread call stack limit exceeded",
        "0XC0000374" => "STATUS_HEAP_CORRUPTION — Process corrupted its internal memory heap",
        "0X80000003" => "STATUS_BREAKPOINT — Hardcoded debug breakpoint reached",
        "0XC0000008" => "STATUS_INVALID_HANDLE — Closed or uninitialized handle used",
        _ => "Unhandled Win32 Exception Code"
    };

    private static string DecodeLogonType(int type) => type switch
    {
        2 => "2 (Interactive — Physical Keyboard/Console logon)",
        3 => "3 (Network — SMB share, IPC$, mapped drive or RPC connection)",
        4 => "4 (Batch — Windows Scheduled Task execution)",
        5 => "5 (Service — Windows Background Service startup)",
        7 => "7 (Unlock — User unlocked workstation screen)",
        8 => "8 (NetworkCleartext — Plaintext credentials transmitted over network)",
        9 => "9 (NewCredentials — RunAs with /netonly credentials)",
        10 => "10 (RemoteInteractive — Remote Desktop Protocol / RDP session)",
        11 => "11 (CachedInteractive — Logged on with cached credentials while offline)",
        _ => $"{type} (Windows Logon Category {type})"
    };

    private static string DecodeSubStatus(string subStatus) => subStatus.ToUpperInvariant() switch
    {
        "0XC000006A" => "STATUS_WRONG_PASSWORD — The user account exists, but the password provided was wrong.",
        "0XC000006E" => "STATUS_NO_SUCH_USER — The targeted username does not exist on this machine or domain.",
        "0XC0000234" => "STATUS_ACCOUNT_LOCKED_OUT — User account is locked due to too many failed password attempts.",
        "0XC0000072" => "STATUS_ACCOUNT_DISABLED — The targeted user account is disabled by administrator policy.",
        "0XC000006F" => "STATUS_INVALID_LOGON_HOURS — User is not authorized to log on at this time of day.",
        "0XC0000193" => "STATUS_ACCOUNT_EXPIRED — The user account expiration date has passed.",
        "0XC0000071" => "STATUS_PASSWORD_EXPIRED — User password must be changed before logging on.",
        _ => "Logon verification rejected by authentication authority"
    };
}
