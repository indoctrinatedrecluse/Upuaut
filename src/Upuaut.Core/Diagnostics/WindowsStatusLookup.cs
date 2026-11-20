namespace Upuaut.Core.Diagnostics;

public sealed record WindowsStatusInfo(string SymbolicName, string Meaning, string Category = "Native Status");

/// <summary>
/// Authoritative lookup table for Windows NTSTATUS, HRESULT, Win32 error codes, and crash bugchecks.
/// </summary>
public static class WindowsStatusLookup
{
    private static readonly Dictionary<uint, WindowsStatusInfo> Codes = new()
    {
        // Core Process & Memory Crash Exceptions (NTSTATUS)
        [0xC0000005] = new("STATUS_ACCESS_VIOLATION", "The software attempted to read or write to an invalid memory address.", "Memory Exception"),
        [0xC0000006] = new("STATUS_IN_PAGE_ERROR", "The process encountered an I/O error while attempting to page memory into its address space.", "Paging Exception"),
        [0xC0000008] = new("STATUS_INVALID_HANDLE", "An invalid, closed, or uninitialized handle was passed to a system call.", "Handle Exception"),
        [0xC000001D] = new("STATUS_ILLEGAL_INSTRUCTION", "An attempt was made to execute an illegal processor instruction or instruction not supported by the CPU.", "Execution Exception"),
        [0xC0000025] = new("STATUS_NONCONTINUABLE_EXCEPTION", "An exception handler attempted to resume execution after a noncontinuable exception.", "Execution Exception"),
        [0xC00000FD] = new("STATUS_STACK_OVERFLOW", "A thread stack overflow occurred. A new guard page for the stack cannot be allocated.", "Stack Exception"),
        [0xC0000374] = new("STATUS_HEAP_CORRUPTION", "A process has corrupted its own internal memory heap structure.", "Memory Exception"),
        [0xC0000409] = new("STATUS_STACK_BUFFER_OVERRUN", "A stack buffer overrun or security /GS guard check failed, triggering fail-fast termination.", "Security Exception"),
        [0x80000003] = new("STATUS_BREAKPOINT", "A software or debugger breakpoint was reached.", "Debug Exception"),
        [0x80000004] = new("STATUS_SINGLE_STEP", "A single instruction step was signaled by the CPU.", "Debug Exception"),
        [0xE0434352] = new("CLR_EXCEPTION", "A managed .NET exception was surfaced through the native Windows structured exception mechanism.", "Managed Exception"),
        [0xC0000096] = new("STATUS_PRIVILEGED_INSTRUCTION", "An attempt was made to execute an instruction reserved for kernel or privileged CPU modes.", "Security Exception"),

        // Common General NTSTATUS
        [0xC0000001] = new("STATUS_UNSUCCESSFUL", "The requested operation did not succeed.", "NTSTATUS"),
        [0xC000000D] = new("STATUS_INVALID_PARAMETER", "An invalid parameter was passed to a service or function.", "NTSTATUS"),
        [0xC0000017] = new("STATUS_NO_MEMORY", "Insufficient virtual memory is available for the operating system to complete the operation.", "Resource Exhaustion"),
        [0xC0000022] = new("STATUS_ACCESS_DENIED", "A process attempted an operation without the required security privileges or ACL permissions.", "Security"),
        [0xC0000034] = new("STATUS_OBJECT_NAME_NOT_FOUND", "The specified object or file was not found.", "NTSTATUS"),
        [0xC0000043] = new("STATUS_SHARING_VIOLATION", "A file cannot be accessed because it is locked by another process.", "File System"),
        [0xC000006A] = new("STATUS_WRONG_PASSWORD", "Logon failure: the specified user password is incorrect.", "Authentication"),
        [0xC000006E] = new("STATUS_NO_SUCH_USER", "Logon failure: the specified user account does not exist.", "Authentication"),
        [0xC000006F] = new("STATUS_INVALID_LOGON_HOURS", "Logon failure: user is not permitted to log on at this time.", "Authentication"),
        [0xC0000071] = new("STATUS_PASSWORD_EXPIRED", "Logon failure: user password has expired and must be updated.", "Authentication"),
        [0xC0000072] = new("STATUS_ACCOUNT_DISABLED", "Logon failure: the account is currently disabled by administrator policy.", "Authentication"),
        [0xC000009A] = new("STATUS_INSUFFICIENT_RESOURCES", "System resource exhaustion (pool memory, handles, or threads).", "Resource Exhaustion"),
        [0xC00000BB] = new("STATUS_NOT_SUPPORTED", "The requested command or hardware feature is not supported by the firmware or driver.", "Hardware / ACPI"),
        [0xC0000135] = new("STATUS_DLL_NOT_FOUND", "The application failed to launch because a required DLL library could not be located.", "Dynamic Link Library"),
        [0xC0000142] = new("STATUS_DLL_INIT_FAILED", "The application failed to initialize a required DLL properly.", "Dynamic Link Library"),
        [0xC0000193] = new("STATUS_ACCOUNT_EXPIRED", "Logon failure: the user account expiration date has passed.", "Authentication"),
        [0xC000021A] = new("STATUS_SYSTEM_PROCESS_TERMINATED", "A critical system process (e.g. csrss.exe or winlogon.exe) unexpectedly stopped.", "System Stability"),
        [0xC0000234] = new("STATUS_ACCOUNT_LOCKED_OUT", "Logon failure: user account is locked out due to excessive failed attempts.", "Authentication"),

        // Common HRESULT & Win32 Errors
        [0x80070005] = new("E_ACCESSDENIED", "Access is denied. The calling account does not possess necessary ACL permissions.", "Win32 / HRESULT"),
        [0x80070002] = new("ERROR_FILE_NOT_FOUND", "The system cannot find the file specified.", "Win32 / HRESULT"),
        [0x80070003] = new("ERROR_PATH_NOT_FOUND", "The system cannot find the path specified.", "Win32 / HRESULT"),
        [0x8007000E] = new("E_OUTOFMEMORY", "Ran out of available memory.", "Win32 / HRESULT"),
        [0x80070057] = new("E_INVALIDARG", "One or more arguments are invalid.", "Win32 / HRESULT"),
        [0x80004005] = new("E_FAIL", "Unspecified general failure.", "Win32 / HRESULT"),
        [0x8007007E] = new("ERROR_MOD_NOT_FOUND", "The specified DLL module could not be found.", "Win32 / HRESULT"),
        [0x800700C1] = new("ERROR_BAD_EXE_FORMAT", "%1 is not a valid Win32 application (32-bit vs 64-bit architecture mismatch).", "Win32 / HRESULT"),
        [0x80070422] = new("ERROR_SERVICE_DISABLED", "The service cannot be started, either because it is disabled or has no enabled devices associated with it.", "Win32 / HRESULT"),
        [0x80070424] = new("ERROR_SERVICE_DOES_NOT_EXIST", "The specified service does not exist as an installed service.", "Win32 / HRESULT"),
        [0x800704C7] = new("ERROR_CANCELLED", "The operation was cancelled by the user or an administrative policy.", "Win32 / HRESULT"),
        [0x800706BA] = new("RPC_S_SERVER_UNAVAILABLE", "The RPC server is unavailable or not listening.", "Win32 / HRESULT"),
        [0x80070643] = new("ERROR_INSTALL_FAILURE", "Fatal error during Windows Installer (MSI) installation.", "Win32 / HRESULT"),
        [0x800F081F] = new("CBS_E_SOURCE_NOT_FOUND", "The source files could not be found for a Windows component or DISM repair operation.", "Component Servicing"),
        [0x80040154] = new("REGDB_E_CLASSNOTREG", "COM Class not registered. The requested COM server registration is missing from the Windows registry.", "COM"),
    };

    public static bool TryGetStatus(uint code, out WindowsStatusInfo info)
    {
        return Codes.TryGetValue(code, out info!);
    }

    public static bool TryGetStatus(string codeString, out WindowsStatusInfo info)
    {
        if (!string.IsNullOrWhiteSpace(codeString))
        {
            var clean = codeString.Trim();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                clean = clean[2..];

            if (uint.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out var code))
            {
                return Codes.TryGetValue(code, out info!);
            }
        }

        info = null!;
        return false;
    }
}
