/*
 * StackUnwinderTest.cpp — comprehensive test for StackUnwinderLib
 *
 * Four test scenarios, each run in three passes:
 *   Pass 1 — "Normal":         modules from Toolhelp, export names only
 *   Pass 2 — "Auto-Discovery": zero modules, single-pass RIP scan
 *   Pass 3 — "PDB Resolution": full symbol names via DbgHelp + PDBs
 *
 * Scenarios:
 *   1. Recursion        — same function 10 deep
 *   2. Deep chain       — A -> B -> C -> D -> E -> F (unique named functions)
 *   3. Function pointer — calls through arrays of function pointers
 *   4. Win32 callback   — EnumWindows calls our callback, crosses DLL boundary
 *
 * Link with: dbghelp.lib, user32.lib
 *
 * NOTE: If your project uses precompiled headers, uncomment:
 */
 // #include "pch.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include "stack_unwinder.h"
#include "stack_unwinder_pdb.h"
#include "stack_unwinder_pdb.h"

/* ================================================================== */
/*  Infrastructure (shared by all tests)                              */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/*  ReadMemory callback — trivial for same-process user-mode          */
/* ------------------------------------------------------------------ */
static BOOLEAN CALLBACK
ReadProcessMemory_CB(
    _Out_writes_bytes_(Size) PVOID  Destination,
    _In_ UINT64 SourceAddress,
    _In_ UINT64 Size)
{
    __try {
        memcpy(Destination, (const void*)(ULONG_PTR)SourceAddress, (size_t)Size);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/*  Enumerate loaded modules via toolhelp and register them           */
/* ------------------------------------------------------------------ */
static void
RegisterAllModules(UNWIND_CONTEXT* Ctx)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    if (Module32First(hSnap, &me)) {
        do {
            char name[64];
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, name, sizeof(name), NULL, NULL);

            UnwinderAddModule(Ctx,
                (UINT64)(ULONG_PTR)me.modBaseAddr,
                (UINT64)me.modBaseSize,
                name);
        } while (Module32Next(hSnap, &me));
    }

    CloseHandle(hSnap);
}

/* ------------------------------------------------------------------ */
/*  Convert a Windows CONTEXT to the unwinder's GPR array             */
/* ------------------------------------------------------------------ */
static void
ContextToGpr(const CONTEXT* WinCtx, UINT64 Gpr[GPR_COUNT])
{
    Gpr[GPR_RAX] = WinCtx->Rax;
    Gpr[GPR_RCX] = WinCtx->Rcx;
    Gpr[GPR_RDX] = WinCtx->Rdx;
    Gpr[GPR_RBX] = WinCtx->Rbx;
    Gpr[GPR_RSP] = WinCtx->Rsp;
    Gpr[GPR_RBP] = WinCtx->Rbp;
    Gpr[GPR_RSI] = WinCtx->Rsi;
    Gpr[GPR_RDI] = WinCtx->Rdi;
    Gpr[GPR_R8] = WinCtx->R8;
    Gpr[GPR_R9] = WinCtx->R9;
    Gpr[GPR_R10] = WinCtx->R10;
    Gpr[GPR_R11] = WinCtx->R11;
    Gpr[GPR_R12] = WinCtx->R12;
    Gpr[GPR_R13] = WinCtx->R13;
    Gpr[GPR_R14] = WinCtx->R14;
    Gpr[GPR_R15] = WinCtx->R15;
}

/* ------------------------------------------------------------------ */
/*  Helper: format trace and print it                                 */
/* ------------------------------------------------------------------ */
static void
PrintTrace(UNWIND_CONTEXT* Ctx)
{
    INT32 needed = UnwinderFormatTrace(Ctx, NULL, 0);
    CHAR* buf = (CHAR*)malloc(needed);
    if (buf) {
        UnwinderFormatTrace(Ctx, buf, needed);
        printf("%s", buf);
        free(buf);
    }
}

/* ------------------------------------------------------------------ */
/*  Run all passes for a captured CONTEXT                             */
/* ------------------------------------------------------------------ */
__declspec(noinline) static void
RunAllPasses(const CONTEXT* ctx, const char* testName)
{
    printf("\n");
    printf("##################################################\n");
    printf("  TEST: %s\n", testName);
    printf("##################################################\n\n");

    /* Pass 1 — Normal (Toolhelp + exports only) */
    {
        UNWIND_CONTEXT uc;
        UnwinderInit(&uc, ReadProcessMemory_CB);
        RegisterAllModules(&uc);

        UINT64 gpr[GPR_COUNT];
        ContextToGpr(ctx, gpr);

        UnwinderWalk(&uc, ctx->Rip, ctx->Rsp, gpr);
        UnwinderResolveExports(&uc);

        printf("  --- Pass 1: Normal (Toolhelp, exports only) ---\n");
        PrintTrace(&uc);
    }

    printf("\n");

    /* Pass 2 — Auto-Discovery (single pass, no OS APIs) */
    {
        UNWIND_CONTEXT uc;
        UnwinderInit(&uc, ReadProcessMemory_CB);
        UnwinderEnableAutoDiscovery(&uc, 32 * 1024 * 1024);

        UINT64 gpr[GPR_COUNT];
        ContextToGpr(ctx, gpr);

        UnwinderWalk(&uc, ctx->Rip, ctx->Rsp, gpr);

        printf("  --- Pass 2: Auto-Discovery (%d module(s) found) ---\n",
            uc.ModuleCount);
        PrintTrace(&uc);
    }

    printf("\n");

    /* Pass 3 — PDB Resolution on the formatted trace string.
     *
     * This simulates the offline workflow:
     *   1. Hypervisor produces a trace string (no PDB available there)
     *   2. Later, on a dev machine, feed the string + PDB path to
     *      UnwinderResolveTraceWithPdb to get real function names.
     *
     * Here we use the auto-discovery trace (Pass 2 output) as input,
     * then resolve it with our own EXE's PDB.
     */
    {
        UNWIND_CONTEXT uc;
        UnwinderInit(&uc, ReadProcessMemory_CB);
        UnwinderEnableAutoDiscovery(&uc, 32 * 1024 * 1024);

        UINT64 gpr[GPR_COUNT];
        ContextToGpr(ctx, gpr);
        UnwinderWalk(&uc, ctx->Rip, ctx->Rsp, gpr);

        /* Format the raw trace (this is what the hypervisor would log) */
        INT32 traceLen = UnwinderFormatTrace(&uc, NULL, 0);
        CHAR* rawTrace = (CHAR*)malloc(traceLen);
        if (rawTrace) {
            UnwinderFormatTrace(&uc, rawTrace, traceLen);

            /* Get our EXE path — the PDB should be next to it */
            CHAR exePath[MAX_PATH];
            GetModuleFileNameA(NULL, exePath, MAX_PATH);

            /*
             * Build PDB module mappings.
             * In the auto-discovery trace, the EXE appears as whatever
             * name the export directory gave it.  For a VS-built EXE
             * that's often the project name, but in discovery mode it
             * may be "unknown" if there's no export directory.
             *
             * We map both the real EXE name and "unknown" to the same PDB.
             */
            CHAR exeName[64];
            {
                const CHAR* p = exePath;
                const CHAR* last = exePath;
                while (*p) { if (*p == '\\' || *p == '/') last = p + 1; p++; }
                strncpy_s(exeName, sizeof(exeName), last, sizeof(exeName) - 1);
            }

            PDB_MODULE_ENTRY pdbs[2];
            pdbs[0].ModuleName = exeName;
            pdbs[0].PdbOrImagePath = exePath;
            pdbs[1].ModuleName = "unknown";
            pdbs[1].PdbOrImagePath = exePath;

            /* Resolve — this is the offline post-analysis step */
            INT32 resolvedLen = UnwinderResolveTraceWithPdb(
                rawTrace, pdbs, 2, NULL, 0);

            CHAR* resolvedTrace = (CHAR*)malloc(resolvedLen);
            if (resolvedTrace) {
                UnwinderResolveTraceWithPdb(
                    rawTrace, pdbs, 2, resolvedTrace, resolvedLen);

                printf("  --- Pass 3: PDB Resolution (offline, from trace string) ---\n");
                printf("%s", resolvedTrace);
                free(resolvedTrace);
            }
            free(rawTrace);
        }
    }
}

/* ================================================================== */
/*  Test 1: Recursion (same function, 10 deep)                        */
/* ================================================================== */

__declspec(noinline) static void
CaptureTrace(const char* testName)
{
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    RunAllPasses(&ctx, testName);
}

static const int RECURSION_DEPTH = 10;

__declspec(noinline) static void
RecursiveX(int depth)
{
    if (depth >= RECURSION_DEPTH) {
        CaptureTrace("Recursion (10 deep)");
        return;
    }
    RecursiveX(depth + 1);
}

static void Test_Recursion(void)
{
    RecursiveX(0);
}

/* ================================================================== */
/*  Test 2: Deep chain of unique named functions                      */
/*                                                                    */
/*  A → B → C → D → E → F → capture                                  */
/*  Each function should appear with a distinct name in the trace.    */
/* ================================================================== */

__declspec(noinline) static void ChainF(void) {
    CaptureTrace("Deep Chain (A->B->C->D->E->F)");
}
__declspec(noinline) static void ChainE(void) { ChainF(); }
__declspec(noinline) static void ChainD(void) { ChainE(); }
__declspec(noinline) static void ChainC(void) { ChainD(); }
__declspec(noinline) static void ChainB(void) { ChainC(); }
__declspec(noinline) static void ChainA(void) { ChainB(); }

static void Test_DeepChain(void)
{
    ChainA();
}

/* ================================================================== */
/*  Test 3: Function pointer / callback chain                         */
/*                                                                    */
/*  Calls through an array of function pointers. Tests that the       */
/*  unwinder handles indirect calls (the call target isn't visible    */
/*  in the binary's control flow).                                    */
/* ================================================================== */

/* Forward declarations */
__declspec(noinline) static void FpStageA(void);
__declspec(noinline) static void FpStageB(void);
__declspec(noinline) static void FpStageC(void);
__declspec(noinline) static void FpStageD(void);

typedef void (*STAGE_FN)(void);

/*
 * Use volatile so the compiler can't see through the function
 * pointer and inline or devirtualize the calls.
 */
static volatile STAGE_FN g_StageChain[] = {
    FpStageA,
    FpStageB,
    FpStageC,
    FpStageD,
    NULL
};

__declspec(noinline) static void
FpDispatch(int index)
{
    STAGE_FN fn = g_StageChain[index];
    if (fn) fn();
}

__declspec(noinline) static void FpStageD(void) {
    CaptureTrace("Function Pointer Chain (Dispatch->A->B->C->D)");
}
__declspec(noinline) static void FpStageC(void) { FpDispatch(3); }
__declspec(noinline) static void FpStageB(void) { FpDispatch(2); }
__declspec(noinline) static void FpStageA(void) { FpDispatch(1); }

static void Test_FunctionPointer(void)
{
    FpDispatch(0);
}

/* ================================================================== */
/*  Test 4: Win32 API callback (EnumWindows)                          */
/*                                                                    */
/*  The OS calls our callback from inside user32.dll. The trace       */
/*  should cross the DLL boundary:                                    */
/*    our callback → user32!EnumWindows internals → our Test function */
/*                                                                    */
/*  This exercises unwinding across module boundaries where .pdata    */
/*  comes from different PE images.                                   */
/* ================================================================== */

static BOOL g_CapturedInCallback = FALSE;

static BOOL CALLBACK
EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    (void)hwnd;
    (void)lParam;

    if (!g_CapturedInCallback) {
        g_CapturedInCallback = TRUE;
        CaptureTrace("Win32 Callback (EnumWindows -> our callback)");
    }

    /* Return FALSE to stop enumeration after first capture */
    return FALSE;
}

static void Test_Win32Callback(void)
{
    g_CapturedInCallback = FALSE;
    EnumWindows(EnumWindowsCallback, 0);
}

/* ================================================================== */
/*  Test 5: Offline PDB resolution from a raw trace string            */
/*                                                                    */
/*  This simulates the real hypervisor workflow end-to-end:            */
/*    Step 1 — Capture trace with auto-discovery (no OS, no PDBs)     */
/*    Step 2 — Format it to a string (what the hypervisor logs)       */
/*    Step 3 — Print the RAW trace (sub_XXXX names)                   */
/*    Step 4 — Feed the string + PDB paths to the resolver            */
/*    Step 5 — Print the RESOLVED trace (real function names)         */
/*                                                                    */
/*  Uses a simple call chain so you can easily compare the output.    */
/* ================================================================== */

__declspec(noinline) static void PdbTestInner(void);
__declspec(noinline) static void PdbTestMiddle(void);
__declspec(noinline) static void PdbTestOuter(void);

__declspec(noinline) static void
PdbTestInner(void)
{
    CONTEXT ctx;
    RtlCaptureContext(&ctx);

    printf("\n");
    printf("##################################################\n");
    printf("  TEST: Offline PDB Resolution\n");
    printf("##################################################\n\n");

    /* ---- Step 1: Capture with auto-discovery (simulates hypervisor) ---- */
    UNWIND_CONTEXT uc;
    UnwinderInit(&uc, ReadProcessMemory_CB);
    UnwinderEnableAutoDiscovery(&uc, 32 * 1024 * 1024);

    UINT64 gpr[GPR_COUNT];
    ContextToGpr(&ctx, gpr);
    UnwinderWalk(&uc, ctx.Rip, ctx.Rsp, gpr);

    /* ---- Step 2: Format to string (this is what the hypervisor logs) ---- */
    INT32 rawLen = UnwinderFormatTrace(&uc, NULL, 0);
    CHAR* rawTrace = (CHAR*)malloc(rawLen);
    if (!rawTrace) return;
    UnwinderFormatTrace(&uc, rawTrace, rawLen);

    /* ---- Step 3: Print RAW trace ---- */
    printf("  --- RAW trace (as the hypervisor would log it) ---\n");
    printf("%s\n", rawTrace);

    /* ---- Step 4: Resolve with PDB ---- */
    /*
     * Build module-to-PDB mappings.
     * We use our own EXE path — DbgHelp will find the .pdb next to it.
     *
     * In a real scenario you'd map each module name from the trace
     * to the corresponding PDB file path on your dev machine.
     */
    CHAR exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    /* Extract just the filename for matching */
    CHAR exeName[64];
    {
        const CHAR* p = exePath;
        const CHAR* last = exePath;
        while (*p) { if (*p == '\\' || *p == '/') last = p + 1; p++; }
        strncpy_s(exeName, sizeof(exeName), last, sizeof(exeName) - 1);
    }

    PDB_MODULE_ENTRY pdbs[2];
    pdbs[0].ModuleName = exeName;     /* e.g. "StackUnwinderTest.exe" */
    pdbs[0].PdbOrImagePath = exePath;
    pdbs[1].ModuleName = "unknown";   /* auto-discovery fallback name */
    pdbs[1].PdbOrImagePath = exePath;

    INT32 resolvedLen = UnwinderResolveTraceWithPdb(
        rawTrace, pdbs, 2, NULL, 0);

    CHAR* resolvedTrace = (CHAR*)malloc(resolvedLen);
    if (resolvedTrace) {
        UnwinderResolveTraceWithPdb(
            rawTrace, pdbs, 2, resolvedTrace, resolvedLen);

        /* ---- Step 5: Print RESOLVED trace ---- */
        printf("  --- RESOLVED trace (after PDB offline analysis) ---\n");
        printf("%s\n", resolvedTrace);

        free(resolvedTrace);
    }

    free(rawTrace);
}

__declspec(noinline) static void
PdbTestMiddle(void)
{
    PdbTestInner();
}

__declspec(noinline) static void
PdbTestOuter(void)
{
    PdbTestMiddle();
}

static void Test_OfflinePdb(void)
{
    PdbTestOuter();
}

/* ================================================================== */
/*  Offline PDB resolver from command line                            */
/*                                                                    */
/*  Usage:                                                            */
/*    StackUnwinderTest.exe resolve <trace.txt> <pdbs.txt>            */
/*                                                                    */
/*  trace.txt — raw trace string from UnwinderFormatTrace             */
/*  pdbs.txt  — one mapping per line:  ModuleName=PathToPdbOrImage    */
/*                                                                    */
/*  Example pdbs.txt:                                                 */
/*    ntoskrnl.exe=C:\symbols\ntkrnlmp.pdb                           */
/*    hal.dll=C:\symbols\hal.pdb                                      */
/*    StackUnwinder=C:\build\StackUnwinder.exe                        */
/*    unknown=C:\mydriver\mydriver.pdb                                */
/* ================================================================== */

/* Read entire file into a malloc'd buffer. Returns NULL on failure. */
static CHAR*
ReadFileToString(const CHAR* Path, INT32* OutSize)
{
    HANDLE hFile;
    DWORD  fileSize, bytesRead;
    CHAR* buf;

    hFile = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error: Cannot open file: %s\n", Path);
        return NULL;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        printf("Error: Empty or invalid file: %s\n", Path);
        CloseHandle(hFile);
        return NULL;
    }

    buf = (CHAR*)malloc(fileSize + 1);
    if (!buf) {
        CloseHandle(hFile);
        return NULL;
    }

    if (!ReadFile(hFile, buf, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("Error: Failed to read file: %s\n", Path);
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }

    buf[fileSize] = '\0';
    if (OutSize) *OutSize = (INT32)fileSize;
    CloseHandle(hFile);
    return buf;
}

/*
 * Parse pdbs.txt into an array of PDB_MODULE_ENTRY.
 *
 * Format: one mapping per line, "ModuleName=PdbPath"
 * Blank lines and lines starting with '#' are ignored.
 *
 * Returns the number of entries parsed.
 * moduleNames and pdbPaths are parallel arrays of pointers into
 * the mutable fileBuffer (we null-terminate in place).
 */
static INT32
ParsePdbMappings(
    CHAR* fileBuffer,
    CHAR* moduleNames[],
    CHAR* pdbPaths[],
    INT32   maxEntries
)
{
    INT32  count = 0;
    CHAR* p = fileBuffer;

    while (*p && count < maxEntries) {
        CHAR* lineStart = p;
        CHAR* lineEnd;
        CHAR* eq;

        /* Find end of line */
        while (*p && *p != '\n' && *p != '\r') p++;
        lineEnd = p;

        /* Skip newlines */
        while (*p == '\n' || *p == '\r') p++;

        /* Null-terminate the line */
        *lineEnd = '\0';

        /* Skip blank lines and comments */
        if (lineStart[0] == '\0' || lineStart[0] == '#')
            continue;

        /* Find '=' separator */
        eq = lineStart;
        while (*eq && *eq != '=') eq++;
        if (*eq != '=') {
            printf("Warning: Skipping invalid line (no '='): %s\n", lineStart);
            continue;
        }

        /* Split into name and path */
        *eq = '\0';
        moduleNames[count] = lineStart;
        pdbPaths[count] = eq + 1;

        /* Trim trailing spaces from module name */
        {
            CHAR* end = eq - 1;
            while (end >= lineStart && (*end == ' ' || *end == '\t')) {
                *end = '\0';
                end--;
            }
        }

        /* Trim leading spaces from path */
        while (*pdbPaths[count] == ' ' || *pdbPaths[count] == '\t')
            pdbPaths[count]++;

        count++;
    }

    return count;
}

static int
RunOfflineResolve(const CHAR* tracePath, const CHAR* pdbsPath)
{
    CHAR* traceStr = NULL;
    CHAR* pdbsStr = NULL;
    INT32  traceSize, pdbsSize;
    CHAR* moduleNames[MAX_PDB_MODULES];
    CHAR* pdbPathPtrs[MAX_PDB_MODULES];
    PDB_MODULE_ENTRY pdbEntries[MAX_PDB_MODULES];
    INT32  pdbCount, i;
    INT32  resolvedLen;
    CHAR* resolvedTrace = NULL;
    int    ret = 1;

    printf("=== Offline PDB Resolution ===\n\n");

    /* Read trace file */
    traceStr = ReadFileToString(tracePath, &traceSize);
    if (!traceStr) goto done;
    printf("Loaded trace from: %s (%d bytes)\n", tracePath, traceSize);

    /* Read and parse PDB mappings file */
    pdbsStr = ReadFileToString(pdbsPath, &pdbsSize);
    if (!pdbsStr) goto done;

    pdbCount = ParsePdbMappings(pdbsStr, moduleNames, pdbPathPtrs, MAX_PDB_MODULES);
    if (pdbCount == 0) {
        printf("Error: No valid PDB mappings found in: %s\n", pdbsPath);
        goto done;
    }

    printf("Loaded %d PDB mapping(s) from: %s\n", pdbCount, pdbsPath);
    for (i = 0; i < pdbCount; i++) {
        printf("  [%d] \"%s\" -> \"%s\"\n", i, moduleNames[i], pdbPathPtrs[i]);
    }

    /* Build PDB_MODULE_ENTRY array */
    for (i = 0; i < pdbCount; i++) {
        pdbEntries[i].ModuleName = moduleNames[i];
        pdbEntries[i].PdbOrImagePath = pdbPathPtrs[i];
    }

    /* Print the raw input trace */
    printf("\n--- Input trace ---\n");
    printf("%s", traceStr);
    if (traceStr[traceSize - 1] != '\n') printf("\n");

    /* Resolve */
    resolvedLen = UnwinderResolveTraceWithPdb(traceStr, pdbEntries, pdbCount, NULL, 0);
    resolvedTrace = (CHAR*)malloc(resolvedLen);
    if (!resolvedTrace) {
        printf("Error: Failed to allocate %d bytes for resolved trace\n", resolvedLen);
        goto done;
    }

    UnwinderResolveTraceWithPdb(traceStr, pdbEntries, pdbCount, resolvedTrace, resolvedLen);

    /* Print resolved trace */
    printf("\n--- Resolved trace ---\n");
    printf("%s", resolvedTrace);
    if (resolvedTrace[resolvedLen - 2] != '\n') printf("\n");

    ret = 0;

done:
    if (resolvedTrace) free(resolvedTrace);
    if (traceStr)      free(traceStr);
    if (pdbsStr)       free(pdbsStr);
    return ret;
}

/* ================================================================== */
/*  Test runner                                                       */
/* ================================================================== */

typedef void (*TEST_FN)(void);

typedef struct _TEST_ENTRY {
    const char* Name;
    TEST_FN     Fn;
} TEST_ENTRY;

static const TEST_ENTRY g_Tests[] = {
    { "Recursion",        Test_Recursion       },
    { "Deep Chain",       Test_DeepChain       },
    { "Function Pointer", Test_FunctionPointer },
    { "Win32 Callback",   Test_Win32Callback   },
    { "Offline PDB",      Test_OfflinePdb      },
};

static int
RunTests(void)
{
    HMODULE hExe = GetModuleHandleA(NULL);
    int count = sizeof(g_Tests) / sizeof(g_Tests[0]);
    int i;

    printf("Image base: 0x%016llX\n", (UINT64)(ULONG_PTR)hExe);
    printf("Stack Unwinder Test - %d scenarios\n", count);
    printf("==================================================\n");

    for (i = 0; i < count; i++) {
        printf("\n>>> Running: %s\n", g_Tests[i].Name);
        g_Tests[i].Fn();
    }

    printf("\n==================================================\n");
    printf("All tests complete.\n");
    return 0;
}

/* ================================================================== */
/*  Usage / Help                                                      */
/* ================================================================== */

static void
PrintUsage(const char* exeName)
{
    printf("Stack Unwinder - Test & Offline PDB Resolver\n\n");
    printf("Usage:\n");
    printf("  %s                              Run all test scenarios\n", exeName);
    printf("  %s test                         Run all test scenarios\n", exeName);
    printf("  %s resolve <trace.txt> <pdbs.txt>  Resolve a trace with PDBs\n\n", exeName);
    printf("trace.txt:\n");
    printf("  Raw trace output from UnwinderFormatTrace (as logged by hypervisor)\n\n");
    printf("pdbs.txt (one mapping per line):\n");
    printf("  # Lines starting with '#' are comments\n");
    printf("  ModuleName=C:\\path\\to\\file.pdb\n");
    printf("  ntoskrnl.exe=C:\\symbols\\ntkrnlmp.pdb\n");
    printf("  hal.dll=C:\\symbols\\hal.pdb\n");
    printf("  StackUnwinder=C:\\build\\StackUnwinder.exe\n");
    printf("  unknown=C:\\mydriver\\mydriver.pdb\n");
}

/* ================================================================== */
/*  Entry point                                                       */
/* ================================================================== */

int main(int argc, char* argv[])
{
    /* No args or "test" → run test scenarios */
    if (argc <= 1)
        return RunTests();

    if (_stricmp(argv[1], "test") == 0)
        return RunTests();

    /* "resolve <trace.txt> <pdbs.txt>" → offline PDB resolution */
    if (_stricmp(argv[1], "resolve") == 0) {
        if (argc < 4) {
            printf("Error: 'resolve' requires two arguments.\n\n");
            PrintUsage(argv[0]);
            return 1;
        }
        return RunOfflineResolve(argv[2], argv[3]);
    }

    /* Unknown command */
    printf("Error: Unknown command '%s'\n\n", argv[1]);
    PrintUsage(argv[0]);
    return 1;
}