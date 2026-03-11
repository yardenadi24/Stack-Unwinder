/*
 * test_unwinder.cpp — minimal test for StackUnwinderLib
 *
 * No DbgHelp, no PDBs — uses only the library's built-in PE export
 * table resolution for function names.
 *
 * NOTE: If your project uses precompiled headers, uncomment:
 */
 // #include "pch.h"

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "stack_unwinder.h"

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
/*  CaptureAndWalk — grab current context, run the unwinder           */
/* ------------------------------------------------------------------ */
__declspec(noinline) static void
CaptureAndWalk(void)
{
    CONTEXT ctx;
    RtlCaptureContext(&ctx);

    UNWIND_CONTEXT uc;
    UnwinderInit(&uc, ReadProcessMemory_CB);
    RegisterAllModules(&uc);

    UINT64 initialGpr[GPR_COUNT];
    ContextToGpr(&ctx, initialGpr);

    UnwinderWalk(&uc, ctx.Rip, ctx.Rsp, initialGpr);

    /* Resolve function names from PE export tables (no PDBs needed) */
    UnwinderResolveExports(&uc);

    UnwinderPrintTrace(&uc, printf);
}

/* ------------------------------------------------------------------ */
/*  Recursive function under test                                     */
/* ------------------------------------------------------------------ */
static const int N = 10;

__declspec(noinline) void
RecursiveX(int depth)
{
    if (depth >= N) {
        printf("Reached depth %d - capturing stack trace...\n", depth);
        CaptureAndWalk();
        return;
    }

    printf("RecursiveX depth=%d\n", depth);
    RecursiveX(depth + 1);
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                       */
/* ------------------------------------------------------------------ */
int main()
{
    HMODULE hExe = GetModuleHandleA(NULL);
    printf("Image base: 0x%016llX\n", (UINT64)(ULONG_PTR)hExe);
    printf("Stack Unwinder Test - recursing %d times\n\n", N);
    RecursiveX(0);
    printf("Done.\n");
    return 0;
}