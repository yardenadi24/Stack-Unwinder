/*
 * stack_unwinder_pdb.cpp — Offline PDB symbol resolution
 *
 * Parses the trace string produced by UnwinderFormatTrace, resolves
 * function names via DbgHelp + PDB files, and produces a new trace
 * string with real symbol names.
 *
 * This file uses Win32 APIs and must be linked with dbghelp.lib.
 * It is NOT part of the core unwinder — keep it out of your
 * hypervisor build.
 */

#include "stack_unwinder_pdb.h"

#include <dbghelp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "dbghelp.lib")

 /* ================================================================== */
 /*  Internal helpers                                                  */
 /* ================================================================== */

 /* Fake base addresses for DbgHelp module loading.
    Each PDB module gets a unique base so they don't collide.
    We space them 0x100000000 apart (4 GB) to be safe. */
#define PDB_FAKE_BASE_START  0x0000000100000000ULL
#define PDB_FAKE_BASE_STRIDE 0x0000000100000000ULL

    /* Case-insensitive ASCII compare (no CRT locale dependency) */
static BOOLEAN
StrEqualNoCase(const CHAR* A, const CHAR* B)
{
    while (*A && *B) {
        CHAR a = *A, b = *B;
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return FALSE;
        A++; B++;
    }
    return (*A == *B);
}

/* Get length of string */
static INT32
StrLen(const CHAR* S)
{
    INT32 n = 0;
    while (S[n]) n++;
    return n;
}

/* Check if string ends with a given suffix (case-insensitive) */
static BOOLEAN
EndsWithNoCase(const CHAR* S, INT32 Len, const CHAR* Suffix, INT32 SufLen)
{
    INT32 i;
    if (Len < SufLen) return FALSE;
    for (i = 0; i < SufLen; i++) {
        CHAR a = S[Len - SufLen + i];
        CHAR b = Suffix[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/*
 * Module-name-aware comparison.
 *
 * Matches "StackUnwinder" against "StackUnwinder.exe" (and vice versa).
 * The trace may have the bare name (from debug directory, .pdb stripped)
 * while the user provides the full filename, or the other way around.
 *
 * Strategy: strip known PE extensions (.exe, .dll, .sys, .pdb) from
 * both sides, then compare the stems case-insensitively.
 */
static BOOLEAN
ModuleNameMatch(const CHAR* A, const CHAR* B)
{
    INT32 lenA = StrLen(A);
    INT32 lenB = StrLen(B);
    INT32 stemA = lenA;
    INT32 stemB = lenB;
    INT32 i;

    /* Strip known extensions */
    if (EndsWithNoCase(A, lenA, ".exe", 4)) stemA = lenA - 4;
    else if (EndsWithNoCase(A, lenA, ".dll", 4)) stemA = lenA - 4;
    else if (EndsWithNoCase(A, lenA, ".sys", 4)) stemA = lenA - 4;
    else if (EndsWithNoCase(A, lenA, ".pdb", 4)) stemA = lenA - 4;

    if (EndsWithNoCase(B, lenB, ".exe", 4)) stemB = lenB - 4;
    else if (EndsWithNoCase(B, lenB, ".dll", 4)) stemB = lenB - 4;
    else if (EndsWithNoCase(B, lenB, ".sys", 4)) stemB = lenB - 4;
    else if (EndsWithNoCase(B, lenB, ".pdb", 4)) stemB = lenB - 4;

    if (stemA != stemB) return FALSE;

    for (i = 0; i < stemA; i++) {
        CHAR a = A[i], b = B[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* Parse a hex number from a string, advancing *Ptr past it.
   Handles optional "0x" prefix.  Returns FALSE if no digits found. */
static BOOLEAN
ParseHex(const CHAR** Ptr, UINT64* Out)
{
    const CHAR* p = *Ptr;
    UINT64      val = 0;
    int         digits = 0;

    /* Skip "0x" or "0X" prefix */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    while ((*p >= '0' && *p <= '9') ||
        (*p >= 'A' && *p <= 'F') ||
        (*p >= 'a' && *p <= 'f'))
    {
        val <<= 4;
        if (*p >= '0' && *p <= '9')      val |= (*p - '0');
        else if (*p >= 'A' && *p <= 'F') val |= (*p - 'A' + 10);
        else                             val |= (*p - 'a' + 10);
        p++;
        digits++;
    }

    *Ptr = p;
    *Out = val;
    return (digits > 0);
}

/*
 * Try to parse a frame line and extract module name + RVA.
 *
 * Expected formats:
 *   "  [ 0]  module!func+0xOFF  (0xRVA)"
 *   "  [ 0]  module!sub_XXXX+0xOFF  (0xRVA)"
 *   "  [ 0]  module+0xRVA"
 *   "  [ 0]  ???+0xRVA"
 *
 * On success: fills ModuleName (null-terminated, up to ModNameMax),
 * stores the RVA in *Rva, and returns TRUE.
 */
static BOOLEAN
ParseFrameLine(
    const CHAR* Line,
    _Out_writes_(ModNameMax) CHAR* ModuleName,
    INT32       ModNameMax,
    _Out_ UINT64* Rva
)
{
    const CHAR* p = Line;
    const CHAR* modStart;
    const CHAR* modEnd;
    INT32       len;

    *Rva = 0;
    ModuleName[0] = '\0';

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Must start with '[' (frame index) */
    if (*p != '[') return FALSE;

    /* Skip past "]  " — find the closing bracket then skip spaces */
    while (*p && *p != ']') p++;
    if (*p != ']') return FALSE;
    p++; /* skip ']' */
    while (*p == ' ') p++;

    /* Now p points to "module!func+0x..." or "module+0x..." or "???+0x..." */
    modStart = p;

    /* Find the '!' or '+' that terminates the module name */
    modEnd = p;
    while (*modEnd && *modEnd != '!' && *modEnd != '+' && *modEnd != ' ' && *modEnd != '\n')
        modEnd++;

    len = (INT32)(modEnd - modStart);
    if (len <= 0 || len >= ModNameMax) return FALSE;

    memcpy(ModuleName, modStart, len);
    ModuleName[len] = '\0';

    /* Find the RVA in parentheses at the end: "(0xHEX)" */
    {
        const CHAR* paren = Line;
        const CHAR* lastParen = NULL;

        /* Find the last '(' in the line */
        while (*paren) {
            if (*paren == '(') lastParen = paren;
            paren++;
        }

        if (lastParen) {
            const CHAR* rvaStr = lastParen + 1; /* skip '(' */
            if (ParseHex(&rvaStr, Rva))
                return TRUE;
        }
    }

    /* No parenthesized RVA — try parsing "module+0xRVA" directly */
    if (*modEnd == '+') {
        const CHAR* rvaStr = modEnd + 1;
        if (ParseHex(&rvaStr, Rva))
            return TRUE;
    }

    return FALSE;
}

/*
 * Rebuild a frame line with a resolved symbol name.
 *
 * Writes something like:
 *   "  [ 0]  module!RealFunctionName+0x1A  (0x118A8)"
 *
 * Returns the number of characters written (or that would be written
 * if Buf is NULL — sizing pass).
 */
static INT32
FormatResolvedLine(
    const CHAR* OriginalLine,
    const CHAR* ModuleName,
    const CHAR* SymbolName,
    UINT64      SymbolOffset,
    UINT64      Rva,
    CHAR* Buf,
    INT32       BufSize
)
{
    /* Use snprintf for the resolved line */
    CHAR  tmp[512];
    const CHAR* p = OriginalLine;
    CHAR  prefix[32]; /* "  [ N]  " */
    INT32 pi = 0;
    INT32 len;

    /* Extract the "  [ N]  " prefix from the original line */
    while (*p == ' ' || *p == '\t') {
        if (pi < (INT32)sizeof(prefix) - 1) prefix[pi++] = *p;
        p++;
    }
    /* Copy through "]  " */
    while (*p && *p != ']') {
        if (pi < (INT32)sizeof(prefix) - 1) prefix[pi++] = *p;
        p++;
    }
    if (*p == ']') {
        if (pi < (INT32)sizeof(prefix) - 1) prefix[pi++] = ']';
        p++;
    }
    while (*p == ' ') {
        if (pi < (INT32)sizeof(prefix) - 1) prefix[pi++] = ' ';
        p++;
    }
    prefix[pi] = '\0';

    /* Build the resolved line */
    if (SymbolOffset > 0) {
        len = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
            "%s%s!%s+0x%llX  (0x%llX)",
            prefix, ModuleName, SymbolName,
            (unsigned long long)SymbolOffset,
            (unsigned long long)Rva);
    }
    else {
        len = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
            "%s%s!%s  (0x%llX)",
            prefix, ModuleName, SymbolName,
            (unsigned long long)Rva);
    }

    if (len < 0) len = (INT32)strlen(tmp);

    if (Buf && BufSize > 0) {
        INT32 copy = (len < BufSize - 1) ? len : BufSize - 1;
        memcpy(Buf, tmp, copy);
        Buf[copy] = '\0';
    }

    return len;
}

/* ================================================================== */
/*  Internal: DbgHelp session management                              */
/* ================================================================== */

typedef struct _PDB_SESSION {
    HANDLE  hProcess;           /* Fake process handle for DbgHelp    */
    UINT64  ModBases[MAX_PDB_MODULES];   /* Fake base per module      */
    CHAR    ModNames[MAX_PDB_MODULES][64];
    INT32   ModCount;
    BOOLEAN Initialized;
} PDB_SESSION;

static BOOLEAN
PdbSessionInit(
    PDB_SESSION* Session,
    const PDB_MODULE_ENTRY* PdbModules,
    INT32                   PdbModuleCount
)
{
    INT32 i;

    memset(Session, 0, sizeof(*Session));

    /* Use a pseudo-handle — DbgHelp just needs a unique HANDLE value */
    Session->hProcess = (HANDLE)(ULONG_PTR)0xDEAD0001;

    if (!SymInitialize(Session->hProcess, NULL, FALSE))
        return FALSE;

    /* Undecorate symbols for cleaner output */
    SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);

    Session->Initialized = TRUE;

    for (i = 0; i < PdbModuleCount && i < MAX_PDB_MODULES; i++) {
        UINT64 fakeBase = PDB_FAKE_BASE_START + (UINT64)i * PDB_FAKE_BASE_STRIDE;
        DWORD64 loaded;

        loaded = SymLoadModuleEx(
            Session->hProcess,
            NULL,                               /* hFile          */
            PdbModules[i].PdbOrImagePath,       /* ImageName      */
            PdbModules[i].ModuleName,           /* ModuleName     */
            fakeBase,                           /* BaseOfDll      */
            0x7FFFFFFF,                         /* SizeOfDll (large) */
            NULL,                               /* Data           */
            0                                   /* Flags          */
        );

        if (loaded == 0) {
            /* SymLoadModuleEx failed — skip this module but continue */
            Session->ModBases[i] = 0;
        }
        else {
            Session->ModBases[i] = fakeBase;
        }

        /* Copy module name for matching */
        strncpy_s(Session->ModNames[i], sizeof(Session->ModNames[i]),
            PdbModules[i].ModuleName,
            sizeof(Session->ModNames[i]) - 1);

        Session->ModCount++;
    }

    return TRUE;
}

static void
PdbSessionCleanup(PDB_SESSION* Session)
{
    if (Session->Initialized) {
        INT32 i;
        for (i = 0; i < Session->ModCount; i++) {
            if (Session->ModBases[i] != 0)
                SymUnloadModule64(Session->hProcess, Session->ModBases[i]);
        }
        SymCleanup(Session->hProcess);
        Session->Initialized = FALSE;
    }
}

/*
 * Resolve an RVA to a symbol name for a given module.
 * Returns TRUE if resolved, fills SymbolName and SymbolOffset.
 */
static BOOLEAN
PdbSessionResolve(
    PDB_SESSION* Session,
    const CHAR* ModuleName,
    UINT64       Rva,
    _Out_writes_(NameMax) CHAR* SymbolName,
    INT32        NameMax,
    _Out_ UINT64* SymbolOffset
)
{
    INT32  i;
    UINT64 fakeBase = 0;

    *SymbolOffset = 0;
    SymbolName[0] = '\0';

    /* Find which loaded module this belongs to */
    for (i = 0; i < Session->ModCount; i++) {
        if (ModuleNameMatch(Session->ModNames[i], ModuleName)) {
            fakeBase = Session->ModBases[i];
            break;
        }
    }

    if (fakeBase == 0)
        return FALSE;

    /* Resolve via DbgHelp */
    {
        CHAR                  symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
        SYMBOL_INFO* sym = (SYMBOL_INFO*)symBuf;
        DWORD64               displacement = 0;

        memset(symBuf, 0, sizeof(symBuf));
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddr(Session->hProcess, fakeBase + Rva, &displacement, sym)) {
            /* Copy the undecorated name */
            INT32 copyLen = (INT32)sym->NameLen;
            if (copyLen >= NameMax) copyLen = NameMax - 1;
            memcpy(SymbolName, sym->Name, copyLen);
            SymbolName[copyLen] = '\0';
            *SymbolOffset = displacement;
            return TRUE;
        }
    }

    return FALSE;
}

/* ================================================================== */
/*  Internal: Core trace rewriting logic                              */
/*                                                                    */
/*  Used by both the sizing pass (Out==NULL) and the real pass.       */
/*  Walks InputTrace line by line, resolves where possible, and       */
/*  writes to Out.                                                    */
/* ================================================================== */

static INT32
RewriteTrace(
    PDB_SESSION* Session,
    const CHAR* InputTrace,
    CHAR* Out,
    INT32        OutSize
)
{
    const CHAR* p = InputTrace;
    INT32       pos = 0;

    /* Helper: append a character */
#define EMIT_CHAR(ch) do {                          \
        if (Out && pos < OutSize - 1) Out[pos] = (ch);  \
        pos++;                                           \
    } while(0)

    /* Helper: append a string */
#define EMIT_STR(s) do {                 \
        const CHAR* _s = (s);                \
        while (*_s) { EMIT_CHAR(*_s); _s++; }\
    } while(0)

    while (*p) {
        /* Extract one line */
        const CHAR* lineStart = p;
        const CHAR* lineEnd = p;
        CHAR        lineBuf[512];
        INT32       lineLen;

        while (*lineEnd && *lineEnd != '\n') lineEnd++;
        lineLen = (INT32)(lineEnd - lineStart);
        if (lineLen >= (INT32)sizeof(lineBuf)) lineLen = (INT32)sizeof(lineBuf) - 1;
        memcpy(lineBuf, lineStart, lineLen);
        lineBuf[lineLen] = '\0';

        /* Try to parse as a frame line */
        {
            CHAR    modName[64];
            UINT64  rva;
            CHAR    symName[256];
            UINT64  symOffset;

            if (ParseFrameLine(lineBuf, modName, sizeof(modName), &rva) &&
                PdbSessionResolve(Session, modName, rva, symName, sizeof(symName), &symOffset))
            {
                /* We got a resolved symbol — build a new line */
                CHAR resolved[512];
                FormatResolvedLine(lineBuf, modName, symName, symOffset, rva,
                    resolved, sizeof(resolved));
                EMIT_STR(resolved);
            }
            else {
                /* Pass through unmodified */
                EMIT_STR(lineBuf);
            }
        }

        /* Emit the newline if present */
        if (*lineEnd == '\n') {
            EMIT_CHAR('\n');
            lineEnd++;
        }
        p = lineEnd;
    }

    /* Null-terminate */
    if (Out) {
        INT32 end = (pos < OutSize) ? pos : OutSize - 1;
        if (end >= 0) Out[end] = '\0';
    }

#undef EMIT_CHAR
#undef EMIT_STR

    return pos;
}

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

INT32
UnwinderResolveTraceWithPdb(
    _In_                              const CHAR* InputTrace,
    _In_reads_(PdbModuleCount)        const PDB_MODULE_ENTRY* PdbModules,
    _In_                              INT32                    PdbModuleCount,
    _Out_writes_opt_(OutputSize) CHAR* OutputTrace,
    _In_                              INT32                    OutputSize
)
{
    PDB_SESSION session;
    INT32       result;

    if (!InputTrace)
        return 0;

    if (!PdbSessionInit(&session, PdbModules, PdbModuleCount)) {
        /* DbgHelp failed to init — just copy input unchanged */
        INT32 len = (INT32)strlen(InputTrace);
        if (OutputTrace && OutputSize > 0) {
            INT32 copy = (len < OutputSize - 1) ? len : OutputSize - 1;
            memcpy(OutputTrace, InputTrace, copy);
            OutputTrace[copy] = '\0';
        }
        return len;
    }

    if (!OutputTrace || OutputSize <= 0) {
        /* Sizing pass */
        result = RewriteTrace(&session, InputTrace, NULL, 0);
        PdbSessionCleanup(&session);
        return result + 1; /* +1 for null terminator */
    }

    /* Real pass */
    result = RewriteTrace(&session, InputTrace, OutputTrace, OutputSize);
    PdbSessionCleanup(&session);
    return (result < OutputSize) ? result : OutputSize - 1;
}