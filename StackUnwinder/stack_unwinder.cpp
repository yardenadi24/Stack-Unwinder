#include "stack_unwinder.h"
#ifdef _MSC_VER
#pragma function(memset)
#pragma function(memcpy)
#endif

void* memset(void* Dest, int Value, size_t Count)
{
    UINT8* p = (UINT8*)Dest;
    while (Count--) {
        *p++ = (UINT8)Value;
    }
    return Dest;
}

void* memcpy(void* Dest, const void* Src, size_t Count)
{
    UINT8* d = (UINT8*)Dest;
    const UINT8* s = (const UINT8*)Src;
    while (Count--) {
        *d++ = *s++;
    }
    return Dest;
}

#ifndef RtlZeroMemory
static __forceinline void ZeroMem(void* Dest, size_t Size)
{
    memset(Dest, 0, Size);
}
#define RtlZeroMemory(d, s) ZeroMem((d), (s))
#endif

#ifndef RtlCopyMemory
static __forceinline void CopyMem(void* Dest, const void* Src, size_t Size)
{
    memcpy(Dest, Src, Size);
}
#define RtlCopyMemory(d, s, n) CopyMem((d), (s), (n))
#endif

static void StrCopyA(
    _Out_writes_(MaxLen) CHAR* Dest,
    _In_opt_ const CHAR* Src,
    _In_ INT32                 MaxLen
)
{
    INT32 i = 0;
    if (!Src) { Dest[0] = '\0'; return; }
    while (i < MaxLen - 1 && Src[i]) {
        Dest[i] = Src[i];
        i++;
    }
    Dest[i] = '\0';
}

static __forceinline BOOLEAN
SafeRead(UNWIND_CONTEXT* Ctx, void* Dest, UINT64 Addr, UINT64 Size)
{
    if (!Ctx->ReadMemory) return FALSE;
    return Ctx->ReadMemory(Dest, Addr, Size);
}

static __forceinline BOOLEAN
ReadU16(UNWIND_CONTEXT* Ctx, UINT64 Addr, UINT16* Out)
{
    return SafeRead(Ctx, Out, Addr, sizeof(UINT16));
}

static __forceinline BOOLEAN
ReadU32(UNWIND_CONTEXT* Ctx, UINT64 Addr, UINT32* Out)
{
    return SafeRead(Ctx, Out, Addr, sizeof(UINT32));
}

static __forceinline BOOLEAN
ReadU64(UNWIND_CONTEXT* Ctx, UINT64 Addr, UINT64* Out)
{
    return SafeRead(Ctx, Out, Addr, sizeof(UINT64));
}

static INT32
FindModule(UNWIND_CONTEXT* Ctx, UINT64 Address)
{
    INT32 i;
    for (i = 0; i < Ctx->ModuleCount; i++) {
        UINT64 Base = Ctx->Modules[i].BaseAddress;
        UINT64 End = Base + Ctx->Modules[i].SizeOfImage;
        if (Address >= Base && Address < End) {
            return i;
        }
    }
    return -1;
}

static BOOLEAN
ParsePePdata(UNWIND_CONTEXT* Ctx, INT32 ModuleIndex)
{
    MODULE_INFO* Mod;
    UINT64                  Base;
    IMAGE_DOS_HEADER        DosHdr;
    IMAGE_NT_HEADERS64      NtHdrs;
    IMAGE_DATA_DIRECTORY    ExcDir;

    Mod = &Ctx->Modules[ModuleIndex];
    if (Mod->Parsed) {
        return (Mod->PdataSize > 0);
    }
    Mod->Parsed = TRUE;
    Base = Mod->BaseAddress;

    /* DOS header */
    if (!SafeRead(Ctx, &DosHdr, Base, sizeof(DosHdr)))
        return FALSE;
    if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    /* NT headers */
    if (!SafeRead(Ctx, &NtHdrs, Base + DosHdr.e_lfanew, sizeof(NtHdrs)))
        return FALSE;
    if (NtHdrs.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    if (NtHdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return FALSE;

    /* Exception directory */
    if (NtHdrs.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        return FALSE;

    ExcDir = NtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (ExcDir.VirtualAddress == 0 || ExcDir.Size == 0)
        return FALSE;

    Mod->PdataVa = Base + ExcDir.VirtualAddress;
    Mod->PdataSize = ExcDir.Size;
    return TRUE;
}

/* ================================================================== */
/*  PE Export Directory parsing                                        */
/* ================================================================== */

static BOOLEAN
ParsePeExports(UNWIND_CONTEXT* Ctx, INT32 ModuleIndex)
{
    MODULE_INFO* Mod;
    UINT64                  Base;
    IMAGE_DOS_HEADER        DosHdr;
    IMAGE_NT_HEADERS64      NtHdrs;
    IMAGE_DATA_DIRECTORY    ExpDir;
    IMAGE_EXPORT_DIRECTORY  ExportDir;

    Mod = &Ctx->Modules[ModuleIndex];
    if (Mod->ExportsParsed)
        return (Mod->NumberOfNames > 0);
    Mod->ExportsParsed = TRUE;
    Base = Mod->BaseAddress;

    /* DOS header */
    if (!SafeRead(Ctx, &DosHdr, Base, sizeof(DosHdr)))
        return FALSE;
    if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    /* NT headers */
    if (!SafeRead(Ctx, &NtHdrs, Base + DosHdr.e_lfanew, sizeof(NtHdrs)))
        return FALSE;
    if (NtHdrs.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    if (NtHdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return FALSE;

    /* Export directory */
    if (NtHdrs.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return FALSE;

    ExpDir = NtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExpDir.VirtualAddress == 0 || ExpDir.Size == 0)
        return FALSE;

    Mod->ExportDirVa = Base + ExpDir.VirtualAddress;
    Mod->ExportDirSize = ExpDir.Size;

    /* Read the export directory structure */
    if (!SafeRead(Ctx, &ExportDir, Mod->ExportDirVa, sizeof(ExportDir)))
        return FALSE;

    Mod->NumberOfFunctions = ExportDir.NumberOfFunctions;
    Mod->NumberOfNames = ExportDir.NumberOfNames;
    Mod->AddressOfFunctionsVa = Base + ExportDir.AddressOfFunctions;
    Mod->AddressOfNamesVa = Base + ExportDir.AddressOfNames;
    Mod->AddressOfOrdinalsVa = Base + ExportDir.AddressOfNameOrdinals;

    return (Mod->NumberOfNames > 0);
}

/*
 * Find the nearest exported function at or below the given RVA.
 *
 * Strategy: Walk all named exports, track the one with the largest
 * RVA that is <= target RVA.  This is O(N) in the number of exports,
 * which is fine for a diagnostic tool.
 */
static BOOLEAN
FindNearestExport(
    UNWIND_CONTEXT* Ctx,
    INT32           ModuleIndex,
    UINT32          TargetRva,
    _Out_writes_(NameMaxLen) CHAR* NameOut,
    INT32           NameMaxLen,
    _Out_ UINT64* OffsetOut
)
{
    MODULE_INFO* Mod = &Ctx->Modules[ModuleIndex];
    UINT32       BestRva = 0;
    UINT32       BestNameRva = 0;
    BOOLEAN      Found = FALSE;
    UINT32       i;

    for (i = 0; i < Mod->NumberOfNames; i++) {
        UINT16 Ordinal;
        UINT32 FuncRva;
        UINT32 NameRva;

        /* Read ordinal for this named export */
        if (!ReadU16(Ctx, Mod->AddressOfOrdinalsVa + (UINT64)i * 2, &Ordinal))
            continue;
        if (Ordinal >= Mod->NumberOfFunctions)
            continue;

        /* Read function RVA via ordinal */
        if (!ReadU32(Ctx, Mod->AddressOfFunctionsVa + (UINT64)Ordinal * 4, &FuncRva))
            continue;

        /* Skip forwarded exports (RVA points inside the export directory) */
        if (Mod->ExportDirSize > 0) {
            UINT32 ExpStart = (UINT32)(Mod->ExportDirVa - Mod->BaseAddress);
            UINT32 ExpEnd = ExpStart + Mod->ExportDirSize;
            if (FuncRva >= ExpStart && FuncRva < ExpEnd)
                continue;
        }

        /* Is this the closest function at or below our target? */
        if (FuncRva <= TargetRva && FuncRva > BestRva) {
            BestRva = FuncRva;

            /* Read the name RVA */
            if (ReadU32(Ctx, Mod->AddressOfNamesVa + (UINT64)i * 4, &NameRva))
                BestNameRva = NameRva;

            Found = TRUE;
        }
    }

    if (!Found) {
        NameOut[0] = '\0';
        *OffsetOut = 0;
        return FALSE;
    }

    /* Read the actual name string */
    if (BestNameRva != 0) {
        CHAR TmpName[128];
        memset(TmpName, 0, sizeof(TmpName));
        SafeRead(Ctx, TmpName, Mod->BaseAddress + BestNameRva, sizeof(TmpName) - 1);
        TmpName[sizeof(TmpName) - 1] = '\0';
        StrCopyA(NameOut, TmpName, NameMaxLen);
    }
    else {
        NameOut[0] = '\0';
    }

    *OffsetOut = (UINT64)(TargetRva - BestRva);
    return TRUE;
}

/* ================================================================== */

static BOOLEAN
FindRuntimeFunction(
    UNWIND_CONTEXT* Ctx,
    INT32                        ModuleIndex,
    UINT32                       Rva,
    IMAGE_RUNTIME_FUNCTION_ENTRY* RfOut
)
{
    MODULE_INFO* Mod;
    UINT32                        Count, Lo, Hi, Mid;
    UINT64                        EntryVa;
    IMAGE_RUNTIME_FUNCTION_ENTRY  Rf;

    Mod = &Ctx->Modules[ModuleIndex];
    Count = Mod->PdataSize / (UINT32)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    if (Count == 0) return FALSE;

    Lo = 0;
    Hi = Count - 1;

    while (Lo <= Hi) {
        Mid = Lo + (Hi - Lo) / 2;
        EntryVa = Mod->PdataVa + (UINT64)Mid * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

        if (!SafeRead(Ctx, &Rf, EntryVa, sizeof(Rf)))
            return FALSE;

        if (Rva < Rf.BeginAddress) {
            if (Mid == 0) break;
            Hi = Mid - 1;
        }
        else if (Rva >= Rf.EndAddress) {
            Lo = Mid + 1;
        }
        else {
            *RfOut = Rf;
            return TRUE;
        }
    }

    return FALSE;
}

static INT32
ExtraSlotCount(UINT8 Op, UINT8 OpInfo)
{
    switch (Op) {
    case UWOP_PUSH_NONVOL:      return 0;
    case UWOP_ALLOC_LARGE:      return (OpInfo == 0) ? 1 : 2;
    case UWOP_ALLOC_SMALL:      return 0;
    case UWOP_SET_FPREG:        return 0;
    case UWOP_SAVE_NONVOL:      return 1;
    case UWOP_SAVE_NONVOL_FAR:  return 2;
    case UWOP_EPILOG:           return 1;
    case UWOP_SPARE:            return 2;
    case UWOP_SAVE_XMM128:      return 1;
    case UWOP_SAVE_XMM128_FAR:  return 2;
    case UWOP_PUSH_MACHFRAME:   return 0;
    default:                    return 0;
    }
}

static BOOLEAN
UnwindOneFrame(
    UNWIND_CONTEXT* Ctx,
    INT32                         ModuleIndex,
    IMAGE_RUNTIME_FUNCTION_ENTRY* Rf,
    UINT64                        CurrentRip
)
{
    UINT64                        Base;
    IMAGE_RUNTIME_FUNCTION_ENTRY  CurrentRf;
    UINT64                        UiVa, CodesVa;
    UINT8                         UiHdr[4];
    UINT8                         Flags, SizeOfProlog, CountOfCodes;
    UINT8                         FrameReg, FrameOff;
    UINT32                        OffsetInFunc;
    BOOLEAN                       InPrologue;
    UNWIND_CODE                   Codes[256];
    INT32                         i;
    UNWIND_CODE* Uc;
    UINT8                         Op, OpInfo;
    UINT32                        Alloc, Offset, AlignedCount;

    Base = Ctx->Modules[ModuleIndex].BaseAddress;
    CurrentRf = *Rf;

    for (;;) {
        UiVa = Base + CurrentRf.UnwindInfoAddress;
        if (!SafeRead(Ctx, UiHdr, UiVa, 4))
            return FALSE;

        Flags = (UiHdr[0] >> 3) & 0x1F;
        SizeOfProlog = UiHdr[1];
        CountOfCodes = UiHdr[2];
        FrameReg = UiHdr[3] & 0x0F;
        FrameOff = (UiHdr[3] >> 4) & 0x0F;

        OffsetInFunc = (UINT32)(CurrentRip - Base - CurrentRf.BeginAddress);
        InPrologue = (OffsetInFunc < SizeOfProlog);

        CodesVa = UiVa + 4;
        if (CountOfCodes > 0) {
            if (!SafeRead(Ctx, Codes, CodesVa, (UINT64)CountOfCodes * 2))
                return FALSE;
        }

        if (FrameReg != 0 && !InPrologue) {
            Ctx->Gpr[GPR_RSP] = Ctx->Gpr[FrameReg] - (UINT64)FrameOff * 16;
        }

        i = 0;
        while (i < (INT32)CountOfCodes) {
            Uc = &Codes[i];
            Op = Uc->UnwindOp;
            OpInfo = Uc->OpInfo;

            if (InPrologue && Uc->CodeOffset > OffsetInFunc) {
                i += 1 + ExtraSlotCount(Op, OpInfo);
                continue;
            }

            switch (Op) {

            case UWOP_PUSH_NONVOL:
                ReadU64(Ctx, Ctx->Gpr[GPR_RSP], &Ctx->Gpr[OpInfo]);
                Ctx->Gpr[GPR_RSP] += 8;
                break;

            case UWOP_ALLOC_LARGE:
                if (OpInfo == 0) {
                    Alloc = (UINT32)Codes[i + 1].FrameOffset * 8;
                }
                else {
                    Alloc = (UINT32)Codes[i + 1].FrameOffset
                        | ((UINT32)Codes[i + 2].FrameOffset << 16);
                }
                Ctx->Gpr[GPR_RSP] += Alloc;
                break;

            case UWOP_ALLOC_SMALL:
                Ctx->Gpr[GPR_RSP] += (UINT64)OpInfo * 8 + 8;
                break;

            case UWOP_SET_FPREG:
                break;

            case UWOP_SAVE_NONVOL:
                Offset = (UINT32)Codes[i + 1].FrameOffset * 8;
                ReadU64(Ctx, Ctx->Gpr[GPR_RSP] + Offset, &Ctx->Gpr[OpInfo]);
                break;

            case UWOP_SAVE_NONVOL_FAR:
                Offset = (UINT32)Codes[i + 1].FrameOffset
                    | ((UINT32)Codes[i + 2].FrameOffset << 16);
                ReadU64(Ctx, Ctx->Gpr[GPR_RSP] + Offset, &Ctx->Gpr[OpInfo]);
                break;

            case UWOP_SAVE_XMM128:
            case UWOP_SAVE_XMM128_FAR:
                break;

            case UWOP_PUSH_MACHFRAME:
                if (OpInfo == 1) {
                    Ctx->Gpr[GPR_RSP] += 8;
                }
                break;

            default:
                break;
            }

            i += 1 + ExtraSlotCount(Op, OpInfo);
        }

        if (Flags & UNW_FLAG_CHAININFO) {
            AlignedCount = (CountOfCodes + 1) & ~1u;
            if (!SafeRead(Ctx, &CurrentRf,
                CodesVa + (UINT64)AlignedCount * 2,
                sizeof(CurrentRf)))
                return FALSE;
            continue;
        }

        break;
    }

    return TRUE;
}

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

VOID
UnwinderInit(
    _Out_ UNWIND_CONTEXT* Context,
    _In_  READ_MEMORY_FN  ReadMemory
)
{
    memset(Context, 0, sizeof(*Context));
    Context->ReadMemory = ReadMemory;
}

INT32
UnwinderAddModule(
    _Inout_  UNWIND_CONTEXT* Context,
    _In_     UINT64          BaseAddress,
    _In_     UINT64          SizeOfImage,
    _In_opt_ const CHAR* Name
)
{
    INT32        Idx;
    MODULE_INFO* Mod;

    if (Context->ModuleCount >= MAX_MODULES)
        return -1;

    Idx = Context->ModuleCount++;
    Mod = &Context->Modules[Idx];
    memset(Mod, 0, sizeof(*Mod));
    Mod->BaseAddress = BaseAddress;
    Mod->SizeOfImage = SizeOfImage;
    StrCopyA(Mod->Name, Name, sizeof(Mod->Name));
    return Idx;
}

INT32
UnwinderWalk(
    _Inout_ UNWIND_CONTEXT* Context,
    _In_    UINT64          Rip,
    _In_    UINT64          Rsp,
    _In_opt_ const UINT64* InitialGpr
)
{
    UINT64                        CurrentRip;
    UINT64                        OldRsp, ReturnAddr;
    INT32                         ModIdx;
    STACK_FRAME_ENTRY* Frame;
    IMAGE_RUNTIME_FUNCTION_ENTRY  Rf;

    Context->FrameCount = 0;

    if (InitialGpr) {
        memcpy(Context->Gpr, InitialGpr, sizeof(Context->Gpr));
    }
    else {
        memset(Context->Gpr, 0, sizeof(Context->Gpr));
    }
    Context->Gpr[GPR_RSP] = Rsp;
    CurrentRip = Rip;

    while (Context->FrameCount < MAX_STACK_FRAMES) {

        Frame = &Context->Frames[Context->FrameCount];
        Frame->Rip = CurrentRip;
        Frame->Rsp = Context->Gpr[GPR_RSP];
        ModIdx = FindModule(Context, CurrentRip);
        Frame->ModuleIndex = ModIdx;
        Frame->Rva = (ModIdx >= 0)
            ? (CurrentRip - Context->Modules[ModIdx].BaseAddress)
            : 0;
        Frame->FunctionName[0] = '\0';
        Frame->FunctionRva = 0;
        Frame->FunctionOffset = 0;
        Context->FrameCount++;

        if (CurrentRip == 0)
            break;

        /* Try structured unwind */
        if (ModIdx >= 0 && ParsePePdata(Context, ModIdx)) {
            UINT32 Rva = (UINT32)(CurrentRip - Context->Modules[ModIdx].BaseAddress);
            if (FindRuntimeFunction(Context, ModIdx, Rva, &Rf)) {
                Frame->FunctionRva = Rf.BeginAddress;
                Frame->FunctionOffset = Rva - Rf.BeginAddress;
                UnwindOneFrame(Context, ModIdx, &Rf, CurrentRip);
            }
        }

        /* Pop return address */
        ReturnAddr = 0;
        if (!ReadU64(Context, Context->Gpr[GPR_RSP], &ReturnAddr))
            break;

        OldRsp = Context->Gpr[GPR_RSP];
        Context->Gpr[GPR_RSP] += 8;

        if (Context->Gpr[GPR_RSP] <= OldRsp)
            break;

        CurrentRip = ReturnAddr;
        if (ReturnAddr == 0)
            break;
    }

    return Context->FrameCount;
}

VOID
UnwinderResolveExports(
    _Inout_ UNWIND_CONTEXT* Context
)
{
    INT32 i;
    for (i = 0; i < Context->FrameCount; i++) {
        STACK_FRAME_ENTRY* Frame = &Context->Frames[i];
        INT32 ModIdx = Frame->ModuleIndex;

        if (ModIdx < 0)
            continue;

        /* Make sure exports are parsed for this module */
        if (!ParsePeExports(Context, ModIdx))
            continue;

        FindNearestExport(
            Context,
            ModIdx,
            (UINT32)Frame->Rva,
            Frame->FunctionName,
            sizeof(Frame->FunctionName),
            &Frame->FunctionOffset
        );
    }
}

VOID
UnwinderPrintTrace(
    _In_ PUNWIND_CONTEXT Context,
    _In_ PRINT_FN        PrintFn
)
{
    INT32 i;

    if (!PrintFn) return;

    PrintFn("\n===== Stack Trace (%d frames) =====\n", Context->FrameCount);

    for (i = 0; i < Context->FrameCount; i++) {
        STACK_FRAME_ENTRY* f = &Context->Frames[i];
        const CHAR* modName = (f->ModuleIndex >= 0)
            ? Context->Modules[f->ModuleIndex].Name
            : "???";

        if (f->FunctionName[0] != '\0') {
            PrintFn("  [%2d]  %s!%s+0x%llX  (0x%llX)\n",
                i, modName, f->FunctionName,
                (unsigned long long)f->FunctionOffset,
                (unsigned long long)f->Rva);
        }
        else if (f->FunctionRva != 0) {
            PrintFn("  [%2d]  %s!sub_%X+0x%llX  (0x%llX)\n",
                i, modName, (unsigned)f->FunctionRva,
                (unsigned long long)f->FunctionOffset,
                (unsigned long long)f->Rva);
        }
        else {
            PrintFn("  [%2d]  %s+0x%llX\n",
                i, modName,
                (unsigned long long)f->Rva);
        }
    }

    PrintFn("===================================\n");
}