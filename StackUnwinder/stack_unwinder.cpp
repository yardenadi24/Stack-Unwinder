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

static INT32 StrLenA(const CHAR* S)
{
    INT32 n = 0;
    if (!S) return 0;
    while (S[n]) n++;
    return n;
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

/* ================================================================== */
/*  CRT-free string formatting helpers                                */
/* ================================================================== */

/*
 * TRACE_BUFFER — lightweight write cursor for building the trace string.
 * When Buf is NULL we just count characters (sizing pass).
 */
typedef struct _TRACE_BUFFER {
    CHAR* Buf;
    INT32  Size;     /* Total buffer size            */
    INT32  Pos;      /* Current write position       */
} TRACE_BUFFER;

static void
TbInit(TRACE_BUFFER* Tb, CHAR* Buf, INT32 Size)
{
    Tb->Buf = Buf;
    Tb->Size = Size;
    Tb->Pos = 0;
}

/* Append a single character */
static void
TbPutChar(TRACE_BUFFER* Tb, CHAR Ch)
{
    if (Tb->Buf && Tb->Pos < Tb->Size - 1)
        Tb->Buf[Tb->Pos] = Ch;
    Tb->Pos++;
}

/* Append a null-terminated string */
static void
TbPutStr(TRACE_BUFFER* Tb, const CHAR* S)
{
    if (!S) return;
    while (*S) {
        TbPutChar(Tb, *S);
        S++;
    }
}

/* Append a decimal integer (INT32) */
static void
TbPutDec(TRACE_BUFFER* Tb, INT32 Value)
{
    CHAR  tmp[16];
    INT32 i = 0;
    BOOLEAN neg = FALSE;

    if (Value < 0) {
        neg = TRUE;
        Value = -Value;
    }
    if (Value == 0) {
        tmp[i++] = '0';
    }
    else {
        while (Value > 0) {
            tmp[i++] = (CHAR)('0' + (Value % 10));
            Value /= 10;
        }
    }
    if (neg) TbPutChar(Tb, '-');
    while (i > 0) TbPutChar(Tb, tmp[--i]);
}

/* Append a zero-padded decimal with minimum width (for frame index) */
static void
TbPutDecPad(TRACE_BUFFER* Tb, INT32 Value, INT32 Width)
{
    CHAR  tmp[16];
    INT32 i = 0;

    if (Value == 0) {
        tmp[i++] = '0';
    }
    else {
        INT32 v = Value;
        while (v > 0) {
            tmp[i++] = (CHAR)('0' + (v % 10));
            v /= 10;
        }
    }
    /* Pad with spaces */
    while (i < Width) {
        TbPutChar(Tb, ' ');
        Width--;
    }
    while (i > 0) TbPutChar(Tb, tmp[--i]);
}

/* Append a UINT64 as 0xHEX */
static void
TbPutHex64(TRACE_BUFFER* Tb, UINT64 Value)
{
    static const CHAR hex[] = "0123456789ABCDEF";
    CHAR  tmp[16];
    INT32 i = 0;

    TbPutStr(Tb, "0x");

    if (Value == 0) {
        TbPutChar(Tb, '0');
        return;
    }
    while (Value > 0) {
        tmp[i++] = hex[Value & 0xF];
        Value >>= 4;
    }
    while (i > 0) TbPutChar(Tb, tmp[--i]);
}

/* Append a UINT32 as plain hex (no 0x prefix, for sub_ addresses) */
static void
TbPutHex32Plain(TRACE_BUFFER* Tb, UINT32 Value)
{
    static const CHAR hex[] = "0123456789ABCDEF";
    CHAR  tmp[8];
    INT32 i = 0;

    if (Value == 0) {
        TbPutChar(Tb, '0');
        return;
    }
    while (Value > 0) {
        tmp[i++] = hex[Value & 0xF];
        Value >>= 4;
    }
    while (i > 0) TbPutChar(Tb, tmp[--i]);
}

/* Null-terminate the buffer (safe even if we overflowed) */
static void
TbFinish(TRACE_BUFFER* Tb)
{
    if (Tb->Buf) {
        INT32 end = (Tb->Pos < Tb->Size) ? Tb->Pos : Tb->Size - 1;
        if (end >= 0)
            Tb->Buf[end] = '\0';
    }
}

/* ================================================================== */

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

VOID
UnwinderEnableAutoDiscovery(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           MaxScanSize
)
{
    if (MaxScanSize > 0) {
        Context->AutoDiscover = TRUE;
        Context->MaxScanSize = MaxScanSize;
    }
    else {
        Context->AutoDiscover = FALSE;
        Context->MaxScanSize = 0;
    }
}

/* ================================================================== */
/*  PE module name reader (export dir -> debug dir -> "unknown")      */
/* ================================================================== */

/* CodeView PDB 7.0 signature ("RSDS") */
#define CV_SIGNATURE_RSDS  0x53445352

#ifndef IMAGE_DEBUG_TYPE_CODEVIEW
#define IMAGE_DEBUG_TYPE_CODEVIEW  2
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_DEBUG
#define IMAGE_DIRECTORY_ENTRY_DEBUG  6
#endif

typedef struct _CV_INFO_PDB70 {
    UINT32  CvSignature;    /* CV_SIGNATURE_RSDS                   */
    UINT8   Guid[16];       /* PDB GUID                            */
    UINT32  Age;
    CHAR    PdbFileName[1]; /* Null-terminated, variable length     */
} CV_INFO_PDB70;

/*
 * Extract a filename from a full path.
 *   "C:\build\mydriver.pdb" -> "mydriver.pdb"
 *   "mydriver.pdb"          -> "mydriver.pdb"
 */
static const CHAR*
PathGetFilename(const CHAR* Path)
{
    const CHAR* last = Path;
    const CHAR* p = Path;
    while (*p) {
        if (*p == '\\' || *p == '/') last = p + 1;
        p++;
    }
    return last;
}

/*
 * Strip ".pdb" extension if present, replace with nothing.
 *   "StackUnwinderTest.pdb" -> "StackUnwinderTest"
 */
static void
StripPdbExtension(CHAR* Name)
{
    INT32 len = StrLenA(Name);
    if (len >= 4) {
        CHAR* ext = &Name[len - 4];
        if ((ext[0] == '.') &&
            (ext[1] == 'p' || ext[1] == 'P') &&
            (ext[2] == 'd' || ext[2] == 'D') &&
            (ext[3] == 'b' || ext[3] == 'B'))
        {
            ext[0] = '\0';
        }
    }
}

/*
 * Try reading the module name from the PE debug directory.
 *
 * Looks for a CodeView RSDS entry which contains the PDB path.
 * Extracts the filename and strips the .pdb extension:
 *   "C:\build\StackUnwinderTest.pdb" -> "StackUnwinderTest"
 */
static BOOLEAN
ReadPeDebugName(
    UNWIND_CONTEXT* Ctx,
    UINT64          ImageBase,
    IMAGE_NT_HEADERS64* NtHdrs,
    _Out_writes_(MaxLen) CHAR* NameOut,
    INT32           MaxLen
)
{
    IMAGE_DATA_DIRECTORY    DbgDir;
    UINT32                  EntryCount, i;
    IMAGE_DEBUG_DIRECTORY   DbgEntry;
    UINT8                   CvBuf[512];
    CV_INFO_PDB70* Cv;
    const CHAR* Filename;
    CHAR                    TmpName[64];

    if (NtHdrs->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
        return FALSE;

    DbgDir = NtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (DbgDir.VirtualAddress == 0 || DbgDir.Size == 0)
        return FALSE;

    EntryCount = DbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    for (i = 0; i < EntryCount; i++) {
        UINT64 entryVa = ImageBase + DbgDir.VirtualAddress +
            (UINT64)i * sizeof(IMAGE_DEBUG_DIRECTORY);

        if (!SafeRead(Ctx, &DbgEntry, entryVa, sizeof(DbgEntry)))
            continue;

        /* We only care about CodeView entries */
        if (DbgEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
            continue;

        /* SizeOfData must be reasonable */
        if (DbgEntry.SizeOfData < sizeof(CV_INFO_PDB70) ||
            DbgEntry.SizeOfData > sizeof(CvBuf))
            continue;

        /* Read the CodeView data (use AddressOfRawData = RVA when loaded) */
        if (DbgEntry.AddressOfRawData == 0)
            continue;

        if (!SafeRead(Ctx, CvBuf, ImageBase + DbgEntry.AddressOfRawData,
            DbgEntry.SizeOfData))
            continue;

        Cv = (CV_INFO_PDB70*)CvBuf;
        if (Cv->CvSignature != CV_SIGNATURE_RSDS)
            continue;

        /* Ensure the PDB filename is null-terminated within the buffer */
        CvBuf[DbgEntry.SizeOfData - 1] = '\0';

        /* Sanity: first char of filename should be printable */
        if (Cv->PdbFileName[0] < 0x20 || Cv->PdbFileName[0] > 0x7E)
            continue;

        /* Extract just the filename, strip .pdb extension */
        Filename = PathGetFilename(Cv->PdbFileName);
        StrCopyA(TmpName, Filename, sizeof(TmpName));
        StripPdbExtension(TmpName);

        if (TmpName[0] != '\0') {
            StrCopyA(NameOut, TmpName, MaxLen);
            return TRUE;
        }
    }

    return FALSE;
}

/*
 * Read the module name for a PE image. Tries in order:
 *   1. Export directory Name field  (DLLs, ntoskrnl, etc.)
 *   2. Debug directory PDB filename (EXEs, anything with /Zi)
 *   3. Falls back to "unknown"
 */
static void
ReadPeDllName(
    UNWIND_CONTEXT* Ctx,
    UINT64          ImageBase,
    _Out_writes_(MaxLen) CHAR* NameOut,
    INT32           MaxLen
)
{
    IMAGE_DOS_HEADER        DosHdr;
    IMAGE_NT_HEADERS64      NtHdrs;
    IMAGE_DATA_DIRECTORY    ExpDir;
    IMAGE_EXPORT_DIRECTORY  ExportDir;
    UINT32                  NameRva;
    CHAR                    TmpName[64];

    NameOut[0] = '\0';

    /* Parse PE headers (shared by both strategies) */
    if (!SafeRead(Ctx, &DosHdr, ImageBase, sizeof(DosHdr)))
        goto fallback;
    if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE)
        goto fallback;

    if (!SafeRead(Ctx, &NtHdrs, ImageBase + DosHdr.e_lfanew, sizeof(NtHdrs)))
        goto fallback;
    if (NtHdrs.Signature != IMAGE_NT_SIGNATURE)
        goto fallback;
    if (NtHdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        goto fallback;

    /* Strategy 1: Export directory Name */
    if (NtHdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        ExpDir = NtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (ExpDir.VirtualAddress != 0 && ExpDir.Size != 0) {
            if (SafeRead(Ctx, &ExportDir, ImageBase + ExpDir.VirtualAddress, sizeof(ExportDir))) {
                NameRva = ExportDir.Name;
                if (NameRva != 0) {
                    memset(TmpName, 0, sizeof(TmpName));
                    if (SafeRead(Ctx, TmpName, ImageBase + NameRva, sizeof(TmpName) - 1)) {
                        TmpName[sizeof(TmpName) - 1] = '\0';
                        if (TmpName[0] >= 0x20 && TmpName[0] <= 0x7E) {
                            StrCopyA(NameOut, TmpName, MaxLen);
                            return;
                        }
                    }
                }
            }
        }
    }

    /* Strategy 2: Debug directory PDB filename */
    if (ReadPeDebugName(Ctx, ImageBase, &NtHdrs, NameOut, MaxLen))
        return;

fallback:
    StrCopyA(NameOut, "unknown", MaxLen);
}

/* ================================================================== */
/*  Inline module discovery                                           */
/* ================================================================== */

/*
 * TryDiscoverModule — given an address with no known module, scan
 * backward to find the PE base, read the DLL name from exports,
 * register the module, and parse .pdata + exports.
 *
 * Returns the new module index, or -1 on failure.
 */
static INT32
TryDiscoverModule(
    UNWIND_CONTEXT* Ctx,
    UINT64          Address
)
{
    UINT64  Base, Size;
    CHAR    DllName[64];
    INT32   ModIdx;

    if (!UnwinderFindImageBase(Ctx, Address, Ctx->MaxScanSize, &Base, &Size))
        return -1;

    /* Maybe another frame already triggered discovery of this image */
    ModIdx = FindModule(Ctx, Address);
    if (ModIdx >= 0)
        return ModIdx;

    /* Read internal DLL name from PE export directory */
    ReadPeDllName(Ctx, Base, DllName, sizeof(DllName));

    ModIdx = UnwinderAddModule(Ctx, Base, Size, DllName);
    if (ModIdx < 0)
        return -1;

    /* Pre-parse .pdata and exports so they're ready for this frame */
    ParsePePdata(Ctx, ModIdx);
    ParsePeExports(Ctx, ModIdx);

    return ModIdx;
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

        /* Auto-discover: if RIP doesn't belong to any known module,
           scan backward to find the PE base, read the DLL name from
           the export directory, and register it — all inline. */
        if (ModIdx < 0 && Context->AutoDiscover && CurrentRip != 0) {
            ModIdx = TryDiscoverModule(Context, CurrentRip);
        }

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

        /*
         * Resolve export name inline if auto-discovery is on.
         *
         * FIX: Use a local ExportOffset and only write it back to
         * Frame->FunctionOffset on success.  Previously, a failed
         * FindNearestExport call (EXE has no exports) would zero
         * Frame->FunctionOffset, discarding the correct .pdata offset
         * computed just above.
         */
        if (ModIdx >= 0 && Context->AutoDiscover && Frame->FunctionName[0] == '\0') {
            if (Context->Modules[ModIdx].ExportsParsed ||
                ParsePeExports(Context, ModIdx)) {
                UINT64 ExportOffset = 0;
                if (FindNearestExport(
                    Context,
                    ModIdx,
                    (UINT32)Frame->Rva,
                    Frame->FunctionName,
                    sizeof(Frame->FunctionName),
                    &ExportOffset))
                {
                    Frame->FunctionOffset = ExportOffset;
                }
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

/* ================================================================== */
/*  Image base discovery (no OS structures needed)                    */
/* ================================================================== */

/*
 * Scan backward from `Address` on page-aligned boundaries looking
 * for a valid MZ + PE header.  This works because PE images are
 * always loaded at page-aligned addresses.
 */
BOOLEAN
UnwinderFindImageBase(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           Address,
    _In_    UINT64           MaxScanSize,
    _Out_   UINT64* ImageBase,
    _Out_   UINT64* SizeOfImage
)
{
    UINT64              Page;
    UINT64              Limit;
    IMAGE_DOS_HEADER    DosHdr;
    IMAGE_NT_HEADERS64  NtHdrs;

    *ImageBase = 0;
    *SizeOfImage = 0;

    /* Align down to page boundary */
    Page = Address & ~(UINT64)0xFFF;

    /* Don't scan below this address */
    Limit = (Page > MaxScanSize) ? (Page - MaxScanSize) : 0;

    while (Page >= Limit) {

        /* Try reading a DOS header at this page */
        if (!SafeRead(Context, &DosHdr, Page, sizeof(DosHdr)))
            goto next;

        if (DosHdr.e_magic != IMAGE_DOS_SIGNATURE)
            goto next;

        /* Sanity check e_lfanew — must be reasonable and within
           the first page-ish of the image */
        if (DosHdr.e_lfanew < sizeof(IMAGE_DOS_HEADER) ||
            DosHdr.e_lfanew > 0x1000)
            goto next;

        /* Try reading NT headers */
        if (!SafeRead(Context, &NtHdrs, Page + DosHdr.e_lfanew, sizeof(NtHdrs)))
            goto next;

        if (NtHdrs.Signature != IMAGE_NT_SIGNATURE)
            goto next;

        if (NtHdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            goto next;

        /* Verify that our original address actually falls within
           this image's claimed range */
        if (Address >= Page &&
            Address < Page + NtHdrs.OptionalHeader.SizeOfImage)
        {
            *ImageBase = Page;
            *SizeOfImage = NtHdrs.OptionalHeader.SizeOfImage;
            return TRUE;
        }

    next:
        if (Page == 0) break;
        Page -= 0x1000;
    }

    return FALSE;
}

/*
 * After UnwinderWalk, discover and register modules for frames
 * that don't yet belong to any known module.
 *
 * Also re-links those frames to the newly discovered module and
 * re-runs .pdata lookup so the next UnwinderResolveExports has
 * full function info.
 */
INT32
UnwinderDiscoverModules(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           MaxScanSize
)
{
    INT32  i, NewCount = 0;
    UINT64 Base, Size;

    for (i = 0; i < Context->FrameCount; i++) {
        STACK_FRAME_ENTRY* Frame = &Context->Frames[i];

        /* Skip frames that already have a module */
        if (Frame->ModuleIndex >= 0)
            continue;

        /* Skip null RIPs */
        if (Frame->Rip == 0)
            continue;

        /* Check if another frame already discovered this module */
        INT32 Existing = FindModule(Context, Frame->Rip);
        if (Existing >= 0) {
            Frame->ModuleIndex = Existing;
            Frame->Rva = Frame->Rip - Context->Modules[Existing].BaseAddress;
            continue;
        }

        /* Scan backward for PE header */
        if (!UnwinderFindImageBase(Context, Frame->Rip, MaxScanSize, &Base, &Size))
            continue;

        /* Register the new module (no name available — use empty) */
        INT32 ModIdx = UnwinderAddModule(Context, Base, Size, "unknown");
        if (ModIdx < 0)
            continue;

        NewCount++;

        /* Re-link this frame and any subsequent frames in the same image */
        {
            INT32 j;
            for (j = i; j < Context->FrameCount; j++) {
                STACK_FRAME_ENTRY* f2 = &Context->Frames[j];
                if (f2->ModuleIndex >= 0)
                    continue;
                if (f2->Rip >= Base && f2->Rip < Base + Size) {
                    f2->ModuleIndex = ModIdx;
                    f2->Rva = f2->Rip - Base;
                }
            }
        }

        /* Parse .pdata now so FunctionRva/Offset get filled in */
        if (ParsePePdata(Context, ModIdx)) {
            INT32 j;
            for (j = i; j < Context->FrameCount; j++) {
                STACK_FRAME_ENTRY* f2 = &Context->Frames[j];
                if (f2->ModuleIndex != ModIdx)
                    continue;
                IMAGE_RUNTIME_FUNCTION_ENTRY Rf;
                UINT32 Rva = (UINT32)f2->Rva;
                if (FindRuntimeFunction(Context, ModIdx, Rva, &Rf)) {
                    f2->FunctionRva = Rf.BeginAddress;
                    f2->FunctionOffset = Rva - Rf.BeginAddress;
                }
            }
        }
    }

    return NewCount;
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

        /*
         * FIX: Use a local ExportOffset and only write it back to
         * Frame->FunctionOffset on success.  Previously, a failed
         * FindNearestExport call (EXE has no exports) would zero
         * Frame->FunctionOffset, discarding the correct .pdata offset
         * computed during UnwinderWalk.
         */
        {
            UINT64 ExportOffset = 0;
            if (FindNearestExport(
                Context,
                ModIdx,
                (UINT32)Frame->Rva,
                Frame->FunctionName,
                sizeof(Frame->FunctionName),
                &ExportOffset))
            {
                Frame->FunctionOffset = ExportOffset;
            }
        }
    }
}

/* ================================================================== */
/*  Trace formatting                                                  */
/* ================================================================== */

/*
 * Internal: write the full trace into a TRACE_BUFFER.
 * Used by both the sizing pass (Buf==NULL) and the real pass.
 */
static void
FormatTraceInternal(PUNWIND_CONTEXT Context, TRACE_BUFFER* Tb)
{
    INT32 i;

    TbPutStr(Tb, "\n===== Stack Trace (");
    TbPutDec(Tb, Context->FrameCount);
    TbPutStr(Tb, " frames) =====\n");

    for (i = 0; i < Context->FrameCount; i++) {
        STACK_FRAME_ENTRY* f = &Context->Frames[i];
        const CHAR* modName = (f->ModuleIndex >= 0)
            ? Context->Modules[f->ModuleIndex].Name
            : "???";

        TbPutStr(Tb, "  [");
        TbPutDecPad(Tb, i, 2);
        TbPutStr(Tb, "]  ");

        if (f->FunctionName[0] != '\0') {
            /* module!FunctionName+0xOffset  (0xRva) */
            TbPutStr(Tb, modName);
            TbPutChar(Tb, '!');
            TbPutStr(Tb, f->FunctionName);
            TbPutStr(Tb, "+");
            TbPutHex64(Tb, f->FunctionOffset);
            TbPutStr(Tb, "  (");
            TbPutHex64(Tb, f->Rva);
            TbPutChar(Tb, ')');
        }
        else if (f->FunctionRva != 0) {
            /* module!sub_XXXX+0xOffset  (0xRva) */
            TbPutStr(Tb, modName);
            TbPutStr(Tb, "!sub_");
            TbPutHex32Plain(Tb, f->FunctionRva);
            TbPutStr(Tb, "+");
            TbPutHex64(Tb, f->FunctionOffset);
            TbPutStr(Tb, "  (");
            TbPutHex64(Tb, f->Rva);
            TbPutChar(Tb, ')');
        }
        else {
            /* module+0xRva */
            TbPutStr(Tb, modName);
            TbPutStr(Tb, "+");
            TbPutHex64(Tb, f->Rva);
        }

        TbPutChar(Tb, '\n');
    }

    TbPutStr(Tb, "===================================\n");
}

INT32
UnwinderFormatTrace(
    _In_                              PUNWIND_CONTEXT Context,
    _Out_writes_opt_(BufSize) CHAR* Buffer,
    _In_                              INT32           BufSize
)
{
    TRACE_BUFFER Tb;

    if (!Buffer || BufSize <= 0) {
        /* Sizing pass — count characters with a NULL buffer */
        TbInit(&Tb, (CHAR*)0, 0);
        FormatTraceInternal(Context, &Tb);
        return Tb.Pos + 1;   /* +1 for null terminator */
    }

    /* Real pass — write into the caller's buffer */
    TbInit(&Tb, Buffer, BufSize);
    FormatTraceInternal(Context, &Tb);
    TbFinish(&Tb);

    /* Return characters written (not counting the terminator) */
    return (Tb.Pos < BufSize) ? Tb.Pos : BufSize - 1;
}