#pragma once

#ifdef _NTDDK_
/*
 * Full WDK kernel build — ntddk.h already pulled in ntdef.h,
 * ntimage.h, and all base types.  Nothing more needed.
 */
#elif defined(_NTDEF_)
/*
 * Minimal WDK build — ntdef.h loaded but not the image headers.
 */
#include <ntimage.h>
#else
/*
 * Standalone / user-mode SDK build.
 *
 * winnt.h requires a target-architecture macro.
 * <windows.h> normally sets this, but we include winnt.h directly.
 */
#if defined(_M_AMD64) && !defined(_AMD64_)
#define _AMD64_
#endif
#if defined(_M_IX86) && !defined(_X86_)
#define _X86_
#endif
#if defined(_M_ARM64) && !defined(_ARM64_)
#define _ARM64_
#endif

#include <windef.h>
#include <winnt.h>
#endif

 /* ---- Unwind operation codes ---- */
#define UWOP_PUSH_NONVOL       0   /* Push a non-volatile GPR            */
#define UWOP_ALLOC_LARGE       1   /* Large stack allocation              */
#define UWOP_ALLOC_SMALL       2   /* Small stack alloc (8..128 bytes)    */
#define UWOP_SET_FPREG         3   /* Establish frame pointer register    */
#define UWOP_SAVE_NONVOL       4   /* Save GPR at [RSP + offset*8]       */
#define UWOP_SAVE_NONVOL_FAR   5   /* Save GPR at [RSP + 32-bit offset]  */
#define UWOP_EPILOG            6   /* (Version 2) epilog descriptor      */
#define UWOP_SPARE             7   /* Reserved                           */
#define UWOP_SAVE_XMM128       8   /* Save XMM at [RSP + offset*16]      */
#define UWOP_SAVE_XMM128_FAR   9   /* Save XMM at 32-bit offset          */
#define UWOP_PUSH_MACHFRAME    10  /* CPU-pushed machine frame (int/exc) */

/* ---- Flags in UNWIND_INFO.VersionAndFlags ---- */
#define UNW_FLAG_NHANDLER      0x0
#define UNW_FLAG_EHANDLER      0x1
#define UNW_FLAG_UHANDLER      0x2
#define UNW_FLAG_CHAININFO     0x4

/*
 * UNWIND_CODE — 2 bytes per entry.
 *   Byte 0: CodeOffset  — prologue offset where this operation occurs
 *   Byte 1: UnwindOp:4 | OpInfo:4
 *
 * Multi-slot ops store large immediates in the slot(s) that follow.
 */
typedef union _UNWIND_CODE {
    struct {
        UINT8 CodeOffset;
        UINT8 UnwindOp : 4;
        UINT8 OpInfo : 4;
    };
    UINT16 FrameOffset;   /* Raw 16-bit value for multi-slot reads */
} UNWIND_CODE, * PUNWIND_CODE;


/*
 * UNWIND_INFO — variable-length structure at the RVA given by
 * IMAGE_RUNTIME_FUNCTION_ENTRY.UnwindInfoAddress.
 *
 *   Byte 0 : Version:3 | Flags:5
 *   Byte 1 : SizeOfProlog
 *   Byte 2 : CountOfCodes
 *   Byte 3 : FrameRegister:4 | FrameOffset:4
 *   Byte 4+: UNWIND_CODE[CountOfCodes]  (2 bytes each)
 *
 * After the code array (padded to even count):
 *   UNW_FLAG_EHANDLER / UHANDLER → handler RVA + handler data
 *   UNW_FLAG_CHAININFO           → chained IMAGE_RUNTIME_FUNCTION_ENTRY
 */
typedef struct _UNWIND_INFO {
    UINT8       VersionAndFlags;     /* Version:3 | Flags:5             */
    UINT8       SizeOfProlog;
    UINT8       CountOfCodes;
    UINT8       FrameRegAndOffset;   /* FrameRegister:4 | FrameOffset:4*/
    UNWIND_CODE UnwindCodes[1];      /* Variable-length array           */
} UNWIND_INFO, * PUNWIND_INFO;

/* Accessor macros */
#define UNWIND_INFO_VERSION(pUi)       ((pUi)->VersionAndFlags & 0x07)
#define UNWIND_INFO_FLAGS(pUi)         (((pUi)->VersionAndFlags >> 3) & 0x1F)
#define UNWIND_INFO_FRAME_REG(pUi)     ((pUi)->FrameRegAndOffset & 0x0F)
#define UNWIND_INFO_FRAME_OFFSET(pUi)  (((pUi)->FrameRegAndOffset >> 4) & 0x0F)

/* ================================================================== */
/*  x64 GPR indices — matches UNWIND_CODE.OpInfo encoding             */
/* ================================================================== */

#define GPR_RAX     0
#define GPR_RCX     1
#define GPR_RDX     2
#define GPR_RBX     3
#define GPR_RSP     4
#define GPR_RBP     5
#define GPR_RSI     6
#define GPR_RDI     7
#define GPR_R8      8
#define GPR_R9      9
#define GPR_R10    10
#define GPR_R11    11
#define GPR_R12    12
#define GPR_R13    13
#define GPR_R14    14
#define GPR_R15    15
#define GPR_COUNT  16

/* ================================================================== */
/*  Unwinder limits & public structures                               */
/* ================================================================== */

#define MAX_STACK_FRAMES   256
#define MAX_MODULES         64

/*
 * READ_MEMORY_FN — callback the hypervisor supplies.
 *
 * Read `Size` bytes from guest address `SourceAddress` into `Destination`.
 * Returns TRUE on success, FALSE if the page is unmapped / faulted.
 * The unwinder NEVER writes to guest memory.
 */
typedef BOOLEAN(*READ_MEMORY_FN)(
    _Out_writes_bytes_(Size) PVOID  Destination,
    _In_ UINT64 SourceAddress,
    _In_ UINT64 Size
    );

/* Describes one loaded PE image in guest memory */
typedef struct _MODULE_INFO {
    UINT64  BaseAddress;
    UINT64  SizeOfImage;

    /* Cached after first PE parse (zero = not yet parsed) */
    UINT64  PdataVa;
    UINT32  PdataSize;
    BOOLEAN Parsed;

    /* Cached export directory info (zero = not yet parsed) */
    UINT64  ExportDirVa;        /* VA of IMAGE_EXPORT_DIRECTORY   */
    UINT32  ExportDirSize;
    UINT32  NumberOfFunctions;
    UINT32  NumberOfNames;
    UINT64  AddressOfFunctionsVa;   /* VA of function RVA array   */
    UINT64  AddressOfNamesVa;       /* VA of name RVA array       */
    UINT64  AddressOfOrdinalsVa;    /* VA of ordinal array        */
    BOOLEAN ExportsParsed;

    CHAR    Name[64];
} MODULE_INFO, * PMODULE_INFO;

/* One frame in the output stack trace */
typedef struct _STACK_FRAME_ENTRY {
    UINT64  Rip;
    UINT64  Rsp;
    INT32   ModuleIndex;     /* Into Modules[], or -1 if unknown  */
    UINT64  Rva;             /* Rip - BaseAddress (if module found)*/
    UINT32  FunctionRva;     /* BeginAddress from .pdata, or 0     */
    CHAR    FunctionName[128]; /* Nearest export name, or empty    */
    UINT64  FunctionOffset;    /* Rip - function start             */
} STACK_FRAME_ENTRY, * PSTACK_FRAME_ENTRY;

/* Top-level unwinder state — allocate once, reuse across walks */
typedef struct _UNWIND_CONTEXT {
    /* Caller-supplied */
    READ_MEMORY_FN      ReadMemory;
    MODULE_INFO         Modules[MAX_MODULES];
    INT32               ModuleCount;

    /* Auto-discovery: when enabled, UnwinderWalk will scan backward
       from unknown RIPs to find PE image bases, register them, and
       use their .pdata + exports for proper unwinding — all inline,
       no OS APIs needed. */
    BOOLEAN             AutoDiscover;
    UINT64              MaxScanSize;    /* How far back to scan (bytes) */

    /* Output */
    STACK_FRAME_ENTRY   Frames[MAX_STACK_FRAMES];
    INT32               FrameCount;

    /* Internal scratch — GPR values during unwind */
    UINT64              Gpr[GPR_COUNT];
} UNWIND_CONTEXT, * PUNWIND_CONTEXT;

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

VOID
UnwinderInit(
    _Out_ PUNWIND_CONTEXT Context,
    _In_  READ_MEMORY_FN   ReadMemory
);

INT32
UnwinderAddModule(
    _Inout_  PUNWIND_CONTEXT Context,
    _In_     UINT64           BaseAddress,
    _In_     UINT64           SizeOfImage,
    _In_opt_ const CHAR* Name
);

/*
 * UnwinderEnableAutoDiscovery — turn on inline module discovery.
 *
 * When enabled, UnwinderWalk will automatically scan backward from
 * any RIP that doesn't belong to a known module, find its PE image
 * base, read the DLL name from the export directory, register it,
 * and use its .pdata for proper structured unwinding — all in a
 * single pass, no OS APIs needed.
 *
 * MaxScanSize — how far back (bytes) to scan. 32 MB is a safe default.
 *               Pass 0 to disable auto-discovery.
 */
VOID
UnwinderEnableAutoDiscovery(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           MaxScanSize
);

/*
 * UnwinderWalk — walk the stack starting from (Rip, Rsp).
 *
 * InitialGpr (optional):
 *   Array of GPR_COUNT (16) register values matching the register
 *   state at the captured RIP.  Required for correct unwinding of
 *   functions that use a frame pointer (typical in Debug builds).
 *   Pass NULL to zero-initialize all registers except RSP.
 */
INT32
UnwinderWalk(
    _Inout_  PUNWIND_CONTEXT Context,
    _In_     UINT64           Rip,
    _In_     UINT64           Rsp,
    _In_opt_ const UINT64* InitialGpr
);

/*
 * UnwinderFindImageBase — scan backward from an address to find the
 * PE image base.
 *
 * Walks backward from `Address` on page-aligned (0x1000) boundaries,
 * checking for a valid MZ + PE signature.  Searches up to `MaxScanSize`
 * bytes back (default recommendation: 32 MB).
 *
 * On success, stores the image base in *ImageBase and the value of
 * SizeOfImage from the PE optional header in *SizeOfImage, then
 * returns TRUE.
 *
 * This is the primary module-discovery mechanism when OS loader
 * structures (PsLoadedModuleList, PEB) are not yet available —
 * e.g. during early boot or from a Type-1 hypervisor VM exit
 * before Windows has fully initialized.
 */
BOOLEAN
UnwinderFindImageBase(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           Address,
    _In_    UINT64           MaxScanSize,
    _Out_   UINT64* ImageBase,
    _Out_   UINT64* SizeOfImage
);

/*
 * UnwinderDiscoverModules — auto-discover and register modules for
 * all frames after UnwinderWalk.
 *
 * For each frame whose RIP doesn't already belong to a known module,
 * calls UnwinderFindImageBase to scan backward for the PE header,
 * and registers any newly found image via UnwinderAddModule.
 *
 * Call this between UnwinderWalk and UnwinderResolveExports when you
 * have no other way to enumerate loaded modules (e.g. early boot,
 * hypervisor with no guest OS structures).
 *
 * MaxScanSize — how far back (in bytes) to scan from each RIP.
 *               32 * 1024 * 1024 (32 MB) is a safe default.
 *
 * Returns the number of new modules discovered.
 */
INT32
UnwinderDiscoverModules(
    _Inout_ PUNWIND_CONTEXT Context,
    _In_    UINT64           MaxScanSize
);

/*
 * UnwinderResolveExports — after UnwinderWalk, fill in FunctionName
 * for each frame by looking up the nearest PE export symbol.
 *
 * This only finds exported (public) functions. For static/local
 * function names, use PDB-based resolution (e.g. DbgHelp) externally.
 */
VOID
UnwinderResolveExports(
    _Inout_ PUNWIND_CONTEXT Context
);

/*
 * UnwinderFormatTrace — format the stack trace into a caller-supplied buffer.
 *
 * Call after UnwinderWalk (and optionally UnwinderResolveExports).
 *
 * Buffer   — destination buffer, or NULL to query required size.
 * BufSize  — size of Buffer in bytes.
 *
 * Returns the number of characters written (excluding null terminator).
 * If Buffer is NULL or BufSize is 0, returns the required buffer size
 * (including null terminator) so the caller can allocate.
 *
 * Usage pattern:
 *   INT32 needed = UnwinderFormatTrace(&uc, NULL, 0);
 *   CHAR* buf = (CHAR*)alloc(needed);
 *   UnwinderFormatTrace(&uc, buf, needed);
 */
INT32
UnwinderFormatTrace(
    _In_                              PUNWIND_CONTEXT Context,
    _Out_writes_opt_(BufSize) CHAR* Buffer,
    _In_                              INT32           BufSize
);