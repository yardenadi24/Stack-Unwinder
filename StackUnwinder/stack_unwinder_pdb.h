#pragma once
/*
 * stack_unwinder_pdb.h — Offline PDB symbol resolution for stack traces
 *
 * This is a SEPARATE module from the core stack_unwinder library.
 * It uses DbgHelp (Win32) and is intended for offline post-analysis
 * on a development machine, NOT for use inside a hypervisor.
 *
 * Workflow:
 *   1. Hypervisor captures trace -> UnwinderFormatTrace -> logs the string
 *   2. Later, on a dev machine with PDBs:
 *        a) Feed the trace string + PDB mappings to UnwinderResolveTraceWithPdb
 *        b) Get back a new trace string with real function names
 *
 * Link with: dbghelp.lib
 */

#include <windows.h>

 /* ================================================================== */
 /*  PDB module mapping                                                */
 /* ================================================================== */

#define MAX_PDB_MODULES 32

typedef struct _PDB_MODULE_ENTRY {
    const CHAR* ModuleName;     /* Must match module name in trace    */
    /* e.g. "ntoskrnl.exe", "unknown"     */
    const CHAR* PdbOrImagePath; /* Path to .pdb file OR the PE image  */
    /* (DbgHelp can locate PDB from PE)   */
} PDB_MODULE_ENTRY, * PPDB_MODULE_ENTRY;

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

/*
 * UnwinderResolveTraceWithPdb — resolve symbols in a formatted trace
 * string using PDB files via DbgHelp.
 *
 * Parses each frame line in InputTrace, matches the module name
 * against the PdbModules list, and uses DbgHelp to resolve the RVA
 * to a real function name + offset.  Lines whose module doesn't
 * match any PDB entry are passed through unchanged.
 *
 * InputTrace     — the string from UnwinderFormatTrace
 * PdbModules     — array of module->PDB path mappings
 * PdbModuleCount — number of entries in PdbModules
 * OutputTrace    — destination buffer, or NULL to query required size
 * OutputSize     — size of OutputTrace in bytes
 *
 * Returns characters written (excl. null terminator).
 * If OutputTrace is NULL or OutputSize is 0, returns the required
 * buffer size (including null terminator).
 *
 * Example:
 *   PDB_MODULE_ENTRY pdbs[] = {
 *       { "ntoskrnl.exe", "C:\\symbols\\ntoskrnl.pdb" },
 *       { "unknown",      "C:\\mydriver\\mydriver.pdb" },
 *   };
 *   INT32 needed = UnwinderResolveTraceWithPdb(trace, pdbs, 2, NULL, 0);
 *   CHAR* resolved = (CHAR*)malloc(needed);
 *   UnwinderResolveTraceWithPdb(trace, pdbs, 2, resolved, needed);
 */
INT32
UnwinderResolveTraceWithPdb(
    _In_                              const CHAR* InputTrace,
    _In_reads_(PdbModuleCount)        const PDB_MODULE_ENTRY* PdbModules,
    _In_                              INT32                    PdbModuleCount,
    _Out_writes_opt_(OutputSize) CHAR* OutputTrace,
    _In_                              INT32                    OutputSize
);