# Stack-Unwinder
Unwind x64 stack

command (offline):

StackUnwinderTest.exe resolve <trace.txt> <pdbs.txt>

trace.txt:
The output of the tracer:

===== Stack Trace (12 frames) =====

===================================

pdbs.txt example:
ntoskrnl.exe=C:\symbols\ntkrnlmp.pdb
unknown=C:\mydriver\mydriver.pdb
StackUnwinderTest.exe=C:\build\StackUnwinderTest.pdb
