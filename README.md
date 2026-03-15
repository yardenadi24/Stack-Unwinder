# Stack-Unwinder
Unwind x64 stack

command (offline):

StackUnwinderTest.exe resolve <trace.txt> <pdbs.txt>

trace.txt example:
===== Stack Trace (12 frames) =====
  [ 0]  StackUnwinder!sub_11B20+0x0  (0x11B74)
  [ 1]  StackUnwinder!sub_12040+0x0  (0x12084)
  [ 2]  USER32.dll!EnumWindows+0x116  (0x3DD16)
  [ 3]  StackUnwinder!sub_11A90+0x0  (0x11AC5)
  [ 4]  StackUnwinder!sub_13910+0x0  (0x139B9)
  [ 5]  StackUnwinder!sub_13B00+0x0  (0x13B32)
  [ 6]  StackUnwinder!sub_1A730+0x0  (0x1A769)
  [ 7]  StackUnwinder!sub_1A4E0+0x0  (0x1A612)
  [ 8]  StackUnwinder!sub_1A4C0+0x0  (0x1A4CE)
  [ 9]  StackUnwinder!sub_1A7F0+0x0  (0x1A7FE)
  [10]  KERNEL32.dll!BaseThreadInitThunk+0x17  (0x2E8D7)
  [11]  ntdll.dll!RtlUserThreadStart+0x2C  (0x8C48C)
===================================

pdbs.txt example:
ntoskrnl.exe=C:\symbols\ntkrnlmp.pdb
unknown=C:\mydriver\mydriver.pdb
StackUnwinderTest.exe=C:\build\StackUnwinderTest.pdb
