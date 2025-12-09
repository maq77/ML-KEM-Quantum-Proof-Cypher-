Set WshShell = CreateObject("WScript.Shell")

' Get directory of this .vbs file (project root)
currentDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

' Build command to run the batch file hidden
cmd = "cmd.exe /c """ & currentDir & "\run.bat"""

' 0 = hidden window, False = don't wait for it to finish
WshShell.Run cmd, 0, False
