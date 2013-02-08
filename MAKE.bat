set SEVENZIP_HOME="C:\Program Files\7-Zip"
set PYINSTALLER_HOME="C:\pyinstaller-2.0"
set APPP_VERSION=0.2.0
set APPP_WINDOWS_VERSION=0.2.0
if exist MAKE rmdir MAKE /s /q
mkdir MAKE
cd MAKE
rem APPP
mkdir APPP-%APPP_VERSION%
cd APPP-%APPP_VERSION%
copy ..\..\APPP.bat APPP.bat
copy ..\..\APPP.ini APPP.ini
copy ..\..\APPP.py APPP.py
copy ..\..\DNS.ini DNS.ini
copy ..\..\README.txt README.txt
cd ..
%SEVENZIP_HOME%\7z.exe a -tzip APPP-%APPP_VERSION%.zip APPP-%APPP_VERSION%
rem APPP_WINDOWS
mkdir PYINSTALLER
cd PYINSTALLER
python %PYINSTALLER_HOME%\pyinstaller.py -c -F ..\..\APPP.py
cd ..
mkdir APPP_WINDOWS-%APPP_WINDOWS_VERSION%
cd APPP_WINDOWS-%APPP_WINDOWS_VERSION%
copy ..\PYINSTALLER\dist\APPP.exe APPP.exe
copy ..\..\APPP_WINDOWS\APPP.bat APPP.bat
copy ..\..\APPP_WINDOWS\README.txt README.txt
copy ..\..\APPP.ini APPP.ini
copy ..\..\DNS.ini DNS.ini
cd ..
%SEVENZIP_HOME%\7z.exe a -tzip APPP_WINDOWS-%APPP_WINDOWS_VERSION%.zip APPP_WINDOWS-%APPP_WINDOWS_VERSION%
cd ..