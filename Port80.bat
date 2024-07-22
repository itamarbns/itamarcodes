@echo off

cd /d C:\Users\%USERNAME%\Desktop

netstat -na > network.txt

findstr /r /c:"\:80 " network.txt >nul

if %errorlevel% equ 0 (
    echo Port 80 is present
) else (
    echo Port 80 is not present
)
	
del network.txt

pause