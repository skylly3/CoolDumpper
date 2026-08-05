@echo off
echo 正在修改注册表...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v MoveImages /t REG_DWORD /d 0 /f

echo 修改完成，需要重启脚本以使部分设置生效...
echo 10秒后自动重启...
ping 127.0.0.1 -n 10 > nul

REM 重启脚本自身
start "" "%~f0"
exit