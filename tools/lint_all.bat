@echo off
cd ..
call :search_lint include\cfdcore ..\..
call :search_lint src ..
call :search_lint src\include\cfdcore ..\..\..

pause
exit /b

:search_lint
cd %1
for %%A in (*.h) do (
    call python %2\tools\cpplint\cpplint.py %%A
)
for %%A in (*.cpp) do (
    call python %2\tools\cpplint\cpplint.py %%A
)
cd %2
exit /b
