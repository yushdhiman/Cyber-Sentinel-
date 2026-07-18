@echo off
echo Staging all changes...
git add .

set /p commit_msg="Enter commit message (or press Enter for default 'auto-commit'): "
if "%commit_msg%"=="" (
    set commit_msg=auto-commit at %date% %time%
)

echo Committing changes...
git commit -m "%commit_msg%"

echo Pushing to GitHub...
git push

echo.
echo ==========================================
echo Changes pushed to GitHub successfully!
echo ==========================================
pause
