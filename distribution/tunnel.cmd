@echo off
setlocal
set "APP_DIR=%~dp0"
if exist "%APP_DIR%runtime\bin\java.exe" (
  set "TUNNEL_JAVA=%APP_DIR%runtime\bin\java.exe"
) else if defined JAVA_HOME (
  set "TUNNEL_JAVA=%JAVA_HOME%\bin\java.exe"
) else (
  set "TUNNEL_JAVA=java"
)
if not defined JAVA_OPTS set "JAVA_OPTS=-Xms16m -Xmx128m -XX:MaxDirectMemorySize=64m"
"%TUNNEL_JAVA%" %JAVA_OPTS% -jar "%APP_DIR%tunnel.jar" %*
exit /b %ERRORLEVEL%
