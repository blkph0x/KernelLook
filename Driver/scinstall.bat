set "currentDir=%CD%"
echo Current Directory: "%currentDir%"
sc create MyDriver type= kernel binPath= "%currentDir%\Driver\x64\Release\KMDFDriver5.sys"
pause
sc start MyDriver
pause