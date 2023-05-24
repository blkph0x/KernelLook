set "currentDir=%CD%"
echo Current Directory: "%currentDir%"
sc create MyDriver type= kernel binPath= "%currentDir%\KMDFDriver5.sys"
pause
sc start MyDriver
pause