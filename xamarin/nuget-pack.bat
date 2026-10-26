set version=%1

nuget pack Hwsecurity\Hwsecurity.csproj -Version %version% -Properties Configuration=Release
nuget pack HwsecurityFido\HwsecurityFido.csproj -Version %version% -Properties Configuration=Release
nuget pack HwsecurityFido2\HwsecurityFido2.csproj -Version %version% -Properties Configuration=Release
nuget pack HwsecurityUi\HwsecurityUi.csproj -Version %version% -Properties Configuration=Release
