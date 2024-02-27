# PowerShell script content
$fuzzplaygroundProcess = Start-Process .\fuzzplayground -PassThru
$integrationTestProcess = Start-Process .\integration-test -PassThru
Wait-Process -InputObject $integrationTestProcess
if ($fuzzplaygroundProcess -ne $null) {
    Stop-Process -InputObject $fuzzplaygroundProcess
}
if ($integrationTestProcess.ExitCode -eq 0) {
    exit 0
} else {
    exit 1
}