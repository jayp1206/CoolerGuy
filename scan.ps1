Get-ChildItem "C:\path\to\your\directory" -Recurse | ForEach-Object {
    Get-Item $_.FullName -Stream * | Where-Object Stream -ne ':$DATA' | Select-Object FileName, Stream
}
