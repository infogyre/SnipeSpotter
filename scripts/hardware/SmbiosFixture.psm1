# pattern: Functional Core
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# SMBIOS Type 1 UUID occupies formatted offsets 8..23. An all-zero value is the
# documented privacy sentinel: it preserves the 16-byte field and carries no identity.
function Protect-SmbiosFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Data)

    if ($Data.Length -lt 8) { throw 'smbios_invalid_wrapper' }
    $declaredLength = [BitConverter]::ToUInt32($Data, 4)
    if ($declaredLength -eq 0 -or $declaredLength -ne $Data.Length - 8) { throw 'smbios_invalid_wrapper' }
    $tableEnd = 8 + [int]$declaredLength
    $redacted = [byte[]]::new($Data.Length)
    [Array]::Copy($Data, $redacted, $Data.Length)
    $offset = 8
    $structureCount = 0
    $uuidFieldsRedacted = 0

    while ($offset -lt $tableEnd) {
        if ($tableEnd - $offset -lt 4) { throw 'smbios_truncated_structure' }
        $structureType = [int]$redacted[$offset]
        $structureLength = [int]$redacted[$offset + 1]
        if ($structureLength -lt 4) { throw 'smbios_invalid_structure_length' }
        $formattedEnd = $offset + $structureLength
        if ($formattedEnd -gt $tableEnd) { throw 'smbios_truncated_structure' }
        if ($structureType -eq 1) {
            if ($structureLength -lt 24) { throw 'smbios_type1_uuid_unavailable' }
            for ($index = $offset + 8; $index -lt $offset + 24; $index++) { $redacted[$index] = 0 }
            $uuidFieldsRedacted++
        }

        $stringEnd = -1
        for ($cursor = $formattedEnd; $cursor + 1 -lt $tableEnd; $cursor++) {
            if ($redacted[$cursor] -eq 0 -and $redacted[$cursor + 1] -eq 0) { $stringEnd = $cursor + 2; break }
        }
        if ($stringEnd -lt 0) { throw 'smbios_unterminated_strings' }

        $stringIndex = 1
        $stringStart = $formattedEnd
        for ($cursor = $formattedEnd; $cursor -lt $stringEnd - 1; $cursor++) {
            if ($redacted[$cursor] -ne 0) { continue }
            $byteLength = $cursor - $stringStart
            if ($byteLength -gt 0) {
                $placeholder = "PLACEHOLDER_T${structureType}_S${stringIndex}_I${structureCount}"
                $placeholderBytes = [Text.Encoding]::ASCII.GetBytes($placeholder)
                for ($index = 0; $index -lt $byteLength; $index++) {
                    $redacted[$stringStart + $index] = if ($index -lt $placeholderBytes.Length) { $placeholderBytes[$index] } else { 0x58 }
                }
                $stringIndex++
            }
            $stringStart = $cursor + 1
        }
        $structureCount++
        $offset = $stringEnd
        if ($structureType -eq 127) {
            if ($offset -ne $tableEnd) { throw 'smbios_trailing_data' }
            break
        }
    }
    if ($offset -ne $tableEnd) { throw 'smbios_invalid_table_end' }
    [pscustomobject]@{ Bytes = $redacted; StructureCount = $structureCount; UuidFieldsRedacted = $uuidFieldsRedacted }
}

Export-ModuleMember -Function Protect-SmbiosFixture
