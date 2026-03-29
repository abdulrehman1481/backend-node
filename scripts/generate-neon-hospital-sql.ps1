$ErrorActionPreference = "Stop"

$csvPath = "D:\appdev\bdd\archive\pakistan_hospitals_details.csv"
$outPath = "D:\appdev\bdd\backend-node\scripts\seed_hospitals_neon.sql"

if (-not (Test-Path $csvPath)) {
  throw "CSV not found: $csvPath"
}

$rows = Import-Csv -Path $csvPath

function Normalize-Text {
  param([string]$Value)

  if ($null -eq $Value) {
    return ""
  }

  $text = $Value -replace "\s+", " "
  return $text.Trim()
}

function Escape-Sql {
  param([string]$Value)

  $normalized = Normalize-Text -Value $Value
  return $normalized.Replace("'", "''")
}

function Parse-DoctorsCount {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return "NULL"
  }

  $digits = $Value -replace "[^0-9]", ""
  if ([string]::IsNullOrWhiteSpace($digits)) {
    return "NULL"
  }

  $number = [int]$digits
  if ($number -le 0) {
    return "NULL"
  }

  return "$number"
}

function Get-Sha1Hex {
  param([string]$Text)

  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant())
    $hash = $sha1.ComputeHash($bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
  }
  finally {
    $sha1.Dispose()
  }
}

$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine("-- Generated from archive/pakistan_hospitals_details.csv")
[void]$sb.AppendLine("-- Run this in Neon SQL Editor")
[void]$sb.AppendLine("BEGIN;")
[void]$sb.AppendLine("")

foreach ($row in $rows) {
  $name = Escape-Sql -Value $row."HOSPITAL NAME"
  if ([string]::IsNullOrWhiteSpace($name)) {
    continue
  }

  $city = Escape-Sql -Value $row."CITY"
  if ([string]::IsNullOrWhiteSpace($city)) {
    $city = "Unknown"
  }

  $area = Escape-Sql -Value $row."AREA"
  $address = Escape-Sql -Value $row."ADDRESS"
  $contact = Escape-Sql -Value $row."CONTACT"
  $doctorsCount = Parse-DoctorsCount -Value $row."DOCTORS"

  $idInput = "$name|$city|$area|$address"
  $externalId = "csv:" + (Get-Sha1Hex -Text $idInput)

  [void]$sb.AppendLine('INSERT INTO "core_medicalcenter" ("name", "city", "area", "address", "contact", "doctors_count", "center_type", "location", "source", "external_id")')
  [void]$sb.AppendLine(('VALUES (''{0}'', ''{1}'', ''{2}'', ''{3}'', ''{4}'', {5}, ''HOSPITAL'', ''{{"lat":24.8607,"lng":67.0011}}''::jsonb, ''csv_seed'', ''{6}'')' -f $name, $city, $area, $address, $contact, $doctorsCount, $externalId))
  [void]$sb.AppendLine('ON CONFLICT ("external_id") DO UPDATE SET')
  [void]$sb.AppendLine('  "name" = EXCLUDED."name",')
  [void]$sb.AppendLine('  "city" = EXCLUDED."city",')
  [void]$sb.AppendLine('  "area" = EXCLUDED."area",')
  [void]$sb.AppendLine('  "address" = EXCLUDED."address",')
  [void]$sb.AppendLine('  "contact" = EXCLUDED."contact",')
  [void]$sb.AppendLine('  "doctors_count" = EXCLUDED."doctors_count",')
  [void]$sb.AppendLine('  "center_type" = EXCLUDED."center_type",')
  [void]$sb.AppendLine('  "location" = EXCLUDED."location",')
  [void]$sb.AppendLine('  "source" = EXCLUDED."source";')
  [void]$sb.AppendLine("")
}

[void]$sb.AppendLine('SELECT setval(')
[void]$sb.AppendLine('  pg_get_serial_sequence(''"core_medicalcenter"'', ''id''),')
[void]$sb.AppendLine('  COALESCE((SELECT MAX(id) FROM "core_medicalcenter"), 1),')
[void]$sb.AppendLine('  true')
[void]$sb.AppendLine(');')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("COMMIT;")

[System.IO.File]::WriteAllText($outPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

$insertCount = (Select-String -Path $outPath -Pattern '^INSERT INTO').Count
Write-Output "Generated SQL at: $outPath"
Write-Output "Rows exported: $insertCount"
