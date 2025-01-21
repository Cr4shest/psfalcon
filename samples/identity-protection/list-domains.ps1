#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
List domains configured in Falcon Identity Protection
#>
try {
  (Invoke-FalconIdentityGraph -String '{domains(dataSources:[])}').domains
} catch {
  throw $_
}