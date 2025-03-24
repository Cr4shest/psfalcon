function New-FalconLookupFile {
<#
.SYNOPSIS
Upload a lookup file to Falcon NGSIEM
.DESCRIPTION
Requires 'NGSIEM: Write'.
.PARAMETER Repository
Repository name
.PARAMETER Path
Path to lookup file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/humio/api/v1/repositories/{repository}/files:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('\.csv$')]
    [Alias('file')]
    [string]$Path,
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files:post',Mandatory,Position=2)]
    [ValidateSet('3pi_parsers','event_search_all','falcon_for_it_view','forensics_view','investigate_view',
      'search-all',IgnoreCase=$false)]
    [string]$Repository
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ formdata = @('file') }
      Headers = @{ Accept = 'text/plain'; ContentType = 'multipart/form-data' }
    }
  }
  process {
    $Param.Endpoint = $Param.Endpoint -replace '\{repository\}',$PSBoundParameters.Repository
    [void]$PSBoundParameters.Remove('Repository')
    Invoke-Falcon @Param -UserInput $PSBoundParameters -RawOutput
  }
}