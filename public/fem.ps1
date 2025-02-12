function Edit-FalconAsset {
<#
.SYNOPSIS
Assign criticality to an external asset within Falcon Discover
.DESCRIPTION
Requires 'Falcon Discover: Write'.
.PARAMETER Criticality
Asset criticality level
.PARAMETER Comment
Audit log comment
.PARAMETER Cid
Customer identifier
.PARAMETER Id
External asset identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconAsset
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/external-assets/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Position=1)]
    [ValidateSet('Critical','High','Noncritical','Unassigned',IgnoreCase=$false)]
    [string]$Criticality,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Position=2)]
    [Alias('criticality_description')]
    [string]$Comment,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=4)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconSubsidiary {
<#
.SYNOPSIS
Search for Falcon Exposure Management subsidiaries
.DESCRIPTION
Requires 'Falcon Discover: Read'.
.PARAMETER VersionId
Version identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSubsidiary
#>
  [CmdletBinding(DefaultParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/ecosystem-subsidiaries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get',Position=1)]
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get',Position=1)]
    [Parameter(ParameterSetName='/fem/entities/ecosystem-subsidiaries/v1:get',ValueFromPipelineByPropertyName,
      Position=2)]
    [Alias('version_id')]
    [string]$VersionId,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get',Position=2)]
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get',Position=3)]
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get',Position=3)]
    [ValidateSet('name|asc','name|desc','primary_domain|asc','primary_domain|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get',Position=4)]
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get',Position=4)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get')]
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/fem/queries/ecosystem-subsidiaries/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      $Param['Max'] = 100
    }
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters -RawOutput
    if ($Request.meta.version_id -and $Request.resources) {
      if ($Param.Endpoint -match '/queries/') {
        # Create object with 'id' value
        $Request.resources = @($Request.resources).foreach{ [PSCustomObject]@{ id = $_ } }
      }
      @($Request.resources).foreach{
        # Append 'version_id' and output each result
        Set-Property $_ version_id $Request.meta.version_id
        $_
      }
    }
  }
}