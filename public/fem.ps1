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
    [Parameter(ParameterSetName='/fem/combined/ecosystem-subsidiaries/v1:get')]
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
    # Make request for unmodified result
    Invoke-Falcon @Param -UserInput $PSBoundParameters -RawOutput | ForEach-Object {
      if ($_.meta.version_id -and $_.resources) {
        # Capture 'version_id' from 'meta'
        $version_id = $_.meta.version_id
        if ($Param.Endpoint -match '/queries/') {
          @($_.resources).foreach{
            # Convert 'id' string to object with 'id' and 'version_id' values
            [PSCustomObject]@{ id = $_; version_id = $version_id }
          }
        } else {
          @($_.resources).foreach{
            # Append 'version_id' and return each detailed result
            Set-Property $_ version_id $version_id
            $_
          }
        }
      } else {
        # Return entire result if 'meta.version_id' and 'resources' are not present
        $_
      }
    }
  }
}
function New-CommandName {
<#
.SYNOPSIS
Download the entire contents of the blob. The relative link to this endpoint is returned in the GET /entities/external-assets/v1 request.
.DESCRIPTION
Requires 'Falcon Discover: Read'.
.PARAMETER Assetid
The Asset ID
.PARAMETER Hash
The File Hash
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/blobs-download/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/blobs-download/v1:get',Mandatory,Position=0)]
    [string]$Assetid,
    [Parameter(ParameterSetName='/fem/entities/blobs-download/v1:get',Mandatory,Position=0)]
    [string]$Hash
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Download a preview of the blob. The relative link to this endpoint is returned in the GET /entities/external-assets/v1 request.
.DESCRIPTION
Requires 'Falcon Discover: Read'.
.PARAMETER Assetid
The Asset ID
.PARAMETER Hash
The File Hash
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/blobs-preview/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/blobs-preview/v1:get',Mandatory,Position=0)]
    [string]$Assetid,
    [Parameter(ParameterSetName='/fem/entities/blobs-preview/v1:get',Mandatory,Position=0)]
    [string]$Hash
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Add external assets for external asset scanning.
.DESCRIPTION
Requires 'Falcon Discover: Write'.
.PARAMETER Assets
Assets to be added
.PARAMETER SubsidiaryId
Subsidiary ID to which assets are to be added
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/external-asset-inventory/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/external-asset-inventory/v1:post',Mandatory,Position=0)]
    [inventoryapi.UserExternalAsset]$Assets,
    [Parameter(ParameterSetName='/fem/entities/external-asset-inventory/v1:post',Position=0)]
    [Alias('subsidiary_id')]
    [string]$SubsidiaryId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Delete multiple external assets.
.DESCRIPTION
Requires 'Falcon Discover: Write'.
.PARAMETER Id
XXX identifier

One or more asset IDs (max: 100).
.PARAMETER Description
Some description that the user attached to the delete
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/external-assets/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:delete',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:delete',Mandatory,Position=0)]
    [string]$Description
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}