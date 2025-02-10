function Edit-FalconCorrelationRule {
<#
.SYNOPSIS
Modify Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Id
Correlation rule identifier
.PARAMETER Name
Correlation rule name
.PARAMETER Description
Correlation rule description
.PARAMETER Tactic
MITRE ATT&CK tactic identifier
.PARAMETER Technique
MITRE ATT&CK technique identifier
.PARAMETER Severity
Correlation rule severity
.PARAMETER Search
Search properties ('filter', 'lookback', 'outcome', 'trigger_mode')
.PARAMETER Operation
Operation properties ('schedule', 'start_on', 'stop_on')
.PARAMETER Status
Correlation rule status
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidatePattern('^TA\d{4}$')]
    [string]$Tactic,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidatePattern('^T\d{4}$')]
    [string]$Technique,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [ValidateSet(10,30,50,70,90)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [object]$Search,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [object]$Operation,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=9)]
    [ValidateSet('active','inactive',IgnoreCase=$false)]
    [string]$Status
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
  }
  process {
    @('search','operation').foreach{
      if ($PSBoundParameters.$_) {
        # Add 'search' and 'operation' to 'root' list in Format
        [void]$Param.Format.Body.Remove($_)
        $Param.Format.Body.root += $_
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconCorrelationRule {
<#
.SYNOPSIS
Search for Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Read'.
.PARAMETER Id
Correlation rule identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/queries/rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=1)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=2)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=3)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=3)]
    [ValidateSet('created_on|asc','created_on|desc','last_updated_on|asc','last_updated_on|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=4)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconCorrelationRule {
<#
.SYNOPSIS
Create Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Name
Correlation rule name
.PARAMETER Description
Correlation rule description
.PARAMETER Cid
Customer identifier
.PARAMETER Tactic
MITRE ATT&CK tactic identifier
.PARAMETER Technique
MITRE ATT&CK technique identifier
.PARAMETER Severity
Correlation rule severity
.PARAMETER Search
Search properties ('filter', 'lookback', 'outcome', 'trigger_mode')
.PARAMETER Operation
Operation properties ('schedule', 'start_on', 'stop_on')
.PARAMETER Status
Correlation rule status
.PARAMETER TriggerOnCreate
Trigger correlation rule upon creation
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('customer_id')]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidatePattern('^TA\d{4}$')]
    [string]$Tactic,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidatePattern('^T\d{4}$')]
    [string]$Technique,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=6)]
    [ValidateSet(10,30,50,70,90)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=7)]
    [object]$Search,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=8)]
    [object]$Operation,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=9)]
    [ValidateSet('active','inactive',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Position=10)]
    [Alias('trigger_on_create')]
    [boolean]$TriggerOnCreate,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Position=11)]
    [string]$Comment
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
  }
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    @('search','operation').foreach{
      if ($PSBoundParameters.$_) {
        # Add 'search' and 'operation' to 'root' list in Format
        [void]$Param.Format.Body.Remove($_)
        $Param.Format.Body.root += $_
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconCorrelationRule {
<#
.SYNOPSIS
Remove Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Id
Correlation rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}