function Get-FalconWorkflow {
<#
.SYNOPSIS
Search for Falcon Fusion workflows
.DESCRIPTION
Requires 'Workflow: Read'.
.PARAMETER Id
Workflow execution identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Execution
Retrieve information about workflow executions
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/workflows/combined/definitions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/workflows/entities/execution-results/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','execution_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=1)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=2)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=3)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=3)]
    [int]$Limit,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/workflows/entities/execution-results/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Mandatory)]
    [switch]$Execution,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) } } else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters -Max 500
    }
  }
}
function Invoke-FalconWorkflow {
<#
.SYNOPSIS
Execute an on-demand Falcon Fusion workflow
.DESCRIPTION
Requires 'Workflow: Write'.
.PARAMETER Cid
Target CID. Child CIDs are supported in Flight Control environments.
.PARAMETER Key
Optional UUID used to help de-duplicate executions
.PARAMETER Depth
Execution depth limit to help prevent execution loops from multiple workflow triggers
.PARAMETER SourceEventUrl
Optional source URL for auditing
.PARAMETER Json
Json string to define Workflow trigger key/value pairs
.PARAMETER Name
Workflow name
.PARAMETER Id
Workflow identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/workflows/entities/execute/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',Position=1)]
    [Parameter(ParameterSetName='Name',Position=1)]
    [Alias('execution_cid')]
    [string[]]$Cid,
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',Position=2)]
    [Parameter(ParameterSetName='Name',Position=2)]
    [string]$Key,
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',Position=3)]
    [Parameter(ParameterSetName='Name',Position=3)]
    [ValidateRange(1,4)]
    [int32]$Depth,
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',Position=4)]
    [Parameter(ParameterSetName='Name',Position=4)]
    [Alias('source_event_url')]
    [string]$SourceEventUrl,
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',Mandatory)]
    [Parameter(ParameterSetName='Name',Mandatory)]
    [string]$Json,
    [Parameter(ParameterSetName='Name',ValueFromPipelineByPropertyName,Mandatory)]
    [string]$Name,
    [Parameter(ParameterSetName='/workflows/entities/execute/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Mandatory)]
    [Alias('definition_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/workflows/entities/execute/v1:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters -JsonBody $PSBoundParameters.Json }
}
function Receive-FalconWorkflow {
<#
.SYNOPSIS
Download a Falcon Fusion workflow YAML
.DESCRIPTION
Requires 'Workflow: Read'.
.PARAMETER Path
Destination path. If not provided, your Workflow identifier will be used to create a file in the local directory.
.PARAMETER Sanitize
Remove potentially identifiable information before export
.PARAMETER Id
Workflow identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/workflows/entities/definitions/export/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/workflows/entities/definitions/export/v1:get',Position=1)]
    [ValidatePattern('\.(yaml|yml)$')]
    [string]$Path,
    [Parameter(ParameterSetName='/workflows/entities/definitions/export/v1:get',Position=2)]
    [boolean]$Sanitize,
    [Parameter(ParameterSetName='/workflows/entities/definitions/export/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('execution_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/workflows/entities/definitions/export/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/yaml' }
    }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    $Param.Format['Outfile'] = 'path'
  }
  process {
    if (!$PSBoundParameters.Path) {
      $PSBoundParameters['Path'] = Join-Path (Get-Location).Path ($PSBoundParameters.Id,'yaml' -join '.')
    }
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Send-FalconWorkflow {
<#
.SYNOPSIS
Upload a Fusion workflow YAML
.DESCRIPTION
Requires 'Workflow: Write'.
.PARAMETER Name
Workflow name
.PARAMETER ValidateOnly
Validate workflow without creating it
.PARAMETER Path
Path to Falcon Fusion workflow YAML
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/workflows/entities/definitions/import/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/workflows/entities/definitions/import/v1:post',Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/workflows/entities/definitions/import/v1:post',Position=2)]
    [Alias('validate_only')]
    [boolean]$ValidateOnly,
    [Parameter(ParameterSetName='/workflows/entities/definitions/import/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('\.(yaml|yml)$')]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist or is a directory."
      }
    })]
    [Alias('data_file','FullName')]
    [string]$Path
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ ContentType = 'multipart/form-data' }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}