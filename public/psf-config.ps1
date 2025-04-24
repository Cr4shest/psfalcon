function Export-FalconConfig {
<#
.SYNOPSIS
Create an archive containing Falcon configuration files
.DESCRIPTION
Uses various PSFalcon commands to gather and export groups, policies and exclusions as a collection of Json files
within a zip archive. The exported files can be used with 'Import-FalconConfig' to restore configurations to your
existing CID or create them in another CID.
.PARAMETER Select
Selected items to export from your current CID, or leave unspecified to export all available items
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Export-FalconConfig
#>
  [CmdletBinding(DefaultParameterSetName='ExportItem',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='ExportItem',Position=1)]
    [ValidateSet('ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup',
      'FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion','PreventionPolicy',
      'ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [Alias('Items')]
    [string[]]$Select,
    [Parameter(ParameterSetName='ExportItem')]
    [switch]$Force
  )
  begin {
    function Get-ItemContent ([string]$String) {
      # Request content for provided 'Item'
      Write-Host ('[Export-FalconConfig] Exporting "{0}"...' -f $String)
      $ConfigFile = Join-Path $Location "$String.json"
      $Config = if ($String -match '^FileVantage(Policy|RuleGroup)$') {
        [string]$Filter = if ($String -eq 'FileVantagePolicy') {
          # Filter to user-created FileVantagePolicy
          '$_.created_by -ne "cs-cloud-provisioning" -and $_.name -notmatch "^Default Policy \((Linux|Mac|' +
            'Windows)\)$"'
        } else {
          # Filter to user-created FileVantageRuleGroup
          '$_.created_by -ne "internal"'
        }
        $Param = @{ Detailed = $true; All = $true }
        if ($String -eq 'FileVantagePolicy' ) { $Param['include'] = 'exclusions' }
        @((Get-Command "Get-Falcon$String").Parameters.Type.Attributes.ValidValues).foreach{
          # Retrieve FileVantagePolicy/RuleGroup for each 'Type'
          & "Get-Falcon$String" @Param -Type $_ 2>$null |
            Where-Object -FilterScript ([scriptblock]::Create($Filter))
        }
      } elseif ($String -match '(?<!Content)Policy$') {
        @('Windows','Mac','Linux').foreach{
          # Create policy exports in 'platform_name' order to retain precedence
          & "Get-Falcon$String" -Filter "platform_name:'$_'" -Detailed -All 2>$null
        }
      } else {
        & "Get-Falcon$String" -Detailed -All 2>$null
      }
      if ($Config) {
        if ($String -eq 'FirewallPolicy') {
          # Export firewall settings
          Write-Host '[Export-FalconConfig] Exporting "FirewallSetting"...'
          $Setting = Get-FalconFirewallSetting -Id $Config.id 2>$null
          foreach ($i in $Setting) {
            ($Config | Where-Object { $_.id -eq $i.policy_id }).PSObject.Properties.Add((
              New-Object PSNoteProperty('settings',$i)
            ))
          }
        } elseif ($String -eq 'FileVantageRuleGroup') {
          # Update 'assigned_rules' with rule content inside FileVantage rule groups
          foreach ($i in $Config) {
            $RuleId = $i.assigned_rules.id | Where-Object { ![string]::IsNullOrWhiteSpace($_) }
            if ($RuleId) {
              Write-Host ('[Export-FalconConfig] Exporting rules for {0} group "{1}"...' -f $i.type,$i.name)
              $i.assigned_rules = @(Get-FalconFileVantageRule -RuleGroupId $i.id -Id $RuleId)
            }
          }
        } elseif ($String -eq 'HostGroup') {
          if ($Config.group_type -match '^static') {
            Write-Host '[Export-FalconConfig] Collecting list of hosts to match "HostGroup" members...'
            try {
              [System.Collections.Generic.List[object]]$HostList = Get-FalconHost -Detailed -All -Field device_id,
                platform_name,hostname
              if ($HostList) {
                foreach ($i in @($Config).Where({$_.group_type -match '^static'})) {
                  # Split 'assignment_rule' into list of hostname or device_id values
                  $RuleList = @($i.assignment_rule -split '(device_id:|hostname:)').Where({
                    $_ -match '\[.+\]'}) -replace "^\[|'|\],?$" -split ','
                  $Member = if ($RuleList -and $i.group_type -eq 'static') {
                    # Match 'members' by hostname
                    @($HostList).Where({$RuleList -contains $_.hostname})
                  } elseif ($Rulelist -and $i.group_type -eq 'staticByID') {
                    # Match 'members' by device_id
                    @($HostList).Where({$RuleList -contains $_.device_id})
                  }
                  if ($Member) {
                    # Add selected host info as 'members'
                    Write-Host ('[Export-FalconConfig] Appending members to HostGroup "{0}"...' -f $i.name)
                    $i.PSObject.Properties.Add((New-Object PSNoteProperty('members',@($Member))))
                  }
                }
              }
            } catch {
              Write-Error 'Unable to collect list of hosts. Verify "Hosts: Read" permission.'
            }
          }
        }
        # Export results to json file and output created file name
        try {
          ConvertTo-Json @($Config) -Depth 32 | Out-File $ConfigFile -Append
          $ConfigFile
        } catch {
          throw "Unable to write to '$((Get-Location).Path)'. Try 'Export-FalconConfig' in a new location."
        }
      }
    }
    # Get current location and set output archive path
    $Location = (Get-Location).Path
    $ExportFile = Join-Path $Location "FalconConfig_$(Get-Date -Format FileDateTime).zip"
  }
  process {
    $OutPath = Test-OutFile $ExportFile
    if ($OutPath.Category -eq 'WriteError' -and !$Force) {
      Write-Error @OutPath
    } else {
      if (!$Select) {
        # Use items in 'ValidateSet' when not provided
        [string[]]$Select = @((Get-Command $MyInvocation.MyCommand.Name).ParameterSets.Where({$_.Name -eq
          'ExportItem'}).Parameters.Where({$_.Name -eq 'Select'}).Attributes.ValidValues).foreach{ $_ }
      }
      if ($Select -contains 'FileVantagePolicy' -and $Select -notcontains 'FileVantageRuleGroup') {
        # Force 'FileVantageRuleGroup' when exporting 'FileVantagePolicy' for 'rule_groups'
        [string[]]$Select = @($Select + 'FileVantageRuleGroup')
      }
      if ($Select -contains 'FirewallGroup') {
        # Force 'FirewallRule' when exporting 'FirewallGroup'
        [string[]]$Select = @($Select + 'FirewallRule')
      }
      if ($Select -match '^((Ioa|Ml|Sv)Exclusion|FileVantagePolicy|Ioc)$' -and $Select -notcontains 'HostGroup') {
        # Force 'HostGroup' when exporting exclusions or IOCs
        [string[]]$Select = @($Select + 'HostGroup')
      }
      # Retrieve results, export to Json and capture file name
      [string[]]$JsonFiles = foreach ($String in $Select) { ,(Get-ItemContent $String) }
      if ($JsonFiles -and $PSCmdlet.ShouldProcess($ExportFile,'Compress-Archive')) {
        # Archive Json exports with content and remove them when complete
        $Param = @{
          Path = @(Get-ChildItem).Where({$JsonFiles -contains $_.FullName -and $_.Length -gt 0}).FullName
          DestinationPath = $ExportFile
          Force = $Force
        }
        Compress-Archive @Param
        @($JsonFiles).foreach{
          if (Test-Path $_) {
            Write-Log 'Export-FalconConfig' "Removing '$_'"
            Remove-Item $_ -Force
          }
        }
      }
      # Display created archive
      if (Test-Path $ExportFile) { Get-ChildItem $ExportFile | Select-Object FullName,Length,LastWriteTime }
    }
  }
}
function Import-FalconConfig {
<#
.SYNOPSIS
Import items from a 'FalconConfig' archive into your Falcon environment
.DESCRIPTION
Creates groups, policies, exclusions, rules and scripts within a 'FalconConfig' archive within your authenticated
Falcon environment.

Anything that already exists will be ignored and no existing items will be modified unless the relevant parameters
are included.

If using 'Select', any dependencies are added based on your input and whether or not the 'AssignExisting' switch
is included.

Requires 'Sensor Download: Read' permission for CID comparison plus the relevant read and write permissions for
items that are being imported.
.PARAMETER Path
FalconConfig archive path
.PARAMETER Select
Import selected files from archive
.PARAMETER AssignExisting
Assign existing host groups with identical names to imported items
.PARAMETER ModifyDefault
Modify default policies to match import. Use 'All' for all possible values (or all values in 'Select').
.PARAMETER ModifyExisting
Modify existing items to match import. Use 'All' for all possible values (or all values in 'Select').
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Import-FalconConfig
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [ValidatePattern('\.zip$')]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist or is not a file."
      }
    })]
    [string]$Path,
    [ValidateSet('ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup','FirewallGroup',
      'FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion','PreventionPolicy',
      'ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [string[]]$Select,
    [Alias('Force')]
    [switch]$AssignExisting,
    [ValidateSet('All','ContentPolicy','DeviceControlPolicy','PreventionPolicy','ResponsePolicy',
      'SensorUpdatePolicy')]
    [string[]]$ModifyDefault,
    [ValidateSet('All','ContentPolicy','DeviceControlPolicy','FileVantagePolicy','FileVantageRuleGroup',
      'FirewallGroup','FirewallPolicy','HostGroup','IoaExclusion','IoaGroup','Ioc','MlExclusion',
      'PreventionPolicy','ResponsePolicy','Script','SensorUpdatePolicy','SvExclusion')]
    [string[]]$ModifyExisting
  )
  begin {
    function Add-Result {
      # Create result object for CSV output
      param(
        [ValidateSet('Created','Failed','Ignored','Modified')]
        [string]$Action,
        [PSCustomObject]$Item,
        [string]$Type,
        [string]$Property,
        [string]$Old,
        [string]$New,
        [string]$Comment,
        [string]$Log
      )
      $Result = [PSCustomObject]@{
        time = Get-Date -Format o
        api_client_id = if ($Action -eq 'Ignored') { $null } else { $Script:Falcon.ClientId }
        type = $Type
        id = if ($Type -eq 'FileVantageRule') {
          'rule_group_id',$Item.rule_group_id -join ':'
        } elseif ($Item.instance_id) {
          $Item.instance_id
        } elseif ($Item.family) {
          $Item.family
        } else {
          $Item.id
        }
        name = if ($Type -eq 'FileVantageRule') {
          'precedence',$Item.precedence -join ':'
        } else {
          Select-ObjectName $Item $Type
        }
        platform = if ($Item.platform) {
          $Item.platform -join ','
        } elseif ($Item.platforms) {
          $Item.platforms -join ','
        } elseif ($Item.platform_name) {
          $Item.platform_name
        } elseif ($Type -eq 'IoaRule' -and $Item.rulegroup_id) {
          # Use 'os' from IoaGroup reference to populate IoaRule 'platform'
          @($Config.IoaGroup.Ref).Where({$_.new.Equals($Item.rulegroup_id)}).os
        } elseif ($Type -match '^FileVantageRule(Group)?$') {
          $Item.type
        } elseif ($Type -eq 'FileVantageExclusion' -and $Item.policy_id) {
          # Use 'os' from FileVantagePolicy reference to populate FileVantageExclusion 'platform'
          @($Config.FileVantagePolicy.Ref).Where({$_.new.Equals($Item.policy_id)}).os
        } elseif ($Type -eq 'FirewallRule' -and $Item.rule_group.id) {
          # Use 'os' from FirewallGroup reference to populate FirewallRule 'platform'
          @($Config.FirewallGroup.Ref).Where({$_.new.Equals($Item.rule_group.id)}).os
        } else {
          $null
        }
        action = $Action
        property = $Property
        old_value = $Old
        new_value = $New
        comment = if ($Comment) {
          $Comment
        } elseif ($Item.family -and $Item.rule_group.id) {
          'rule_group_id',$Item.rule_group.id -join ':'
        } elseif ($Item.policy_id -and $Item.id) {
          'policy_id',$Item.policy_id -join ':'
        }
      }
      # Create Result list to contain results when not present and output result
      if (!$Config.ContainsKey($Type)) { $Config[$Type] = @{} }
      if (!$Config.$Type.ContainsKey('Result')) {
        $Config.$Type['Result'] = [System.Collections.Generic.List[PSCustomObject]]@()
      }
      # Update 'old' and 'new' value to ensure 'False' is present
      if ($Result.old_value -eq 'True' -and !$Result.new_value) {
        Set-Property $Result new_value 'False'
      } elseif ($Result.new_value -eq 'True' -and !$Result.old_value) {
        Set-Property $Result old_value 'False'
      }
      $Config.$Type.Result.Add($Result)
      if ($Action -match '^(Created|Failed|Modified)$') {
        # Notify when items are created or modified or when failures occur
        [System.Collections.Generic.List[string]]$Notify = @('[Import-FalconConfig]',$Action)
        if ($Log) { $Notify.Add($Log) }
        if ($Property) { $Notify.Add(('"{0}" for' -f $Property)) }
        if ($Result.platform -and $Result.platform -notmatch ',' -and $Type -notmatch
        '(FileVantage|Firewall)Rule') {
          $Notify.Add($Result.platform)
        }
        $Notify.Add($Type)
        if ($Type -eq 'FileVantageRule') {
          $Notify.Add(('{0} in "{1}".' -f $Result.name,@($Config.FileVantageRuleGroup.Ref).Where({
            $_.new.Equals($Item.rule_group_id)}).name))
        } elseif ($Type -eq 'FileVantageExclusion') {
          $Notify.Add(('"{0}" in "{1}".' -f $Result.name,@($Config.FileVantagePolicy.Ref).Where({
            $_.new.Equals($Item.policy_id)}).name))
        } else {
          $Notify.Add(('"{0}".' -f $Result.name))
        }
        Write-Host ($Notify -join ' ')
      }
      # Export result to CSV
      try { $Result | Export-Csv $OutputFile -NoTypeInformation -Append } catch { Write-Error $_ }
    }
    function Clear-ConfigList ([string]$Item,[string]$Key) {
      # Remove sub-key from Config
      if ($Config.$Item.ContainsKey($Key)) {
        [void]$Config.$Item.Remove($Key)
        Write-Log 'Clear-ConfigList' ('Removed "{0}" from "{1}"' -f $Key,$Item)
      }
    }
    function Compare-Setting ([object]$New,[object]$Old,[string]$Item,[string]$Property,[switch]$Result) {
      if ($Item -eq 'ContentPolicy') {
        [string[]]$Select = foreach ($Ras in $New.settings.ring_assignment_settings) {
          foreach ($i in $Ras.id) {
            # Check each 'ring_assignment_settings' for modified values using 'id' and 'ring_assignment'
            $NewRas = @($Ras).Where({$_.id -eq $i}).ring_assignment
            $OldRas = @($Old.settings.ring_assignment_settings).Where({$_.id -eq $i}).ring_assignment
            if ($NewRas -ne $OldRas) {
              # Capture result or output modified property name
              if ($Result) { Add-Result Modified $New $Item $i $OldRas $NewRas } else { $i }
            }
          }
        }
        # Output settings for modification
        if ($Select) { $New.settings }
      } elseif ($Item -eq 'DeviceControlPolicy') {
        [object[]]$Select = if ($Old) {
          foreach ($i in @($New.settings.PSObject.Properties)) {
            if ($i.Name -match '^(enforcement_mode|end_user_notification|enhanced_file_metadata)$') {
              if ($i.Value -ne $Old.settings.($i.Name)) {
                if ($Result) {
                  # Capture result
                  Add-Result Modified $New $Item $i.Name $Old.settings.($i.Name) $i.Value
                } else {
                  # Output modified property by name
                  $i.Name
                }
              }
            } elseif ($i.Name -eq 'classes') {
              [string[]]$ClassId = foreach ($c in $i.Value) {
                if ($c.exceptions) {
                  if ($Result) {
                    foreach ($e in $New.settings.classes.exceptions) {
                      if (!@($Old.settings.classes.exceptions).Where({$_.id -eq $e.id})) {
                        # Capture result for each new exception
                        Add-Result Modified $New $Item ($c.id,'exceptions' -join '.') -Comment (
                          '{0} {1}:{2}' -f $e.action,$e.match_method,(
                            @(Select-ObjectName $e DeviceControlException).foreach{$e.$_ }) -join '_') ## this isn't displaying the action in the output
                      }
                    }
                  } else {
                    # Output 'class.id' for modification when new exceptions are present
                    $c.id
                  }
                } else {
                  # Check existing class under DeviceControlPolicy in target CID to compare 'action' value
                  $CompC = $Old.settings.($i.Name).Where({$_.id -eq $c.id})
                  if ($CompC -and $c.action -ne $CompC.action) {
                    if ($Result) {
                      # Capture result for modified 'action'
                      Add-Result Modified $New $Item ($c.id,'action' -join '.') $CompC.action $c.action
                    } else {
                      # Output 'class.id' for modification
                      $c.id
                    }
                  }
                }
              }
              if ($ClassId) { @{l='classes';e={,@($_.classes).Where({$ClassId -contains $_.id})}} }
            }
          }
        }
        # Output settings to be modified
        if ($Select) { $New.settings | Select-Object $Select }
      } elseif ($Item -eq 'FirewallPolicy') {
        [string[]]$PropList = 'default_inbound','default_outbound','enforce','local_logging','platform_id',
          'rule_group_ids','test_mode'
        if ($Result) {
          @($PropList).foreach{
            # Capture result
            if ($Ref.$_ -ne $Obj.$_) { Add-Result Modified $Obj $Item $_ $Ref.settings.$_ $Obj.settings.$_ }
          }
        } else {
          [boolean[]]$Edit = @($PropList).foreach{
            if ($_ -eq 'rule_group_ids') {
              foreach ($i in $Obj.settings.rule_group_ids) {
                # Check for new 'rule_group_ids'
                if ($Ref.settings.rule_group_ids -notcontains $i) { $true } else { $false }
              }
            } else {
              # Compare each property
              if ($Ref.$_ -ne $Obj.$_) { $true } else { $false }
            }
          }
          # Output entire 'settings' object if there are differences
          if ($Edit -eq $true) { $Obj.settings }
        }
      } elseif ($Item -eq 'SensorUpdatePolicy') {
        [string[]]$Select = if ($Old) {
          foreach ($i in @($New.settings.PSObject.Properties)) {
            if ($i.Name -match '^(scheduler|variants)$') {
              if ($Result) {
                # Capture 'scheduler' and 'variants' result as json string
                $OldJson = $Old.settings.($i.Name) | ConvertTo-Json -Compress
                $NewJson = $i.Value | ConvertTo-Json -Compress
                if ($NewJson -ne $OldJson) { Add-Result Modified $New $Item $i.Name $OldJson $NewJson }
              } else {
                # Check for modified 'scheduler' or 'variants' sub-property
                [boolean[]]$SubProp = @($i.Value).foreach{
                  @($_.PSObject.Properties).foreach{
                    if ($_.Value -ne $Old.settings.($i.Name).($_.Name)) { $true } else { $false }
                  }
                }
                # Output property name when modified sub-properties are present
                if ($SubProp -eq $true) { $i.Name }
              }
            } else {
              if ($i.Value -ne $Old.settings.($i.Name)) {
                if ($Result) {
                  # Capture result
                  Add-Result Modified $New $Item $i.Name $Old.settings.($i.Name) $i.Value
                } else {
                  # Output modified property name
                  $i.Name
                }
              }
            }
          }
        }
        # Output settings to be modified by property name
        if ($Select) { $New.settings | Select-Object $Select }
      } elseif ($Item -match 'Policy$') {
        # Compare modified policy settings with 'id' and 'value' sub-properties
        $NewArr = $New.settings
        $OldArr = $Old.settings
        if ($OldArr -or $Result) {
          foreach ($i in $NewArr) {
            if ($i.value.PSObject.Properties.Name -eq 'enabled') {
              if ($OldArr.Where({$_.id -eq $i.id}).value.enabled -ne $i.value.enabled) {
                if ($Result) {
                  # Capture modified result for boolean settings
                  Add-Result Modified $New $Item $i.id $OldArr.Where({$_.id -eq
                    $i.id}).value.enabled $i.value.enabled
                } else {
                  # Output setting to be modified
                  Write-Log 'Compare-Setting' (($Item,$New.id -join ': '),([PSCustomObject]@{id=$i.id;old=(
                    $OldArr.Where({$_.id -eq $i.id}).value | ConvertTo-Json -Compress);new=($i.value |
                    ConvertTo-Json -Compress)} | Format-List | Out-String).Trim() -join "`n")
                  $i | Select-Object id,value
                }
              }
            } else {
              foreach ($n in $i.value.PSObject.Properties.Name) {
                if ($OldArr.Where({$_.id -eq $i.id}).value.$n -ne $i.value.$n) {
                  if ($Result) {
                    # Capture modified result for sub-settings
                    Add-Result Modified $New $Item ($i.id,$v -join ':') @($OldArr).Where({$_.id -eq
                      $i.id}).value.$v $Item.value.$v
                  } else {
                    # Output setting to be modified
                    Write-Log 'Compare-Setting' (($Item,$New.id -join ': '),([PSCustomObject]@{id=$i.id;old=(
                      $OldArr.Where({$_.id -eq $i.id}).value | ConvertTo-Json -Compress);new=($i.value |
                      ConvertTo-Json -Compress)} | Format-List | Out-String).Trim() -join "`n")
                    $i | Select-Object id,value
                  }
                }
              }
            }
          }
        } else {
          # Output new settings
          if ($NewArr.id) { $NewArr | Select-Object id,value } else { $NewArr }
        }
      } elseif ($Result) {
        # Compare other modified item properties
        if ($Property -eq 'field_values') {
          foreach ($Name in $New.$Property.name) {
            # Track 'field_values' for IoaRule for each modified value
            $OldFv = @($Old.$Property).Where({$_.name -eq $Name}).values | ConvertTo-Json -Compress
            $NewFv = @($New.$Property).Where({$_.name -eq $Name}).values | ConvertTo-Json -Compress
            if ($NewFv -ne $OldFv) { Add-Result Modified $New $Item $Name $OldFv $NewFv }
          }
        } elseif ($Property) {
          if ($New.$Property -ne $Old.$Property) {
            # Capture specific modified property
            Add-Result Modified $New $Item $Property $Old.$Property $New.$Property
          }
        } else {
          @($New.PSObject.Properties.Name).Where({$_ -notmatch '^(id|comment)$'}).foreach{
            # Capture modified properties, excluding 'id' and 'comment'
            if ($New.$_ -ne $Old.$_) { Add-Result Modified $New $Item $_ $Old.$_ $New.$_ }
          }
        }
      }
    }
    function Compress-Object ([PSCustomObject[]]$Obj,[string]$Item) {
      # Properties to keep when importing objects for evaluation
      foreach ($i in $Obj) {
        [string[]]$PropList = switch -Regex ($Item) {
          '(Content|DeviceControl|Prevention|Response|SensorUpdate)Policy' {
            'cid','id','name','platform_name','description','enabled','groups','settings'
          }
          '(Ml|Sv)Exclusion' {
            'id','value','applied_globally','is_descendant_process','groups'
          }
          'FileVantagePolicy' {
            'cid','id','name','platform','enabled','rule_groups','host_groups'
          }
          'FileVantageRuleGroup' {
            'id','name','type','assigned_rules','policy_assignments'
          }
          'FirewallGroup' {
            'customer_id','id','name','platform','enabled','deleted','description','rule_ids','policy_ids','rules'
          }
          'FirewallPolicy' {
            'cid','id','name','platform_name','description','enabled','channel_version','rule_set_id','groups',
            'settings'
          }
          'FirewallRule' {
            'id','family','name','enabled','deleted','direction','action','address_family','protocol',
              'fqdn_enabled','fqdn','version','description','rule_group','fields','icmp','local_address',
              'local_port','monitor','remote_address','remote_port'
          }
          'HostGroup' {
            'id','group_type','name','assignment_rule','description'
          }
          'IoaExclusion' {
            'id','name','pattern_id','pattern_name','cl_regex','ifn_regex','applied_globally','groups'
          }
          'IoaGroup' {
            'customer_id','id','name','platform','enabled','deleted','version','description','rules','rule_ids'
          }
          'IoaRule' {
            'comment','customer_id','description','disposition_id','enabled','field_values','instance_id','name',
            'pattern_severity','rulegroup_id','ruletype_id'
          }
          'Ioc' {
            'id','type','value','platforms','severity','deleted','expiration','action','mobile_action','tags',
              'applied_globally','host_groups'
          }
          'Script' {
            'id','name','platform','content','sha256','permission_type','write_access','share_with_workflow',
              'workflow_is_disruptive'
          }
        }
        if ($PropList) {
          # Add or replace properties not defined in switch statement
          if ($Item -eq 'MlExclusion') {
            $PropList += 'excluded_from'
          } elseif ($Item -eq 'PreventionPolicy') {
            $PropList = $PropList.Replace('settings','prevention_settings') + 'ioa_rule_groups'
          }
          @($i.PSObject.Properties.Name).foreach{
            # Remove properties not required for comparison
            if ($PropList -notcontains $_) { $i.PSObject.Properties.Remove($_) }
          }
          if ($i.customer_id) {
            # Rename 'customer_id' to 'cid'
            Set-Property $i cid $i.customer_id
            $i.PSObject.Properties.Remove('customer_id')
          }
          @('groups','ioa_rule_groups').foreach{
            # Reduce to an array of identifiers and names
            if ($i.$_) { Set-Property $i $_ @($i.$_ | Select-Object id,name) }
          }
          if ($Item -match '^FileVantage') {
            @('host_groups','policy_assignments','rule_groups').foreach{
              # Reduce to an array of identifiers
              if ($i.$_) { Set-Property $i $_ @($i.$_.id) }
            }
          } elseif ($Item -eq 'FirewallRule' -and $i.rule_group) {
            # Reduce 'rule_group' to identifier, name and platform
            Set-Property $i rule_group ($i.rule_group | Select-Object id,name,platform)
          } elseif ($Item -eq 'FirewallPolicy' -and $i.settings) {
            @('created_by','created_on','modified_by','modified_on').foreach{
              # Strip unnecessary timestamps from 'settings'
              $i.settings.PSObject.Properties.Remove($_)
            }
          } elseif ($Item -eq 'IoaGroup' -and $i.rules) {
            # Compress 'rules'
            Set-Property $i rules @(Compress-Object $i.rules IoaRule)
          } elseif ($Item -eq 'IoaRule' -and $i.field_values) {
            # Reduce 'field_values' to name, label, type and values for IoaRule
            Set-Property $i field_values @($i.field_values | Select-Object name,label,type,values)
          } elseif ($Item -match '^(Ml|Sv)Exclusion$') {
            # Force 'false' for 'is_descendant_process'
            if ([string]::IsNullOrEmpty($i.is_descendant_process)) { Set-Property $i is_descendant_process $false }
          } elseif ($Item -eq 'PreventionPolicy' -and $i.prevention_settings.settings) {
            # Migrate 'settings' from 'prevention_settings' as an array of identifiers and values
            Set-Property $i settings @($i.prevention_settings.settings | Select-Object id,value)
            $i.PSObject.Properties.Remove('prevention_settings')
          } elseif ($Item -eq 'ResponsePolicy' -and $i.settings.settings) {
            # Migrate 'settings' from 'settings' as an array of identifiers and values
            Set-Property $i settings @($i.settings.settings | Select-Object id,value)
          }
          $i
        } else {
          # Return unexpected items unmodified
          $i
        }
      }
    }
    function Confirm-InputValue {
      foreach ($i in @('Default','Existing')) {
        if ($UserDict -and $UserDict.ContainsKey("Modify$i")) {
          # Update 'All' to valid values for 'ModifyDefault' and 'ModifyExisting', or values in 'Select'
          $Output = [System.Collections.Generic.List[string]]@()
          if ($UserDict."Modify$i" -contains 'All' -and $UserDict."Valid$i") {
            if ($UserDict.ContainsKey('Select')) {
              @($UserDict."Valid$i").Where({$UserDict.Select -contains $_}).foreach{ $Output.Add($_) }
            } else {
              @($UserDict."Valid$i").foreach{ $Output.Add($_) }
            }
          } elseif ($UserDict.ContainsKey('Select')) {
            @($UserDict."Modify$i").Where({$UserDict.Select -contains $_}).foreach{ $Output.Add($_) }
          } else {
            @($UserDict."Modify$i").foreach{ $Output.Add($_) }
          }
          $UserDict["Modify$i"] = $Output
        }
      }
      if ($UserDict -and $UserDict.ContainsKey('Select')) {
        # Add dependent values to Select for evaluation (not creation/modification)
        if ($UserDict.AssignExisting) {
          # When AssignExisting is present
          if ($UserDict.Select -match '^(Ioa|Ml|Sv)Exclusion$|Policy$' -and $UserDict.Select -notcontains
          'HostGroup') {
            # HostGroup when importing exclusions or policy
            $UserDict.Select += 'HostGroup'
          }
          if ($UserDict.Select -contains 'PreventionPolicy' -and $UserDict.Select -notcontains 'IoaGroup') {
            # IoaGroup with PreventionPolicy
            $UserDict.Select += 'IoaGroup'
          }
          if ($UserDict.Select -contains 'FileVantagePolicy' -and $UserDict.Select -notcontains
          'FileVantageRuleGroup') {
            # FileVantageRuleGroup with FileVantagePolicy
            $UserDict.Select += 'FileVantageRuleGroup'
          }
          if ($UserDict.Select -contains 'FirewallPolicy' -and $UserDict.Select -notcontains 'FirewallGroup') {
            # FirewallGroup with FirewallPolicy
            $UserDict.Select += 'FirewallGroup'
          }
        }
        if ($UserDict.Select -contains 'FileVantageRuleGroup' -and $UserDict.Select -notcontains
        'FileVantageRule') {
          # FileVantageRule with FileVantageRuleGroup
          $UserDict.Select += 'FileVantageRule'
        }
        if ($UserDict.Select -contains 'FirewallGroup' -and $UserDict.Select -notcontains 'FirewallRule') {
          # FirewallRule with FirewallGroup
          $UserDict.Select += 'FirewallRule'
        }
      }
      # Log and return updated input values
      $UserDict.GetEnumerator().Where({$_.Key -match '^(Modify(Default|Existing)|Select)$'}).foreach{
        Write-Log 'Confirm-InputValue' ("$($_.Key):"," $($_.Value -join ',')" -join "`n")
      }
    }
    function Edit-Item ([PSCustomObject]$Obj,[string]$Item,[string]$Comment) {
      if ($Obj) {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        $Ref = $Config.$Item.Cid | Where-Object -FilterScript (Write-SelectFilter $Obj $Item)
        if ($Ref -and $Item -eq 'FileVantageRuleGroup') {
          foreach ($Ar in $Obj.assigned_rules) {
            # Get matching rule from target CID
            $RefAr = $Ref.assigned_rules | Where-Object -FilterScript (Write-SelectFilter $Ar FileVantageRule)
            if ($RefAr) {
              # Evaluate and each FileVantageRule
              [string[]]$PropList = @($Ar.PSObject.Properties.Name).Where({$_ -notmatch
              '^(id|rule_group_id|type)$'}).foreach{
                if (!$RefAr.$_ -or $RefAr.$_ -ne $Ar.$_) {
                  if ($_ -notmatch '^content_(files|registry_values)$' -or ($_ -match
                  '^content_(files|registry_values)$' -and ![string]::IsNullOrWhiteSpace($RefAr.$_) -or
                  ![string]::IsNullOrWhiteSpace($Ar.$_))) {
                    $_
                  }
                }
              }
              if ($PropList) {
                # Modify FileVantageRule
                @('id','rule_group_id').foreach{
                  # Update identifiers
                  Write-Log 'Edit-Item' ((('FileVantageRule',$_ -join '.') -join ': '),([PSCustomObject]@{
                    old=$Ar.$_;new=$RefAr.$_} | Format-List | Out-String).Trim() -join "`n")
                  Set-Property $Ar $_ $RefAr.$_
                }
                #$Req = $Ar | Edit-FalconFileVantageRule @Param
                if ($Req) {
                  # Capture individual modified property results
                  @($PropList).foreach{ Add-Result Modified $Req FileVantageRule $_ $Ref.$_ $Req.$_ }
                } elseif ($Fail) {
                  # Capture failure to modify exclusion
                  Add-Result Failed $Ar FileVantageRule -Comment $Fail.exception.message -Log 'to modify'
                }
              } else {
                # Capture ignored result
                Add-Result Ignored $Ar FileVantageRule -Comment Identical
              }
            } else {
              # Add rules that don't exist at the bottom of the existing FileVantageRuleGroup
              $Precedence = $Ref.assigned_rules.precedence[-1]+1
              @('rule_group_id','precedence').foreach{
                Write-Log 'Edit-Item' (('FileVantageRule',$_ -join ': '),([PSCustomObject]@{old=$Ar.$_;new=if (
                  $_ -eq 'precedence') { $Precedence } else { $Ref.id }} | Format-List |
                  Out-String).Trim() -join "`n")
              }
              Set-Property $Ar rule_group_id $Ref.id
              Set-Property $Ar precedence $Precedence
              $Req = $Ar | New-FalconFileVantageRule @Param
              if ($Req) {
                # Capture individual modified property results
                @($PropList).foreach{ Add-Result Modified $Req FileVantageRule $_ $Ref.$_ $Req.$_ }
              } elseif ($Fail) {
                # Capture failure to modify exclusion
                Add-Result Failed $Ar FileVantageRule -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          }
        } elseif ($Ref -and $Item -eq 'FirewallGroup') {
          ## need to add FirewallRule evaluation
          #@('id','name','enabled','rule_ids').Where({$_ -ne 'id'}).foreach{
          #  [object]$Diff = if ($null -ne $Item.$_ -and $null -ne $Cid.$_) {
          #    # Compare properties that exist in both Modify and CID
          #    if ($p.Key -eq 'FirewallGroup' -and $_ -eq 'rule_ids') {
          #      if ($Item.rule_ids) {
          #       # Select FirewallRule from import using 'family' as 'id' value
          #       [object[]]$FwRule = foreach ($Rule in $Item.rule_ids) {
          #         $Config.FirewallRule.Import | Where-Object { $_.family -eq $Rule -and
          #           $_.deleted -eq $false }
          #       }
          #       if ($FwRule) {
          #         # Evaluate rules for modification
          #       }
          #      }
          #    }
          #  }
          #  # Output properties that differ, or are not present in CID
          #  if ($Diff -or ($null -ne $Item.$_ -and $null -eq $Cid.$_)) { $m.Add($_) }
          #}
          # Output items with properties to be modified and remove from Modify list
          #if ($m.Count -gt 1) { $Item | Select-Object $m }
        } elseif ($Ref -and $Item -eq 'IoaGroup') {
          foreach ($r in @($Obj.rules).Where({$_.deleted -eq $false})) {
            # Check for matching rule in target environment, excluding deleted IoaRule
            $RefR = @($Ref.rules).Where({$_.deleted -eq $false}) |
              Where-Object -FilterScript (Write-SelectFilter $r IoaRule)
            if ($RefR) {
              [hashtable[]]$PropTable = if ($RefR) {
                # Evaluate IoaRule properties for changes
                @('disposition_id','enabled','pattern_severity').foreach{
                  if (Compare-Object $r.$_ $RefR.$_) { @{ property = $_; old = $RefR.$_; new = $r.$_ } }
                }
                foreach ($Fv in $r.field_values) {
                  # Evaluate 'field_values' as a Json string for each value under 'values'
                  $RefFv = @($RefR.field_values).Where({$_.name.Equals($Fv.name) -and $_.type.Equals($Fv.type)})
                  if ($RefFv) {
                    $ModFv = $false
                    foreach ($v in $RefFv.values) {
                      if ($ModFv -eq $false) {
                        $Old = $v | Select-Object label,value | ConvertTo-Json -Compress
                        $New = @($Fv.values).Where({$_.label.Equals($v.label)}) | Select-Object label,value |
                          ConvertTo-Json -Compress
                        if (Compare-Object $Old $New) {
                          # Capture 'field_values' as a simple Json for result output
                          @{
                            property = 'field_values'
                            old = "{$('"label":"{0}","values":[{1}]' -f $RefFv.label,$Old)}"
                            new = "{$('"label":"{0}","values":[{1}]' -f $Fv.label,$New)}"
                          }
                          $ModFv = $true
                        }
                      }
                    }
                  }
                }
              }
              if ($PropTable) {
                # Copy existing rule and modify properties and modify IoaRule
                $c = $RefR.PSObject.Copy()
                Set-Property $c rulegroup_id $Ref.id
                $Comment = if ($c.comment) { $c.comment } else { ($Comment,'modify_rule' -join ' ') }
                @($PropTable.property).foreach{ Set-Property $c $_ $r.$_ }
                $Req = Edit-FalconIoaRule -RuleUpdate $c -RuleGroupId $Ref.id -Comment $Comment @Param
                if ($Req) {
                  @($PropTable).foreach{
                    # Splat 'old', 'new' and 'property' from Edit to capture result
                    Add-Result Modified $c IoaRule @_ -Comment ('rulegroup_id',$c.rulegroup_id -join ':')
                  }
                } elseif ($Fail) {
                  # Capture failure to modify IoaRule
                  Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to modify'
                }
              } else {
                # Add output with updated 'rulegroup_id' to match 'platform'
                Set-Property $r rulegroup_id $Ref.id
                Add-Result Ignored $r IoaRule -Comment Identical
              }
            } else {
              # Add rules that don't exist at the bottom of the existing IoaGroup
              $Comment = if ($r.comment) { $r.comment } else { ($Comment,'create_rule' -join ' ') }
              $c = $r.PSObject.Copy()
              Set-Property $c rulegroup_id $Ref.id
              $Req = $c | New-FalconIoaRule @Param
              if ($Req) {
                # Update with current 'instance_id', capture result
                Set-Property $c instance_id $Req.instance_id
                Add-Result Created $c IoaRule -Comment ('rulegroup_id',$c.rulegroup_id -join ':')
              } elseif ($Fail) {
                # Capture failure to add IoaRule
                Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to create'
              }
              if ($c.enabled -eq $true) {
                # Enable rule to match import, capture result
                $Req = Edit-FalconIoaRule -RuleUpdate $c -RuleGroupId $Ref.Id -Comment ($Comment,
                  'modify_rule' -join ' ') @Param
                if ($Req) {
                  Add-Result Modified $c IoaRule enabled $false $c.enabled -Comment ('rulegroup_id',
                    $c.rulegroup_id -join ':')
                } elseif ($Fail) {
                  # Capture failure to enable IoaRule
                  Add-Result Failed $c IoaRule -Comment $Fail.exception.message -Log 'to enable'
                }
              }
            }
          }
        } elseif ($Ref -and $Item -match '^(Ioa|Ml|Sv)Exclusion$') {
          # Verify 'applied_globally' and 'groups' values
          Update-Exclusion $Obj $Item $Config.HostGroup.Ref
          [string[]]$PropList = if ($Ref.is_descendant_process -ne $Obj.is_descendant_process) {
            'is_descendant_process'
          } elseif ($Ref.applied_globally -ne $Obj.applied_globally) {
            'applied_globally'
          } elseif ($Ref.applied_globally -eq $false -and (Compare-Object $Ref.groups.id $Obj.groups.id)) {
            # HostGroup identifiers don't match
            'groups'
          }
          if ($PropList -and $Obj.groups) {
            # Update identifier with value from CID and modify exclusion
            Write-Log 'Edit-Item' ($Item,([PSCustomObject]@{old=$Obj.id;new=$Ref.id} | Format-List |
              Out-String).Trim() -join "`n")
            Set-Property $Obj id $Ref.id
            $Req = $Obj | & "Edit-Falcon$Item" @Param
            if ($Req) {
              # Capture individual modified property results
              @($PropList).foreach{ Add-Result Modified $Req $Item $_ $Ref.$_ $Req.$_ }
            } elseif ($Fail) {
              # Capture failure to modify exclusion
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          } elseif (!$PropList) {
            # Add ignored result
            Add-Result Ignored $Obj $Item -Comment Identical
          }
        } elseif ($Ref -and $Item -eq 'Script') {
          # Check Script properties
          [string[]]$PropList = if ($Obj.permission_type -ne $Ref.permission_type) {
            'permission_type'
          } elseif ($Obj.sha256 -ne $Ref.sha256) {
            'content'
          }
          if ($PropList) {
            # Update identifier with value from CID and modify exclusion
            Set-Property $Obj id $Ref.id
            # Modify exclusion
            $Req = $Obj | Edit-FalconScript @Param
            if ($Req) {
              @($PropList).foreach{
                if ($_ -eq 'content') {
                  # Exclude 'old_value' and 'new_value' for 'content'
                  Add-Result Modified $Obj Script content -Comment 'Uploaded content'
                } else {
                  # Capture individual modified property results
                  Add-Result Modified $Obj Script $_ $Ref.$_ $Obj.$_
                }
              }
            } elseif ($Fail) {
              # Capture failure to modify script
              Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
            }
          } else {
            # Add ignored result
            Add-Result Ignored $Obj Script -Comment Identical
          }
        }
      }
    }
    function Edit-Policy ([PSCustomObject]$Obj,[string]$Item,[object]$Ref) {
      $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
      if ($Obj) {
        if ($Obj.id -ne $Ref.id) {
          # Update identifier to match reference policy
          Write-Log 'Edit-Policy' ($Item,([PSCustomObject]@{old=$Obj.id;new=$Ref.id} | Format-List |
            Out-String).Trim() -join "`n")
          Set-Property $Obj id $Ref.id
        }
        if ($Item -eq 'FirewallPolicy') {
          foreach ($i in $Obj.settings.rule_group_ids) {
            [object]$RefG = @($Config.FirewallGroup.Ref).Where({$_.old -eq $i})
            [string[]]$Obj.settings.rule_group_ids = if ($RefG) {
              # Update 'rule_group_ids' with new id values
              Write-Log 'Edit-Policy' (($Item,'rule_group_ids' -join ': '),([PSCustomObject]@{old=$i;
                new=$RefG.new} | Format-List | Out-String).Trim() -join "`n")
              $Obj.settings.rule_group_ids -replace $i,$RefG.new
            } else {
              # Remove unmatched 'rule_group_ids' values
              Write-Log 'Edit-Policy' ('Removed unmatched FirewallGroup "{0}" from {1} "{2}"' -f $i,$Item,$Obj.id)
              $Obj.settings.rule_group_ids -replace $i,$null
            }
          }
          
          if (!$Obj.settings.rule_group_ids) {
            # Remove empty 'rule_group_ids' value and determine if 'settings' has different values
            [void]$Obj.settings.PSObject.Properties.Remove('rule_group_ids')
            Write-Log 'Edit-Policy' ('Removed empty "rule_group_ids" from {0} "{1}"' -f $Item,$Obj.id)
          }
        } elseif ($Item -eq 'FileVantagePolicy') {
          if ($Obj.exclusions) {
            foreach ($e in $Obj.exclusions) {
              # Check for existing matching exclusion
              $RefE = @($Ref.exclusions).Where({$_.name -eq $e.name})
              # Remove 'repeated' from imported exclusion when empty to prevent submission error
              if ($null -eq $e.repeated.PSObject.Properties.Name) { $e.PSObject.Properties.Remove('repeated') }
              if ($RefE) {
                [string[]]$Edit = @($e.PSObject.Properties.Name).Where({$_ -notmatch
                '^((policy_)?id|\w+_timestamp)$'}).foreach{
                  # Compare existing exclusion against import to find new or modified properties
                  if ($_ -eq 'repeated') {
                    foreach ($i in $e.repeated.PSObject.Properties.Name) {
                      # Check each sub-property under 'repeated'
                      if (!$RefE.repeated.$i -or $RefE.repeated.$i -ne $e.repeated.$i) { 'repeated' }
                    }
                  } elseif (!$RefE.$_ -or $e.$_ -ne $RefE.$_) {
                    $_
                  }
                } | Select-Object -Unique
                if ($Edit) {
                  @('id','policy_id').foreach{
                    # Update identifiers
                    Write-Log 'Edit-Policy' (('FileVantageExclusion',$_ -join ': '),([PSCustomObject]@{old=$e.id;
                      new=$RefE.$_} | Format-List | Out-String).Trim() -join "`n")
                    Set-Property $e $_ $RefE.$_
                  }
                  # Modify FileVantageExclusion
                  $Req = $e | Edit-FalconFileVantageExclusion @Param
                  if ($Req) {
                    @($Edit).foreach{
                      if ($_ -eq 'repeated') {
                        # Convert 'repeated' to a string and capture result
                        Add-Result Modified $Req FileVantageExclusion $_ ($RefE.$_ | Format-List |
                          Out-String).Trim() ($Req.$_ | Format-List | Out-String).Trim()
                      } else {
                        # Capture result
                        Add-Result Modified $Req FileVantageExclusion $_ $RefE.$_ $Req.$_
                      }
                    }
                  } elseif ($Fail) {
                    # Capture failure to modify FileVantageExclusion
                    Add-Result Failed $e FileVantageExclusion -Comment $Fail.exception.message -Log 'to modify'
                  }
                }
              } else {
                # Create FileVantageExclusion
                Write-Log 'Edit-Policy' (('FileVantageExclusion','policy_id' -join ': '),([PSCustomObject]@{
                  old=$e.id;new=$Obj.id} | Format-List | Out-String).Trim() -join "`n")
                Set-Property $e policy_id $Obj.id
                $Req = $e | New-FalconFileVantageExclusion @Param
                if ($Req) {
                  # Capture result
                  Add-Result Created $Req FileVantageExclusion
                } elseif ($Fail) {
                  # Capture failure to create FileVantageExclusion
                  Add-Result Failed $e FileVantageExclusion -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
        }
        if ($Obj.settings) {
          if ($Item -eq 'DeviceControlPolicy') {
            $Edit = Compare-Setting $Obj $Ref $Item
            if ($Edit.classes.exceptions) {
              for ($i=0;$i -lt ($Edit.classes.exceptions | Measure-Object).Count;$i+=50) {
                # Add exceptions in groups of 50
                $Clone = $Edit.PSObject.Copy()
                $Group = @($Edit.classes.exceptions)[$i..($i+49)]
                foreach ($Class in $Group.class) {
                  @($Clone.classes).Where({$_.id -eq $Class}).foreach{
                    $_.exceptions = @($Group).Where({$_.class -eq $Class})
                  }
                }
                $Req = & "Edit-Falcon$Item" -Id $Obj.id -Setting $Clone @Param
                if ($Req) {
                  # Capture each modified property
                  Compare-Setting (Compress-Object $Req $Item) $Ref $Item -Result
                } elseif ($Fail) {
                  # Capture failure to modify Policy
                  Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
                }
              }
            } elseif ($Edit) {
              # Modify DeviceControlPolicy class 'action' and capture result
              $Req = & "Edit-Falcon$Item" -Id $Obj.id -Setting $Edit @Param
              if ($Req) {
                # Capture each modified property
                Compare-Setting (Compress-Object $Req $Item) $Ref $Item -Result
              } elseif ($Fail) {
                # Capture failure to modify Policy
                Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          } elseif ($Item -eq 'FirewallPolicy') {
            $Obj.settings = Compare-Setting $Obj $Ref $Item
            if ($Obj.settings) {
              # Update 'policy_id' under 'settings' with 'id' and modify 'settings'
              if ($Obj -and $Obj.settings.policy_id) {
                Write-Log 'Edit-Policy' (($Item,'policy_id' -join ': '),([PSCustomObject]@{
                  old=$Obj.settings.policy_id;new=$Obj.id} | Format-List | Out-String).Trim() -join "`n")
                Set-Property $Obj.settings policy_id $Obj.id
              }
              $Req = $Obj.settings | Edit-FalconFirewallSetting @Param
              if ($Req) {
                # Capture FirewallSetting result
                Compare-Setting $Obj $Ref $Item -Result
              } elseif ($Fail) {
                # Capture failure to modify FirewallPolicy
                Add-Result Failed $Obj FirewallPolicy -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          } else {
            $Edit = Compare-Setting $Obj $Ref $Item
            if ($Edit) {
              # Modify Policy and capture result
              $Req = & "Edit-Falcon$Item" -Id $Obj.id -Setting $Edit @Param
              if ($Req) {
                # Capture each modified property
                Compare-Setting (Compress-Object $Req $Item) $Ref $Item -Result
              } elseif ($Fail) {
                # Capture failure to modify Policy
                Add-Result Failed $Obj $Item -Comment $Fail.exception.message -Log 'to modify'
              }
            }
          }
        }
        if ($Item -eq 'PreventionPolicy') {
          if ($Obj.ioa_rule_groups) {
            # Update IoaGroup identifiers and assign to PreventionPolicy
            $Obj.ioa_rule_groups = Update-GroupId $Obj.ioa_rule_groups $Item ioa_rule_groups
            if ($Obj.ioa_rule_groups) { Submit-Group $Item ioa_rule_groups $Obj $Ref }
          } elseif ($Obj.name -match $PolicyDefault) {
            # Record that no changes were made for default policy when ioa_rule_groups are not present
            Add-Result Ignored $Obj $Item -Comment Identical
          }
        }
        if ($Item -eq 'FileVantagePolicy') {
          # Update identifiers and assign FileVantageRuleGroup and HostGroup to FileVantagePolicy
          @('rule_groups','host_groups').foreach{
            $Obj.$_ = Update-GroupId $Obj.$_ $Item $_
            if ($Obj.$_) { Submit-Group $Item $_ $Obj $Ref }
          }
        } elseif ($Obj.groups -and $Obj.name -notmatch $PolicyDefault) {
          # Assign HostGroup to non-default policy
          $Obj.groups = Update-GroupId $Obj.groups $Item groups
          if ($Obj.groups) { Submit-Group $Item groups $Obj $Ref }
        }
        if ($Obj.name -notmatch $PolicyDefault -and $Ref.enabled -ne $Obj.enabled) {
          # Enable or disable non-default policy
          [string]$Action = if ($Obj.enabled -eq $true) { 'enable' } else { 'disable' }
          Invoke-PolicyAction $Item $Action $Obj -Ref $Ref
        }
      }
    }
    function Find-Import {
      # Filter Import list and create Modify list
      foreach ($p in $Config.GetEnumerator().Where({$_.Key -notmatch $NoEnum -and $_.Value.Import})) {
        $Import = [System.Collections.Generic.List[PSCustomObject]]@()
        $Modify = [System.Collections.Generic.List[PSCustomObject]]@()
        foreach ($i in $p.Value.Import) {
          if ($i.deleted -eq $true) {
            # Ignore 'deleted' items
            Add-Result Ignored $i $p.Key -Comment Deleted
          } else {
            [string]$Platform = switch ($i) {
              # Check for platform value for log message
              { $_.platform } { $i.platform -join ',' }
              { $_.platforms} { $i.platforms -join ',' }
              { $_.platform_name } { $i.platform_name }
            }
            # Determine if matching item exists in target CID
            $Ref = if ($p.Value.Cid) { $p.Value.Cid | Where-Object -FilterScript (Write-SelectFilter $i $p.Key) }
            if ($Ref) {
              [string]$Comment = if ($p.Key -match 'Policy$' -and $i.name -match $PolicyDefault) {
                if ($UserDict.ValidDefault -notcontains $p.Key) {
                  # Ignore default policies that can't be modified
                  'Unmodifiable'
                } elseif (($UserDict.ModifyDefault -and $UserDict.ModifyDefault -notcontains $p.Key) -or
                !$UserDict.ModifyDefault) {
                  # Ignore default policies not specified under 'ModifyDefault'
                  'Not ModifyDefault'
                }
              } else {
                if ($UserDict.ValidExisting -notcontains $p.Key) {
                  # Ignore existing items that can't be modified
                  'Unmodifiable'
                } elseif (($UserDict.ModifyExisting -and $UserDict.ModifyExisting -notcontains $p.Key) -or
                !$UserDict.ModifyExisting) {
                  # Ignore items not specified under 'ModifyExisting'
                  'Not ModifyExisting'
                }
              }
              if ($Comment) {
                # Remove existing items from Import unless comment is specified
                Add-Result Ignored $i $p.Key -Comment $Comment
              } else {
                # Add existing items to Modify to analyze for modification
                $Modify.Add($i.PSObject.Copy())
                $Log = if ($Platform) {
                  'Modify: {0} {1} "{2}"' -f $p.Key,$Platform,$i.id
                } else {
                  'Modify: {0} "{1}"' -f $p.Key,$i.id
                }
                Write-Log 'Update-Config' $Log
              }
            } else {
              # Keep non-existent items under Import and add policies to Modify for changes post-creation
              if ($p.Key -match 'Policy$') { $Modify.Add($i.PSObject.Copy()) }
              $Name = Select-ObjectName $i $p.Key
              $Log = if ($Platform) {
                'Import: {0} {1} "{2}"' -f $p.Key,$Platform,$Name
              } else {
                'Import: {0} "{1}"' -f $p.Key,$Name
              }
              Write-Log 'Update-Config' $Log
              $Import.Add($i)
            }
          }
        }
        if ($Modify) {
          if ($p.Key -eq 'DeviceControlPolicy') {
            # Add DeviceControlPolicy exceptions under class in Modify list when not present in target CID
            foreach ($i in $Modify) {
              foreach ($c in $i.settings.classes) {
                [System.Collections.Generic.List[PSCustomObject]]$c.exceptions = @()
                foreach ($e in @($p.Value.ExImp).Where({$_.policy_id -eq $i.id -and $_.class -eq $c.id})) {
                  $Filter = Write-SelectFilter $e DeviceControlException
                  if ($Filter) {
                    if (!($p.Value.ExCid | Where-Object -FilterScript $Filter)) {
                      # Exclude 'id' and 'policy_id' from exception when adding to class
                      $c.exceptions.Add(($e | Select-Object @($e.PSObject.Properties.Name).Where({
                        $_ -notmatch '^(id|policy_id)$'})))
                    } else {
                      # Capture result for ignored DeviceControlPolicy exceptions
                      Add-Result Ignored $i $p.Key ($c.id,'exceptions' -join '.') -Comment ($e.match_method,((
                        @(Select-ObjectName $e DeviceControlException).foreach{ $e.$_ }) -join '_') -join ':')
                    }
                  }
                }
              }
            }
          }
          # Capture list of items to be modified
          $p.Value['Modify'] = $Modify
        }
        $p.Value['Import'] = $Import
      }
    }
    function Get-CurrentBuild ([string]$String,[string]$Platform) {
      if ($String -match '\|') {
        # Match by sensor build tag, replacing suffix with wildcard for cloud disparities
        if ($String -match '^n\|tagged\|\d{1,}$') { $String = $String -replace '\d{1,}$','*' }
        @($Config.SensorUpdatePolicy.Build).Where({$_.platform -eq $Platform -and $_.build -like "*|$String"}) |
          Select-Object build,sensor_version
      } elseif ($String) {
        # Check for exact sensor build version match
        @($Config.SensorUpdatePolicy.Build).Where({$_.platform -eq $Platform -and $_.build -eq $String}) |
          Select-Object build,sensor_version,stage
      } else {
        $null
      }
    }
    function Get-DcException ([PSCustomObject[]]$Obj) {
      foreach ($i in $Obj) {
        # Generate list of exceptions from a DeviceControlPolicy
        @($i.settings.classes.exceptions).foreach{
          [PSCustomObject]$_ | Select-Object @{l='policy_id';e={$i.id}},id,class,vendor_id,vendor_id_decimal,
          vendor_name,product_id,product_id_decimal,product_name,serial_number,combined_id,action,match_method,
          description
        }
      }
    }
    function Get-FromCid {
      # Retrieve items from CID
      foreach ($p in $Config.GetEnumerator().Where({$_.Value.Import})) {
        $Cid = [System.Collections.Generic.List[PSCustomObject]]@()
        $Param = @{ Detailed = $true; All = $true; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        if ($p.Key -eq 'FileVantagePolicy') {
          # Include exclusions when present in import
          if ($p.Value.exclusions) { $Param['Include'] = 'exclusions' }
          @($p.Value.Import.platform | Select-Object -Unique).foreach{
            # Retrieve FileVantagePolicy from target CID by 'platform'
            Write-Host ('[Import-FalconConfig] Retrieving {0} {1}...' -f $_,$p.Key)
            $RefP = & "Get-Falcon$($p.Key)" -Type $_ @Param
            if ($RefP) {
              # Return relevant properties for FileVantagePolicy, excluding default policies
              @(Compress-Object @($RefP).Where({$_.created_by -ne 'cs-cloud-provisioning' -and $_.name -notmatch
              $PolicyDefault}) $p.Key).foreach{
                $Cid.Add($_)
              }
            } elseif ($Fail) {
              # Notify of failure to retrieve from CID and remove
              Add-Result Failed -Type $p.Key -Log 'to retrieve'
            }
          }
        } elseif ($p.Key -eq 'FileVantageRuleGroup') {
          # Retrieve FileVantageRuleGroup from target CID by 'type' when present in Import
          @($p.Value.Import.type | Select-Object -Unique).foreach{
            Write-Host ('[Import-FalconConfig] Retrieving {0} {1}...' -f $_,$p.Key)
            $RefG = & "Get-Falcon$($p.Key)" -Type $_ @Param
            if ($RefG) {
              $CidG = foreach ($i in @($RefG).Where({$_.created_by -ne 'internal'})) {
                # Exclude FileVantageRuleGroup templates
                if ($i.assigned_rules.id -and @($p.Value.Import).Where({$_.type.Equals($i.type) -and
                $_.name.Equals($i.name)})) {
                  $CidR = @($i.assigned_rules.id).Where({![string]::IsNullOrWhiteSpace($_)})
                  if ($CidR) {
                    # Append rule content for matching imported FileVantageRuleGroup to 'assigned_rules'
                    Write-Host (
                      '[Import-FalconConfig] Retrieving FileVantageRule for {0} group "{1}"...' -f $i.type,$i.name)
                    Set-Property $i assigned_rules (Get-FalconFileVantageRule -RuleGroupId $i.id -Id $CidR)
                  }
                }
                $i
              }
              if ($CidG) { @(Compress-Object $CidG $p.Key).foreach{ $Cid.Add($_) } }
            } elseif ($Fail) {
              # Notify of failure to retrieve from CID and remove
              Add-Result Failed -Type $p.Key -Log 'to retrieve'
            }
          }
        } else {
          # Retrieve items from target CID
          Write-Host ('[Import-FalconConfig] Retrieving {0}...' -f $p.Key)
          $Ref = if ($p.Key -eq 'FirewallPolicy') {
            Get-FalconFirewallPolicy -Include settings @Param
          } else {
            & "Get-Falcon$($p.Key)" @Param
          }
          if ($Ref) {
            if ($p.Key -eq 'DeviceControlPolicy') {
              $p.Value['ExCid'] = [System.Collections.Generic.List[PSCustomObject]]@()
              @(Compress-Object $Ref $p.Key).foreach{
                # Copy exceptions from policy to ExCid list for analysis and add to Cid
                @(Get-DcException $_).foreach{ $p.Value.ExCid.Add($_) }
                $Cid.Add($_)
              }
            } else {
              # Remove unnecessary properties and add to CID list
              @(Compress-Object $Ref $p.Key).foreach{ $Cid.Add($_) }
            }
          } elseif ($Fail) {
            # Notify of failure to retrieve
            Add-Result Failed -Type $p.Key -Log 'to retrieve'
          }
        }
        if ($Cid) {
          # Update identifier references
          Set-IdRef $Cid $p.Key -Update
          # Update HostGroup with values from CID
          if ($Cid.groups) { Set-IdRef $Cid.groups HostGroup -Update }
          if ($p.Key -eq 'PreventionPolicy' -and $Cid.ioa_rule_groups) {
            # Update IoaGroup with values from CID
            Set-IdRef $Cid.ioa_rule_groups IoaGroup -Update
          }
        }
        $p.Value['Cid'] = $Cid
      }
    }
    function Import-ConfigJson ([string]$String,[string[]]$List) {
      $Output = @{}
      try {
        # Define valid files for import using Export-FalconConfig
        [string[]]$Valid = try {
          @((Get-Command Export-FalconConfig).Parameters.Select.Attributes.ValidValues + 'FirewallRule')
        } catch {
          throw 'Failed to retrieve valid import file types from "Export-FalconConfig" command!'
        }
        # Load Json files from archive
        $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
          Get-Content $String -AsByteStream
        } else {
          Get-Content $String -Encoding Byte -Raw
        }
        [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression') | Out-Null
        $FileStream = New-Object System.IO.MemoryStream
        $FileStream.Write($ByteStream,0,$ByteStream.Length)
        $ZipArchive = New-Object System.IO.Compression.ZipArchive($FileStream)
        foreach ($FullName in $ZipArchive.Entries.FullName) {
          # Convert Json and add to hashtable output
          $Filename = $ZipArchive.GetEntry($FullName)
          $Item = ($FullName | Split-Path -Leaf).Split('.')[0]
          if ($Valid -contains $Item) {
            if (!$List -or ($List -and $List -contains $Item)) {
              # Filter to selected items when list is provided
              $Json = ConvertFrom-Json -InputObject (
                New-Object System.IO.StreamReader($Filename.Open())).ReadToEnd()
              if ($Json) {
                # Add required properties from Json as Import
                $Output[$Item] = @{
                  Import = [System.Collections.Generic.List[PSCustomObject]]@(Compress-Object $Json $Item)
                }
                if ($Item -eq 'DeviceControlPolicy') {
                  # Create list for imported DeviceControlPolicy exceptions and remove from imports
                  $Output.$Item['ExImp'] = [System.Collections.Generic.List[PSCustomObject]]@(
                    Get-DcException $Output.$Item.Import)
                  @($Output.$Item.Import.settings.classes).foreach{ $_.exceptions = @() }
                }
                Write-Host ('[Import-FalconConfig] Successfully imported "{0}".' -f $Item)
              }
            } else {
              Write-Log 'Import-ConfigJson' ('Ignored "{0}"' -f $Filename)
            }
          } else {
            Write-Log 'Import-ConfigJson' ('Unexpected "{0}" ignored' -f $Filename)
          }
        }
        if ($FileStream) { $FileStream.Dispose() }
      } catch {
        Write-Host ('[Import-FalconConfig] Failed to import "{0}"!' -f $String)
        throw $_
      }
      if ($Output.Count) { $Output }
    }
    function Invoke-PolicyAction ([string]$Item,[string]$Action,[object]$Obj,[string]$Id,[object]$Ref) {
      # Perform an action on a policy and output result
      $Param = @{ Name = $Action; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
      if ($Id) { $Param['GroupId'] = $Id }
      if ($Obj.id) {
        $Req = if ($Item -eq 'FileVantagePolicy') {
          $Obj | Edit-FalconFileVantagePolicy @Param
        } else {
          $Obj.id | & "Invoke-Falcon$($Item)Action" @Param
        }
        if ($Action -match '^add-(host|rule)-group$') {
          if ($Req) {
            # Return to Submit-Group to capture result
            $Req
          } elseif ($Fail) {
            # Capture group assignment failure ## need to expand?
            Add-Result Failed $null HostGroup -Log 'to assign'
          }
        } elseif ($Action -match '^(enable|disable)$') {
          if ($Req.id) {
            # Capture enable result
            Add-Result Modified $Req $Item enabled $Ref.enabled $Obj.enabled
          } elseif ($Req) {
            # Capture enable result
            Add-Result Modified $Obj $Item enabled $Ref.enabled $Obj.enabled
          } elseif ($Fail) {
            # Capture enable failure
            Add-Result Failed $Req $Item enabled $Ref.enabled $Obj.enabled -Log 'to modify'
          }
        }
      }
    }
    function New-Group ([string]$Item,[string]$Comment) {
      if ($Config.$Item.Import) {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        Write-Host ('[Import-FalconConfig] Creating {0}...' -f $Item)
        if ($Item -eq 'HostGroup') {
          # Create HostGroup
          for ($i=0; $i -lt $Config.$Item.Import.Count; $i+=10) {
            [PSCustomObject[]]$g = @($Config.$Item.Import)[$i..($i+9)]
            $Req = $g | New-FalconHostGroup @Param
            if ($Req) {
              @($Req).foreach{
                # Update identifier reference, capture result
                Set-IdRef $_ $Item -Update
                Add-Result Created $_ $Item
              }
            } elseif ($Fail) {
              # Capture failure result
              @($g).foreach{ Add-Result Failed $_ $Item -Comment $Fail.exception.message -Log 'to create' }
            }
          }
        } elseif ($Item -eq 'FileVantageRuleGroup') {
          foreach ($i in $Config.$Item.Import) {
            # Create FileVantageRuleGrop
            $Req = $i | New-FalconFileVantageRuleGroup @Param
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req.id
              Set-IdRef $Req $Item -Update
              Add-Result Created $Req $Item
            } elseif ($Fail) {
              # Capture creation failure
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
            }
            if ($i.assigned_rules) {
              foreach ($ar in $i.assigned_rules) {
                # Update identifier and create FileVantageRule
                Set-Property $ar rule_group_id $i.id
                $Req = $ar | New-FalconFileVantageRule @Param
                if ($Req) {
                  # Capture FileVantageRule result
                  Add-Result Created $Req FileVantageRule
                } elseif ($Fail) {
                  # Capture FileVantageRule creation failure
                  Add-Result Failed $ar FileVantageRule -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
        } elseif ($Item -eq 'FirewallGroup') {
          foreach ($i in $Config.$Item.Import) {
            if ($i.rule_ids) {
              [object[]]$Rule = foreach ($r in $i.rule_ids) {
                # Select each FirewallRule from import using 'family' as 'id' value (excluding 'deleted')
                @($Config.FirewallRule.Import).Where({$_.family -eq $r -and $_.deleted -eq $false}).foreach{
                  # Trim rule names to 64 characters to meet API restriction
                  if ($_.name.Length -gt 64) { $_.name = ($_.name).SubString(0,63) }
                  $_
                }
              }
              if ($Rule) {
                # Use collection of rules as 'Rule' and remove 'rule_ids'
                [void]$i.PSObject.Properties.Remove('rule_ids')
                Set-Property $i rules $Rule
                Write-Log 'New-Group' ('Selected {0} rules for {1} "{2}".' -f ($Rule | Measure-Object).Count,
                  $Item,(Select-ObjectName $i $Item))
              }
            }
            # Create FirewallGroup
            $Req = $i | New-FalconFirewallGroup @Param
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req
              Set-IdRef $i $Item -Update
              Add-Result Created $i $Item
              if ($Rule) {
                @($Rule).foreach{
                  # Update identifier for FirewallRule, capture result
                  $_.rule_group.id = $i.id
                  Add-Result Created $_ FirewallRule
                }
              }
            } elseif ($Fail) {
              # Capture FirewallGroup creation failure
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
              if ($Rule) {
                @($Rule).foreach{
                  # Capture FirewallRule creation failure
                  Add-Result Failed $_ FirewallRule -Comment $Fail.exception.message -Log 'to create'
                }
              }
            }
          }
          Clear-ConfigList FirewallRule Import
        } elseif ($Item -eq 'IoaGroup') {
          foreach ($i in $Config.$Item.Import) {
            # Create IoaGroup
            $Req = $i | New-FalconIoaGroup @Param
            if ($Req) {
              # Update identifier and reference, capture result
              Set-Property $i id $Req.id
              Set-IdRef $Req $Item -Update
              Add-Result Created $Req $Item
              if ($i.rules) {
                [string]$ArComment = ('rulegroup_id',$i.id -join ':')
                [object[]]$i.rules = foreach ($r in $i.rules) {
                  # Update IoaGroup identifier and append comment when not present
                  Set-Property $r rulegroup_id $Req.id
                  if (!$r.comment) { Set-Property $r comment ($Comment,'create_rule' -join ' ') }
                  # Create IoaRule inside IoaGroup
                  $Rule = $r | New-FalconIoaRule @Param
                  if ($Rule) {
                    # Add to output and set 'enable' status using imported IoaRule
                    Add-Result Created $Rule IoaRule -Comment $ArComment
                    if ($r.enabled -eq $true) { Set-Property $Rule enabled $r.enabled }
                    $Rule
                  } elseif ($Fail) {
                    # Capture IoaRule creation failure
                    Add-Result Failed $i IoaRule -Comment $Fail.exception.message -Log 'to create'
                  }
                }
                if ($i.rules.enabled -eq $true) {
                  # Enable IoaRule
                  if (!$i.comment) { Set-Property $i comment ($Comment,'enable_group' -join ' ') }
                  $EnR = $i | Edit-FalconIoaRule @Param
                  if ($EnR) {
                    @($EnR.rules).Where({$_.enabled -eq $true}).foreach{
                      # Capture IoaRule enable result
                      Add-Result Modified $_ IoaRule enabled $false $_.enabled -Comment $ArComment
                    }
                  } elseif ($Fail) {
                    # Capture IoaRule enable failure
                    Add-Result Failed $i IoaRule -Comment $Fail.exception.message -Log 'to enable'
                  }
                }
                if ($i.enabled -eq $true) {
                  # Enable IoaGroup
                  $EnG = Edit-FalconIoaGroup -Id $Req.id -Enabled $true @Param
                  if ($EnG) {
                    # Capture IoaGroup enable result
                    Add-Result Modified $Req $Item enabled $Req.enabled $EnG.enabled
                  } elseif ($Fail) {
                    # Capture IoaGroup enable failure
                    Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to enable'
                  }
                }
              }
            } elseif ($Fail) {
              # Capture creation failure for IoaGroup
              Add-Result Failed $i $Item -Comment $Fail.exception.message -Log 'to create'
            }
          }
        }
      }
    }
    function Select-ObjectName ([PSCustomObject]$Obj,[string]$Item) {
      # Select a name to display in results and verbose output
      if ($Item -eq 'DeviceControlException') {
        switch ($Obj.match_method) {
          # Output DeviceControlPolicy exceptions properties for filtering or logging names
          'COMBINED_ID' { 'combined_id' }
          'VID' { 'vendor_id_decimal' }
          'VID_PID' { 'vendor_id_decimal','product_id_decimal' }
          'VID_PID_SERIAL' { 'vendor_id_decimal','product_id_decimal','serial_number' }
        }
      } elseif ($Obj.value) {
        if ($Obj.type) { $Obj.type,$Obj.value -join ':' } else { $Obj.value }
      } elseif ($Obj.precedence -and $Item -eq 'FileVantageRule') {
        $Obj.precedence
      } else {
        $Obj.name
      }
    }
    function Set-IdRef ([PSCustomObject[]]$Obj,[string]$Item,[switch]$Update) {
      if ($Item -notmatch $NoEnum) {
        if ($Update) {
          foreach ($i in $Obj) {
            # Check for matching reference using selected properties and filter out matching 'new' identifier
            [string]$Id = if ($i.family) { $i.family } else { $i.id }
            $Filter = Write-SelectFilter $i $Item -Ref
            if ($Filter) {
              $Ref = $Config.$Item.Ref | Where-Object -FilterScript $Filter | Where-Object new -ne $Id
              if ($Ref) {
                # Set 'new' identifier
                Set-Property $Ref new $Id
                Write-Log 'Set-IdRef' ($Item,($Ref | Format-List | Out-String).Trim() -join "`n")
              }
            }
          }
        } else {
          # Create sub-key for $Item when not present
          if ($Config.ContainsKey($Item) -eq $false) { $Config[$Item] = @{} }
          if ($Config.$Item.ContainsKey('Ref') -eq $false) {
            # Create empty identifier reference list when not present
            $Config.$Item['Ref'] = [System.Collections.Generic.List[PSCustomObject]]@()
          }
          foreach ($i in $Obj) {
            [string]$Id = if ($i.family) { $i.family } else { $i.id }
            if ($Id -and !@($Config.$Item.Ref).Where({$_.old.Equals($Id)})) {
              # Create new identifier reference
              $Ref = [PSCustomObject]@{ old = $Id; new = '' }
              @('name','os','type','value').foreach{
                # Capture listed properties
                if ($_ -eq 'os') {
                  # Convert 'platforms', 'platform_name', and 'platform' to 'os'
                  [string[]]$Value = if ($i.platforms) {
                    $i.platforms
                  } elseif ($i.platform_name) {
                    $i.platform_name
                  } elseif ($i.platform) {
                    $i.platform
                  }
                  if ($Value) { Set-Property $Ref $_ $Value }
                } else {
                  if ($i.$_) { Set-Property $Ref $_ $i.$_ }
                }
              }
              # Add 'cid' as reference property when TargetCid matches
              if ($HomeCid -and $i.cid -eq $HomeCid) { Set-Property $Ref cid $i.cid }
              $Config.$Item.Ref.Add($Ref)
              Write-Log 'Set-IdRef' ($Item,($Ref | Format-List | Out-String).Trim() -join "`n")
            } elseif ($Id) {
              # Log that existing reference was skipped
              Write-Log 'Set-IdRef' ($Item,('Ignored existing record "{0}"' -f $Id) -join "`n")
            }
          }
          
        }
      }
    }
    function Submit-Group ([string]$Item,[string]$Property,[object]$Obj,[object]$Ref) {
      if ($Item -eq 'FileVantagePolicy') {
        $Param = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'Fail' }
        if ($Property -eq 'rule_groups' -and $Obj.rule_groups) {
          # Assign FileVantageRuleGroup and capture result
          $Req = $Obj.rule_groups | Add-FalconFileVantageRuleGroup -PolicyId $Obj.id @Param
          if ($Req) {
            Add-Result Modified $Req $Item rule_groups ($Ref.rule_groups -join ',') ($Req.rule_groups.id -join ',')
          } elseif ($Fail) {
            # Capture FileVantageRuleGroup assignment failure
            Add-Result Failed $Obj FileVantagePolicy -Comment $Fail.exception.message -Log 'to assign'
          }
        } elseif ($Property -eq 'host_groups' -and $Obj.host_groups) {
          # Assign HostGroup and capture result
          $Req = $Obj.host_groups | Add-FalconFileVantageHostGroup -PolicyId $Obj.id @Param
          if ($Req) {
            Add-Result Modified $Req $Item host_groups ($Ref.host_groups -join ',') ($Req.host_groups.id -join ',')
          } elseif ($Fail) {
            # Capture HostGroup assignment failure
            Add-Result Failed $Obj FileVantagePolicy -Comment $Fail.exception.message -Log 'to assign'
          }
        }
      } else {
        # Assign group(s) to target object
        [string]$Action = if ($Property -eq 'ioa_rule_groups') { 'add-rule-group' } else { 'add-host-group' }
        [object[]]$Req = foreach ($g in $Obj.$Property) {
          # Assign each HostGroup or IoaGroup
          if ($Ref.$Property.id -notcontains $g.id) { Invoke-PolicyAction $Item $Action $Obj $g.id }
        }
        if ($Req -and $Req[-1].$Property.id) {
          # Capture latest assignment result if entire objects are returned
          Add-Result Modified $Req[-1] $Item $Property ($Ref.$Property.id -join ',') (
            $Req[-1].$Property.id -join ',')
        } elseif ($Req) {
          # Combine '$Property.$Id' values
          Add-Result Modified $Obj $Item $Property ($Ref.$Property -join ',') ($Req -join ',')
        }
      }
    }
    function Update-Exclusion ([PSCustomObject]$Obj,[string]$Item) {
      if ($Obj.applied_globally -eq $true) {
        # Convert 'groups' to 'all' when 'applied_globally' is true
        Set-Property $Obj groups @('all')
        Write-Log 'Update-Exclusion' ('Changed "groups" for {0} "{1}" to "all"' -f $Item,$Obj.id)
      } elseif ($Obj.groups) {
        foreach ($i in $Obj.groups) {
          # Update assigned HostGroup with new identifiers or remove existing group
          $New = @($Config.HostGroup.Ref).Where({$_.old -eq $i.id}).new
          if ($New) {
            Write-Log 'Update-Exclusion' ('Changed group identifier "{0}" to "{1}" for {2} "{3}"' -f $i.id,$New,
              $Item,$Obj.id)
            Set-Property $i id $New
          } else {
            Write-Log 'Update-Exclusion' ('Removed group identifier "{0}" from {1} "{2}"' -f $i.id,$Item,$Obj.id)
          }
        }
        # Filter out any HostGroup without a defined identifier
        $Obj.groups = @($Obj.groups).Where({$_.id})
      }
    }
    function Update-GroupId ([object[]]$Obj,[string]$Item,[string]$Type) {
      # Determine which identifier reference to check by 'Type'
      [string]$Key = switch ($Type) {
        'groups' { 'HostGroup' }
        'host_groups' { 'HostGroup' }
        'ioa_rule_groups' { 'IoaGroup' }
        'rule_groups' { 'FileVantageRuleGroup' }
      }
      foreach ($i in $Obj) {
        if ($i.id) {
          $Filter = Write-SelectFilter $i $Key -Ref
          if ($Filter) {
            $Ref = $Config.$Key.Ref | Where-Object -FilterScript $Filter
            if ($Ref.new -and $i.id -ne $Ref.new) {
              # Update group identifier
              Write-Log 'Update-GroupId' "$(($Item,$Type -join ': '),($i | Select-Object name,
                @{l='old';e={$i.id}},@{l='new';e={$Ref.new}} | Format-List | Out-String).Trim() -join "`n")"
              Set-Property $i id $Ref.new
            } elseif (!$Ref.new) {
              # Remove from groups value when new identifier is not available
              [object[]]$Obj = @($Obj).Where({$_.id -ne $i.id})
              Write-Log 'Update-GroupId' ($Item,('Removed unmatched group "{0}"' -f $i.id) -join ': ')
            }
          }
        } elseif ($i -match '^[a-fA-F0-9]{32}$') {
          # Use identifier reference to replace 'old' identifier values with 'new' values
          $New = @($Config.$Key.Ref).Where({$_.old -eq $i}).new
          if ($New) {
            # Update identifier
            [object[]]$Obj = $Obj -replace $i,$New
            Write-Log 'Update-GroupId' "$(($Item,$Type -join ': '),($i | Select-Object @{l='old';e={$i}},
              @{l='new';e={$New}} | Format-List | Out-String).Trim() -join "`n")"
          } else {
            # Remove from array when new identifier is not available
            [object[]]$Obj = @($Obj).Where({$_ -ne $i})
            Write-Log 'Update-GroupId' (($Item,$Type -join ': '),
              (' Removed unmatched group "{0}"' -f $i) -join "`n")
          }
        }
      }
      $Obj
    }
    function Update-SuPolicy {
      # Default timezone for use with 'scheduler'
      [string]$DefaultTz = 'Etc/Universal'
      foreach ($i in $Config.SensorUpdatePolicy.Import) {
        # Update sensor builds of imported policies with current build values
        if ($i -and $i.settings.build) {
          [string]$pBuild = if ($i.settings.build -match '|') {
            ($i.settings.build -split '\|',2)[-1]
          } else {
            $i.settings.build
          }
          $pNew = Get-CurrentBuild $pBuild $i.platform_name
          if ($pNew -and $pNew.build -ne $i.settings.build) {
            # Replace 'build' and related properties with current tagged version
            @('build','sensor_version','stage').foreach{
              Write-Log 'Update-SuPolicy' ($i.id,(' Changed "{0}" value from "{1}" to "{2}"' -f $_,$i.settings.$_,
                $pNew.$_) -join "`n")
              Set-Property $i.settings $_ $pNew.$_
            }
          } elseif (!$pNew) {
            # Strip build if build match is not available
            Write-Log 'Update-SuPolicy' ($i.id,(' Failed to match build "{0}"' -f $pBuild) -join "`n")
            Set-Property $i.settings build $null
          }
        }
        if ($i -and [string]::IsNullOrEmpty($i.settings.build)) {
          @('build','sensor_version','stage').foreach{
            # Remove properties to default to 'Sensor version updates off' when 'build' is empty
            Set-Property $i.settings $_ $null
            Write-Log 'Update-SuPolicy' ($i.id,(' Removed "{0}" value' -f $_) -join "`n")
          }
        }
        if ($i -and $i.settings.variants) {
          foreach ($v in $i.settings.variants) {
            # Update sensor variants with current available variant build values
            [string]$vBuild = if ($v.build -match '|') { ($v.build -split '\|',2)[-1] } else { $v.build }
            $vNew = Get-CurrentBuild $vBuild $v.platform
            if ($vNew -and $vNew.build -ne $v.build) {
              # Replace build with current tagged version
              Write-Log 'Update-SuPolicy' ($i.id,(' Changed {0} variant {1} "{2}" to "{3}"' -f $v.platform,$_,
                $v.build,$vNew.build) -join "`n")
              @('build','sensor_version','stage').foreach{ Set-Property $v $_ $vNew.$_ }
            } elseif (!$vNew) {
              # Strip build if match is not available
              Write-Log 'Update-SuPolicy' ($i.id,(' Failed to match {0} variant build "{1}"' -f $v.platform,
                $vBuild) -join "`n")
              Set-Property $v build $null
            }
            if ([string]::IsNullOrEmpty($v.build)) {
              # Strip build and sensor_version if 'build' is not present
              Set-Property $i.settings variants @($i.settings.variants).Where({$_.platform -ne $v.platform})
              Write-Log 'Update-SuPolicy' ($i.id,(' Removed "{0}" from variants' -f $v.platform) -join "`n")
            }
          }
        }
        if ($i -and !$i.settings.variants) {
          # Remove 'variants' if no variants are present for policy creation/modification
          $i.settings.PSObject.Properties.Remove('variants')
          Write-Log 'Update-SuPolicy' ($i.id,' Removed empty variants list' -join "`n")
        }
        if ($i.settings.scheduler) {
          if ([string]::IsNullOrEmpty($i.settings.scheduler.timezone)) {
            # Set default if no timezone is provided under 'scheduler'
            Set-Property $i.settings.scheduler timezone $DefaultTz
            Write-Log 'Update-SuPolicy' ($i.id,(' Set scheduler default timezone to {0}' -f $DefaultTz) -join "`n")
          }
        }
      }
    }
    function Write-SelectFilter ([object]$Obj,[string]$Item,[switch]$Ref) {
      # Create FilterScript to select matching item
      if ($Obj) {
        if ($Item -eq 'DeviceControlException') {
          # Use 'match_method', 'action' and relevant 'name' properties to create filter
          [System.Collections.Generic.List[string]]$Select = @('match_method','action')
          @(Select-ObjectName $Obj $Item).foreach{ $Select.Add($_) }
          [scriptblock]::Create("($((@($Select).foreach{ '$_.{0} -eq "{1}"' -f $_,$Obj.$_}) -join ' -and '))")
        } else {
          [string[]]$Output = switch ($Obj) {
            { $_.platforms } {
              if ($Ref) {
                # Use 'os' to filter 'platforms' for an identifier reference
                "($((@($_.platforms).foreach{ '$_.os -contains "{0}"' -f $_ }) -join ' -and '))"
              } else {
                "($((@($_.platforms).foreach{ '$_.platforms -contains "{0}"' -f $_ }) -join ' -and '))"
              }
            }
            { $_.platform_name } {
              if ($Ref) {
                # Use 'os' to filter 'platform_name' for an identifier reference
                '$_.os -contains "{0}"' -f $_.platform_name
              } else {
                '$_.platform_name -eq "{0}"' -f $_.platform_name
              }
            }
            { $_.platform } {
              if ($Ref) {
                # Use 'os' to filter 'platform' for an identifier reference
                '$_.os -contains "{0}"' -f $_.platform
              } else {
                '$_.platform -eq "{0}"' -f $_.platform
              }
            }
            { $_.name } { '$_.name -eq "{0}"' -f $_.name }
            { $_.path } { '$_.path -eq "{0}"' -f $_.path }
            { $_.precedence } { '$_.precedence -eq "{0}"' -f $_.precedence }
            { $_.ruletype_id } { '$_.ruletype_id -eq "{0}"' -f $_.ruletype_id }
            { $_.type } { '$_.type -eq "{0}"' -f $_.type }
            { $_.value } { '$_.value -eq "{0}"' -f $_.value }
          }
          if ($Output) {
            # Add 'cid' if 'TargetCid' matches, then create FilterScript
            if ($HomeCid -and $Obj.cid -eq $HomeCid) { $Output += '$_.cid -eq "{0}"' -f $Obj.cid }
            [scriptblock]::Create(($Output -join ' -and '))
          } else {
            # Log when filter is not created
            Write-Log 'Write-SelectFilter' (
              'Unable to determine filter critera for "{0}"' -f (Select-ObjectName $Obj $Item))
          }
        }
      }
    }
    [string]$ArchivePath = $Script:Falcon.Api.Path($PSBoundParameters.Path)
    [string]$NoEnum = '^(FirewallRule)$'
    [string]$OutputFile = Join-Path (Get-Location).Path "FalconConfig_$(Get-Date -Format FileDateTime).csv"
    [regex]$PolicyDefault = '^(platform_default|Default Policy \((Linux|Mac|Windows)\))$'
    [string]$UaComment = ((Show-FalconModule).UserAgent,'Import-FalconConfig' -join ': ')
  }
  process {
    $UserDict = @{}
    @('Default','Existing').foreach{
      # Capture valid values for ModifyDefault and ModifyExisting
      $UserDict["Valid$_"] = @(
        (Get-Command Import-FalconConfig).Parameters."Modify$_".Attributes.ValidValues
      ).Where({$_ -ne 'All'})
    }
    $PSBoundParameters.GetEnumerator().Where({!$_.Key.Equals('Path') -and $_.Value}).foreach{
      # Capture user input for AssignExisting, ModifyDefault, ModifyExisting, and Select
      $UserDict[$_.Key] = $_.Value
    }
    # Update input to coincide with Select values
    Confirm-InputValue $UserDict
    if (!$ArchivePath) { throw "Failed to resolve '$($PSBoundParameters.Path)'." }
    [string]$HomeCid = try {
      # Attempt to retrieve CID using 'Get-FalconCcid' for evaluation
      Confirm-CidValue (Get-FalconCcid -EA 0)
    } catch {
      throw "Failed to retrieve target CID value. Verify 'Sensor Download: Read' permission."
    }
    # Import items from target archive
    $Config = Import-ConfigJson $ArchivePath $UserDict.Select
    if (!$Config) { throw "Failed to import configuration files!" }
    # Create identifier references for imported items
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Import})) {
      Set-IdRef $p.Value.Import $p.Key
      if (!$Config.HostGroup.Import -and $p.Values.Import.groups) {
        # Capture HostGroup identifiers when HostGroup was not imported
        Set-IdRef $p.Values.Import.groups HostGroup
      }
      if (!$Config.IoaGroup.Import -and $p.Key -eq 'PreventionPolicy' -and $p.Value.Import.ioa_rule_groups) {
        # Capture IoaGroup identifiers from PreventionPolicy when IoaGroup was not imported
        Set-IdRef $p.Value.Import.ioa_rule_groups IoaGroup
      }
    }
    # Modify imported SensorUpdatePolicy
    if ($Config.SensorUpdatePolicy.Import) {
      $Config.SensorUpdatePolicy['Build'] = try {
        # Retrieve current sensor builds
        Write-Host "[Import-FalconConfig] Retrieving current sensor builds for SensorUpdatePolicy..."
        Get-FalconBuild
      } catch {
        throw "Failed to retrieve current sensor builds. Verify 'Sensor update policies: Write' permission."
      }
      # Update SensorUpdatePolicy scheduler and current builds
      if ($Config.SensorUpdatePolicy.Build) { Update-SuPolicy }
    }
    # Add items from target CID to Config, filter Import, create Modify list
    Get-FromCid
    Find-Import
    # Create HostGroup
    if ($Config.HostGroup.Import) {
      New-Group HostGroup
      Clear-ConfigList HostGroup Import
    }
    # Create non-policy items
    foreach ($p in $Config.GetEnumerator().Where({$_.Key -notmatch 'Policy$' -and $_.Value.Import})) {
      if ($p.Key -match '^(Ioa|Ml|Sv)Exclusion$') {
        # Create IoaExclusion, MlExclusion, SvExclusion
        foreach ($i in $p.Value.Import) {
          if ($i.applied_globally -eq $false -and !$i.groups) {
            # Ignore exclusion, add to output
            Add-Result Ignored $i $p.Key -Comment 'applied_globally:false, groups:null'
          } else {
            # Verify required properties and values
            Update-Exclusion $i $p.Key
            if ($i.groups) {
              # Create exclusion
              @($i | & "New-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
                # Update identifier reference, capture result
                Add-Result Created $_ $p.Key
                Set-IdRef $_ $p.Key -Update
              }
              if ($Fail) { Add-Result Failed $i $p.Key -Comment $Fail.exception.message -Log 'to create' }
            }
          }
        }
      } elseif ($p.Key -match 'Group$') {
        # Create FileVantageRuleGroup, FirewallGroup (including FirewallRule), and IoaGroup
        New-Group $p.Key $UaComment
      } elseif ($p.Key -eq 'Ioc') {
        # Create Ioc
        do {
          
          ## Update host groups for IOCs, add IOCs that aren't "global" and don't have groups to "failed" result

          foreach ($i in ($p.Value.Import | New-FalconIoc -EA 0 -EV Fail)) {
            if ($i.message_type -and $i.message) {
              # Add individual failure to output
              Add-Result Failed $i $p.Key -Log 'to create' -Comment ($i.message_type,$i.message -join ': ')
            } elseif ($i.type -and $i.value) {
              # Update identifier reference, capture result
              Add-Result Created $i $p.Key
              Set-IdRef $i $p.Key -Update
            }
            # Remove individual Ioc from Import
            $p.Value.Import = @($p.Value.Import).Where({$_.type -ne $i.type -and $_.value -ne $i.value})
          }
          if ($Fail) {
            @($p.Value.Import).foreach{
              # Capture full creation failure
              Add-Result Failed $_ $p.Key -Comment $Fail.exception.message -Log 'to create'
            }
          }
        } until ($Fail -or !$p.Value.Import)
      } elseif ($p.Key -eq 'Script') {
        # Create Script
        foreach ($i in $p.Value.Import) {
          @($i | & "Send-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
            Add-Result Created ($i | Select-Object name,platform) $p.Key
          }
          if ($Fail) { Add-Result Failed $i $p.Key -Comment $Fail.exception.message -Log 'to create' }
        }
      }
      if ($p.Key -notmatch $NoEnum) { Clear-ConfigList $p.Key Import }
    }
    # Create Policy
    foreach ($p in $Config.GetEnumerator().Where({$_.Key -match 'Policy$' -and $_.Value.Import})) {
      Write-Host "[Import-FalconConfig] Creating $($p.Key)..."
      for ($i=0;$i -lt $p.Value.Import.Count;$i+=100) {
        [PSCustomObject[]]$g = @($p.Value.Import)[$i..($i+99)]
        @($g | & "New-Falcon$($p.Key)" -EA 0 -EV Fail).foreach{
          # Update identifier reference, capture result, add to CID list for comparison during modification step
          Set-IdRef $_ $p.Key -Update
          Add-Result Created $_ $p.Key
          $Config.($p.Key).Cid.Add((Compress-Object $_ $p.Key))
        }
        if ($Fail) {
          # Capture creation failure
          @($g).foreach{ Add-Result Failed $_ $p.Key -Comment $Fail.exception.message -Log 'to create' }
        }
      }
      Clear-ConfigList $p.Key Import
    }
    # Modify non-policy items
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Modify -and $_.Key -notmatch 'Policy$'})) {
      # Gather matching item from CID, evaluate for differences and modify by type
      foreach ($m in $p.Value.Modify) { Edit-Item $m $p.Key $UaComment }
      Clear-ConfigList $p.Key Modify
    }
    # Modify Policy
    foreach ($p in $Config.GetEnumerator().Where({$_.Value.Modify -and $_.Key -match 'Policy$'})) {
      foreach ($m in $p.Value.Modify) {
        [object[]]$Cid = if ($m) {
          # Gather matching policy from CID
          $Config.($p.Key).Cid | Where-Object -FilterScript (Write-SelectFilter $m $p.Key)
        }
        if ($HomeCid -and @($Cid).Where({$_.cid -eq $HomeCid})) {
          # Filter by 'cid' if re-importing into source CID to remove inherited policies
          [object[]]$Cid = @($Cid).Where({$_.cid -eq $HomeCid})
        }
        if (($Cid | Measure-Object).Count -gt 1) {
          # Make no changes when more than one matching policy is found
          Add-Result Ignored $m $p.Key -Comment ('Multiple {0} named "{1}" present' -f $m.platform_name,$m.name)
        } elseif ($m -and $Cid) {
          # Modify policy by type
          Edit-Policy $m $p.Key $Cid $Config
        }
      }
      Clear-ConfigList $p.Key Modify
    }
  }
  end {
    if ($Config.Values.Result) {
      # Select 'policy created' and FileVantagePolicy 'modified rule_groups' results
      [PSCustomObject[]]$Warn = @($Config.Values.Result).Where({($_.type -match 'Policy$' -and $_.action -eq
        'Created') -or ($_.type -match '^(FileVantage|Firewall)Policy$' -and $_.action -eq 'Modified' -and
        $_.property -match '^rule_group(_id)?s$' -and $_.old_value)})
      foreach ($Platform in ($Warn.platform | Select-Object -Unique)) {
        foreach ($i in @($Warn).Where({$_.platform -eq $Platform})) {
          if ($i.action -eq 'Created' -and @($Config.($i.type).Cid).Where({$_.platform_name -eq $i.platform -and
          $_.name -notmatch $PolicyDefault})) {
            # Output precedence warning for existing policies for each 'platform'
            $PSCmdlet.WriteWarning(
              ('[Import-FalconConfig] Existing {0} {1} were found. Verify precedence!' -f $i.platform,$i.type))
          } elseif ($i.action -eq 'Modified') {
            # Output precedence when rule groups are assigned to policies with existing rule groups
            $PSCmdlet.WriteWarning(
              ('[Import-FalconConfig] {0} {1} "{2}" had existing {3}. Verify precedence!') -f $i.platform,$i.type,
              $i.name,$i.property)
          }
        }
      }
    }
    if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
  }
}