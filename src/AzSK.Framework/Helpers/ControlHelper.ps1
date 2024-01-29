# This class should contains method that would be required to filter/targer controls
class ControlHelper: EventBase{
      
    #Checks if the severities passed by user are valid and filter out invalid ones
   hidden static [string []] CheckValidSeverities([string []] $ParamSeverities)
   {
       $ValidSeverities = @();		
       $ValidSeverityValues = @();	
       $InvalidSeverities = @();		
       $ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
       if([Helpers]::CheckMember($ControlSettings, 'ControlSeverity'))
       {
                   $severityMapping = $ControlSettings.ControlSeverity
                   #Discard the severity values passed in parameter that do not have mapping in Org settings.
                   foreach($sev in $severityMapping.psobject.properties)
                   {                         
                       $ValidSeverities +=  $sev.value       
                   }
                   $ValidSeverityValues += $ParamSeverities | Where-Object { $_ -in $ValidSeverities}
                   $InvalidSeverities += $ParamSeverities | Where-Object { $_ -notin $ValidSeverities }		
       }
       else 
       {
           $ValidEnumSeverities = [Enum]::GetNames('ControlSeverity')
           $ValidSeverityValues += $ParamSeverities | Where-Object { $_ -in $ValidEnumSeverities}
           $InvalidSeverities += $ParamSeverities | Where-Object { $_ -notin $ValidEnumSeverities }	
          
       }
     
       if($InvalidSeverities)
       {
          [EventBase]:: PublishGenericCustomMessage("WARNING: No control severity corresponds to `"$($InvalidSeverities -join ', ')`" for your org.",[MessageType]::Warning)
       }
       
       return $ValidSeverityValues
   }
}