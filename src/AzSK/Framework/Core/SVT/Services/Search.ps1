#using namespace Microsoft.Azure.Commands.Search.Models
Set-StrictMode -Version Latest 
class Search: AzSVTBase
{       
    hidden [PSObject] $ResourceObject;

	Search([string] $subscriptionId, [SVTResource] $svtResource): 
        Base($subscriptionId, $svtResource) 
    { 
        $this.GetResourceObject();
    }

    hidden [PSObject] GetResourceObject()
    {
        if (-not $this.ResourceObject) {
            $this.ResourceObject = Get-AzResource -Name $this.ResourceContext.ResourceName  `
                                    -ResourceType $this.ResourceContext.ResourceType `
                                    -ResourceGroupName $this.ResourceContext.ResourceGroupName

            if(-not $this.ResourceObject)
            {
                throw ([SuppressedException]::new(("Resource '{0}' not found under Resource Group '{1}'" -f ($this.ResourceContext.ResourceName), ($this.ResourceContext.ResourceGroupName)), [SuppressedExceptionType]::InvalidOperation))
            }
        }

        return $this.ResourceObject;
    }

    hidden [ControlResult] CheckSearchReplicaCount([ControlResult] $controlResult)
   {
        $replicaCount = $this.ResourceObject.Properties.replicaCount
	    $isCompliant =  $replicaCount -ge 3
        if($isCompliant) 
        {
          $controlResult.AddMessage([VerificationResult]::Passed,
                                    [MessageData]::new("Replica count for resource " + $this.ResourceContext.ResourceName + " is " + $replicaCount)); 
        }
        else
        {
          $controlResult.AddMessage([VerificationResult]::Failed,
                                    [MessageData]::new("Replica count for resource " + $this.ResourceContext.ResourceName + " is " + $replicaCount));
        }
        
        return $controlResult;
    }
}
