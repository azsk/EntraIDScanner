Set-StrictMode -Version Latest 
class StreamAnalytics: AzSVTBase
{       
    hidden [PSObject] $ResourceObject;

    StreamAnalytics([string] $subscriptionId, [SVTResource] $svtResource): 
        Base($subscriptionId, $svtResource) 
    { 
    }

    hidden [ControlResult] CheckStreamAnalyticsMetricAlert([ControlResult] $controlResult)
    {
        $this.CheckMetricAlertConfiguration($this.ControlSettings.MetricAlert.StreamAnalytics, $controlResult, "");
        return $controlResult;
	 }
}
