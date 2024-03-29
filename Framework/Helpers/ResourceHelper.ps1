﻿class ResourceHelper
{
    static hidden [System.Collections.Generic.Dictionary[string, [PSCustomObject]]] $Cache = [System.Collections.Generic.Dictionary[string, [PSCustomObject]]]::new();

    static [array] FetchResourcesByObjectIdsAndCache($objectIds)
    {
        $objectIdsToFetch = @($objectIds | Get-Unique | Where-Object { -not [ResourceHelper]::Cache.ContainsKey($_) });
        $resources = Get-MgDirectoryObjectById -Ids $objectIdsToFetch;
        foreach ($resource in $resources)
        {
            [ResourceHelper]::Cache[$resource.Id] = $resource;
        }
        return @($objectIds | ForEach-Object { [ResourceHelper]::Cache[$_]; });
    }
}