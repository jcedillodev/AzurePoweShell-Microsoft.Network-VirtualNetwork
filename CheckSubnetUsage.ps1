function Check-SubnetUsage{
    param (
        [Parameter()]
        [Microsoft.Azure.Commands.Network.Models.PSChildResource]$SubnetConfig,

        [Parameter()]
        [Microsoft.Azure.Commands.Network.Models.PSTopLevelResource]$VirtualNetwork,

        [Parameter()]
        [String]$SubnetName
    )

    # If a subnet config object is not passed to function but vnet object/subnet name are, then use the
    # 'Get-AzVirtualNetworkSubnetConfig' cmdlet to retreive this value
    if($null -eq $SubnetConfig)
    {
        $SubnetConfig = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VirtualNetwork -Name $SubnetName
    }

    # Get current script user's current Azure context
    $azContext = Get-AzContext

    # Check if current script user is logged into Azure Powershell - If not, user will need to log in.
    if(!$azContext)
    {
        Write-Host "Please log into Azure PowerShell using the 'Connect-AzAccount' cmdlet." -ForegroundColor Red
        Break
    }

    # Check to see if the provided subscription exists in the current tenant or if the user has permissions into that resource.
    try {
        # Access properties within the SubnetConfig object to get data such as RG name or VNET name
        # to retrieve the VNET object
        $vnetSubId = (($SubnetConfig.Id).Split("/")[2])
        $vnetRg = (($SubnetConfig.Id).Split("/")[4])
        $vnetNm = (($SubnetConfig.Id).Split("/")[8])
        
        # Check if the user's current Az context is set to the subscription of the provided subnet config object
        # then reset to the correct subscription extracted from the provided subnet config resource ID
        if($azContext.subscription.id -ne $vnetSubId)
        {
            $targetSubscription = Get-AzSubscription -SubscriptionId $vnetSubId
            Write-Host "Updating Az context from subscription '$($azContext.Subscription.Name)' to '$($targetSubscription.Name)'." -ForegroundColor Blue
            set-azcontext -subscription $vnetSubId
        }
        
        # Using data extracted from the provided subnet config object, retrieve the VNET object to reference is resource ID
        $vnetObj = Get-AzVirtualNetwork -ResourceGroupName $vnetRg -Name $VnetNm
        $vnetId = $vnetObj.Id

        # Instantiate variables to hold the response to be returned to user once evaluation of the subnet is complete
        # along with the for loop interation variable and an array to hold linked Azure resource(s)
        $res; $x; $linkedAzRes=@();

        # If the subnet config object has any existing objects in the IpConfigurations with no existing objects
        # in the PrivateEndpoints object, add new objects into the linkedAzRes array for each
        if(($SubnetConfig.IpConfigurations).count -gt 0 -and (($SubnetConfig.PrivateEndpoints).count -eq 0 -or $null -eq $SubnetConfig.PrivateEndpoints))
        {
            for($x = 0; $x -lt $SubnetConfig.IpConfigurations.Count; $x++)
            {
                $linkedAzRes += if($null -ne $SubnetConfig.IpConfigurations[$x].Id)
                {
                    @{Id=$SubnetConfig.IpConfigurations[$x].Id}
                }
                else
                {
                    @{Id="Link property with ID is null - see ResourceNavigationLinks property as text: $($SubnetConfig.IpConfigurationsText)"}
                }
            }
        }
        # Else, if there are existing objects in the ResourceNavigationLinks property, add new objects into the linkedAzRes array for each
        elseif (($SubnetConfig.ResourceNavigationLinks).count -gt 0)
        {
            for($x = 0; $x -lt $SubnetConfig.ResourceNavigationLinks.Count; $x++)
            {
                $linkedAzRes += if($null -ne $SubnetConfig.ResourceNavigationLinks[$x].Link)
                {
                    @{Id=$SubnetConfig.ResourceNavigationLinks[$x].Link}
                }
                else
                {
                    @{Id="Link property with ID is null - see ResourceNavigationLinks property as text: $($SubnetConfig.ResourceNavigationLinksText)"}
                }
            }
        }
        # Else, if there are existing objects in the ServiceAssociationLinks property, add new objects into the linkedAzRes array for each
        elseif (($SubnetConfig.ServiceAssociationLinks).count -gt 0)
        {
            for($x = 0; $x -lt $SubnetConfig.ServiceAssociationLinks.Count; $x++)
            {
                $linkedAzRes += if($null -ne $SubnetConfig.ServiceAssociationLinks[$x].Link)
                {
                    @{Id=$SubnetConfig.ServiceAssociationLinks[$x].Link}
                }
                else
                {
                    @{Id="Link property with ID is null - see ServiceAssociationLinks property as text: $($SubnetConfig.ServiceAssociationLinksText)"}
                }
            }
        }
        # Else, if there are existing objects in the PrivateEndpoints property, add new objects into the linkedAzRes array for each
        elseif (($SubnetConfig.PrivateEndpoints).count -gt 0)
        {
            for($x = 0; $x -lt $SubnetConfig.PrivateEndpoints.Count; $x++)
            {
                $linkedAzRes += if($null -ne $SubnetConfig.PrivateEndpoints[$x].Id)
                {
                    @{Id=$SubnetConfig.PrivateEndpoints[$x].Id}
                }
                else
                {
                    @{Id="Link property with ID is null - see PrivateEndpoints property as text: $($SubnetConfig.PrivateEndpointsText)"}
                }
            }
        }

        <# Test
        foreach($item in $linkedAzRes)
        {
            Write-Host "[DEBUG] $ item.Id: $($item.Id)"
        }#>

        # If the linkedAzRes array length is greater than 0, extract the linked resource ID and set response message
        if($linkedAzRes.length -gt 0)
        {
            # Check to see if the vnet resource ID exists in the linkedAzRes array
            if($vnetId -notin $linkedAzRes)
            {
                # Set initial message advising user that the target subnet is in use
                $res = "Subnet [$($SubnetConfig.Name)] is currently in use and is tied to the following resource(s):"
                
                # Then, using a foreach loop, add string(s) with details for each object included in the linkedAzRes array
                # as a subnet could be linked to multiple resources such as private endpoints as an example
                foreach($link in $linkedAzRes)
                {
                    # Split the current loop iteration's object ID property into an array of strings using '/' as the delimiter
                    $azResIdArr = ($link.Id).split("/")

                    # For readability, add a separator for each object
                    $res = $res + "`n" + "########################################"

                    # Use Switch statement to set conditions on how to format responses to users based on the linked resource type (if subnet is in use)
                    $linkedResType = $azResIdArr[6] + "/" + $azResIdArr[7]
                    switch($linkedResType)
                    {
                        "Microsoft.Web/hostingEnvironments" {$res = $res + "`n" + "ASE resource: $($azResIdArr[8])"+ "`n" + "ASE Resource ID: $($link.Id)"}
                        "Microsoft.Network/privateEndpoints" {$res = $res + "`n" + "Private Endpoint resource: $($azResIdArr[8])"+ "`n" + "Private Endpoint Resource ID: $($link.Id)"}
                        "Microsoft.Web/serverFarms" {$res = $res + "`n" + "App Service Plan resource: $($azResIdArr[8])"+ "`n" + "App Service Plan Resource ID: $($link.Id)"}
                        default {$res = $res + "`n" + "Azure resource: $($azResIdArr[8])"+ "`n" + "Azure Resource ID: $($link.Id)"}
                    }
                }
                # As the subnet is in use, return the compile in red text
                Return Write-Host $res -ForegroundColor Red;
            }
        }
        else{
            # If there is not data added to the linkedAzRes variable then the subnet should be available for use
            $res = "Subnet [$($SubnetConfig.Name)] is currently available for use."
            Return Write-Host $res -ForegroundColor Green;
        }
    }
    catch {
        # Return exception message if the Get-AzSubscription call fails either with the target subscription ID not existing in the tenant
        # Or, the user does not have access to the target subscription
        $eMsg = $_.Exception.Message
        Write-Host $eMsg -BackgroundColor Red
        Break
    }
}