function Check-SubnetUsage {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Cidr,
        [Boolean]$DebugFx
    )

    <#
    Cidr to IP/IP Range to Cidr guide - see URL below:
    https://www.ipaddressguide.com/cidr

    For IP availability, see below doc/post:
    https://learn.microsoft.com/en-us/powershell/module/az.network/test-azprivateipaddressavailability?view=azps-10.1.0
    https://stackoverflow.com/questions/41774085/get-list-of-available-ip-addresses-in-subnet
    #>

    try {
        # Get current script user's current Azure context
        $azContext = Get-AzContext -ErrorAction Break

        # Check if current script user is logged into Azure Powershell - If not, user will need to log in.
        if (!$azContext) {
            Write-Host "Please log into Azure PowerShell using the 'Connect-AzAccount' cmdlet." -ForegroundColor Red
            Break
        }

        # Hastable to return to user with results
        $result = @{}

        # Setup arrays to hold the available/utilized CIDR values to pass into the returned result object
        $availableCidrs = @()
        $utilizedCidrs = @()

        # Convert the provided CIDR value into an array
        $cidrstrarr = $Cidr.Split('.')

        # Start process by building a collection of all Azure subscriptions available to the user
        $subscriptions = Get-AzSubscription -ErrorAction Break

        # Iterate through each subscription in the collection setup above
        foreach ($subscription in $subscriptions)
        {
            # Update the current context to the current subscription in the foreach loop iteration
            Set-AzContext -Subscription $subscription.Id -ErrorAction Break

            # Retrieve all vnets existing within the current iterations subscription and store within a collection
            $vnets = Get-AzVirtualNetwork -ErrorAction Break

            # Iterate through this collection of vnets
            foreach ($vnet in $vnets)
            {
                # Extract the resource group value from the VNET resource ID
                $vnetRg = (($vnet.Id).Split('/'))[4]

                # Iterate through all subnets set within each vnet
                foreach ($subnet in $vnet.Subnets)
                {
                    # Construct a wildcard substring of the target CIDR provided by the user to see if there are any existing subnets
                    # that have an address prefix similar to it
                    $networkAddressSubStr = $cidrstrarr[0] + "." + $cidrstrarr[1] + "." + $cidrstrarr[2] + ".*"

                    # While iterating through the existing subnets, if the subnet's address prefix is similar to the above substring
                    # then add it to the collection of utilzied CIDR value(s)
                    if([String]$subnet.AddressPrefix -like [String]$networkAddressSubStr)
                    {
                        if($DebugFx)
                        {
                            Write-Host "[DEBUG] ########################################"
                            Write-Host "[DEBUG] Network Address Substring ($($networkAddressSubStr))"
                            Write-Host "[DEBUG] Vnet: $($vnet.Name)"
                            Write-Host "[DEBUG] Subnet ($($subnet.Name)) - Address Prefix: ($($subnet.AddressPrefix))"
                            Write-Host "[DEBUG] Eval: $(([String]$subnet.AddressPrefix -like [String]$networkAddressSubStr))"
                        }

                        # Create a PS object and add it to the utilized cidrs array
                        $utilizedCidrs += [PSCustomObject][ordered]@{
                            targetCidr = $Cidr
                            subscriptionId = $subscription.Id
                            subscriptionName = $subscription.Name
                            vnetResourceGroup = $vnetRg
                            vnet = $vnet.Name
                            existingSubnet = $subnet.Name
                            subnetAddressPrefix = $subnet.AddressPrefix
                        }

                        # Use Azure CLI to extract available IP(s) on the current VNET
                        # so confirm that Azure CLI is installed and the user is currently logged in
                        $azCliVersion = az --version
                        $azCliCtx = az account show

                        # Check if Azure CLI is installed and the user is logged in, proceed with getting avaialble IP(s)
                        if(($azCliVersion) -and ($azCliCtx))
                        {
                            # Set the current account to the current subscription
                            az account set -s $subscription.Id

                            # Extract available IPs as an array from the current VNET in the iteration
                            $availableIps = az network vnet list-available-ips -g $vnetRg -n $vnet.Name

                            # If there any existing available IP(s) returned from the prior cmdlet, proceed with getting
                            # starting/ending IPs to convert to a CIDR value
                            if($availableIps.Count -gt 0)
                            {
                                # Extract the starting/ending IPs from the array
                                $startingIp = ($availableIps[1].Split('"'))[1]
                                $endingIp = ($availableIps[($availableIps.Count - 2)].Split('"'))[1]

                                # Using the above starting/ending IPs, extract a CIDR value
                                $availableCidr = Get-CidrFromIpRange -StartingIpAddress $startingIp -EndingIpAddress $endingIp

                                if($DebugFx)
                                {
                                    Write-Host "[DEBUG] Available CIDR: $($availableCidr)"
                                }

                                # Create a PS object and add it to the available cidrs array
                                $availableCidrs += [PSCustomObject][ordered]@{
                                    subscriptionId = $subscription.Id
                                    subscriptionName = $subscription.Name
                                    vnetResourceGroup = $vnetRg
                                    vnet = $vnet.Name
                                    availableCidrs = $availableCidr
                                }
                            }
                        }
                    }
                }
            }
        }

        # Set properties on the returned object from script execution
        $result['TargetCidr'] = $Cidr
        if($availableCidrs.Count -gt 0){$result['AvailableCidrs'] = $availableCidrs}
        $result['UtilizedCidrs'] = $utilizedCidrs

        return $result
    }
    catch {
        # If an exception occurs, return the error details to the user
        $eMsg = $_.Exception.Message
        Write-Host $eMsg -BackgroundColor Red
        Break
    }
}

function Get-AllIpsFromRange {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])(\.(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])){3}$")]
        [String]$StartingIpAddress,
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])(\.(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])){3}$")]
        [String]$EndingIpAddress,
        [Boolean]$DebugFct
    )

    $result = @()

    # Take the starting/ending IPs and convert them into arrays to reference the 3rd/4th octets
    $startIpArr = $StartingIpAddress.Split('.')
    $endIpArr = $EndingIpAddress.Split('.')

    # Execute a for loop to iterate through the difference between the starting/ending 3rd octet
    for($x = [int]($startIpArr[2]); $x -le [int]($endIpArr[2]); $x++)
    {
        # Execute a for loop to iterate through the difference between the starting/ending 4th octet
        for($y = [int]($startIpArr[3]); $y -le [int]($endIpArr[3]); $y++)
        {
            # Dynamically construct an IP address as part of the collection to return
            $ip = ($startIpArr[0] + "." + $startIpArr[1] + "." + [String]$x + "." + [String]$y)

            # Debug logging
            if($DebugFct)
            {
                Write-Host "[DEBUG] IP fx (Get-AllIpsFromRange): $($ip)"
            }

            # Convert the string IP address value into an IP address and add to the results collection
            $result += [System.Net.IPAddress]$ip
        }
    }

    # Return result to user
    return $result
}

function Extract-IpRangeFromCidr {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Cidr
    )

    <#
    Base for code sourced from below URL:
    https://blog.tyang.org/2011/05/01/powershell-functions-get-ipv4-network-start-and-end-address/
    #>

    # A result hashtable will be returned when function is executed containing the starting/ending IP address for the IP range
    $result = @{}

    try {
        # Extract the subnet network address from full IPv4 address prefix
        $networkAddress = ($Cidr.Split("/"))[0]

        # Get the network length from IP mask
        [int]$networkLength = ($Cidr.split("/"))[1]

        # Transform string network address to extract IP range
        $networkIp = ([System.Net.IPAddress]$networkAddress).GetAddressBytes()
        [Array]::Reverse($networkIp)
        $networkIp = ([System.Net.IPAddress]($networkIp -join ".")).Address

        ########## Set the Starting IP address for result hashtable ##########
        $startingIp = $networkIp

        # Convert to Double
        if (($startingIp.GetType()).Name -ine "double") {
            $startingIp = [Convert]::ToDouble($startingIp)
        }

        # Cast starting IP as a Double into an IP address
        $startingIp = [System.Net.IPAddress]$startingIp

        # Set the Ending IP address for result hashtable
        $ipLength = 32 - $networkLength

        # Get the number of IPs
        $numOfIps = (([System.Math]::Pow(2, $ipLength)) - 1)

        ########## Set the ending IP in IP range by adding the # of IPs ##########
        $endingIp = $networkIp + $numOfIps

        # Convert to Double
        if (($endingIp.GetType()).Name -ine "double") {
            $endingIp = [Convert]::ToDouble($endingIp)
        }

        # Cast starting IP as a Double into an IP address
        $endingIp = [System.Net.IPAddress]$endingIp

        # Add starting/ending IPs to result hashtable for the IP range
        $result['StartingIp'] = $startingIp
        $result['EndingIp'] = $endingIp

        return $result
    }
    catch {
        <#Do this if a terminating exception happens#>
        $eMsg = $_.Exception.Message
        Write-Host $eMsg -BackgroundColor Red
        Break
    }
}

function Get-CidrFromIpRange {
    param(
        [Parameter(Mandatory = $true)]
        [IPAddress]$StartingIpAddress,
        [Parameter(Mandatory = $true)]
        [IPAddress]$EndingIpAddress
    )

    <#
    Base for code sourced from below URL:
    https://stackoverflow.com/questions/75281955/how-to-convert-ip-range-to-single-cidr-notation-using-powershell
    #>

    Write-Host "[DEBUG] Starting IP Address - fx (Get-CidrFromIpRange): $($StartingIpAddress)"
    Write-Host "[DEBUG] Ending IP Address - fx (Get-CidrFromIpRange): $($EndingIpAddress)"

    try {
        # Check if the provided starting/ending IP addresses are in valid format
        if ($StartingIpAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $EndingIpAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            Write-Error -Message 'Function only works for IPv4 addresses'
        }

        $result = @()

        # Get the IPs in 32-bit unsigned integers (big-endian)
        # The .Address property is little-endian, or host-endian, so avoid that.
        [uint32[]]$octets = $StartingIpAddress.GetAddressBytes()
        [uint32]$StartingIpAddress = ($octets[0] -shl 24) + ($octets[1] -shl 16) + ($octets[2] -shl 8) + $octets[3]

        [uint32[]]$octets = $EndingIpAddress.GetAddressBytes()
        [uint32]$EndingIpAddress = ($octets[0] -shl 24) + ($octets[1] -shl 16) + ($octets[2] -shl 8) + $octets[3]

        # After extracting the octets, remove this variable from scope
        Remove-Variable -Name octets -ErrorAction SilentlyContinue

        while ($StartingIpAddress -le $EndingIpAddress -and $StartingIpAddress -ne [uint32]::MaxValue) {
            # Bitwise shift-right in a loop,
            # to find how many trailing 0 bits there are
            $trailingZeros = 0
            while ([uint32]($StartingIpAddress -shr $trailingZeros) % 2 -eq 0) {
                $trailingZeros++
            }

            # switch all those bits to 1, 
            # see if that takes us past the end IP address. 
            # Try one fewer in a loop until it doesn't pass the end.
            do {
                [uint32]$current = $StartingIpAddress -bor ([math]::Pow(2, $trailingZeros) - 1)
                $trailingZeros--
            } while ($current -gt $EndingIpAddress)

            # Now compare this new address with the original,
            # and handwave idk what this is for
            $prefixLen = 0
            while (([uint32]($current -band [math]::Pow(2, $prefixLen))) -ne ([uint32]($StartingIpAddress -band [math]::Pow(2, $prefixLen)))) {
                $prefixLen++
            }
            $prefixLen = 32 - $prefixLen

            # add this subnet to the output
            [byte[]]$bytes = @(
                (($StartingIpAddress -band [uint32]4278190080) -shr 24),
                (($StartingIpAddress -band [uint32]16711680) -shr 16),
                (($StartingIpAddress -band [uint32]65280) -shr 8),
                ($StartingIpAddress -band [uint32]255)
            )            
            # Add CIDR value into array
            $result += ([IPAddress]::new($bytes).IpAddressToString + "/$prefixLen")

            # Add 1 to current IP
            [uint32]$StartingIpAddress = [uint32]($current + 1)
        }

        # Return result after completing the while loop
        return $result
    }
    catch {
        #Do this if a terminating exception happens#
        $eMsg = $_.Exception.Message
        Write-Host $eMsg -BackgroundColor Red
        Break
    }
}

function Convert-StringIPToIntIP {
    <#
    Base for code sourced from below URL:
    https://sa.stln.net/articles/converting-a-string-with-an-ipv4-address-to-an-integer-with-powershell.html
    #>
    param (
        [Parameter(Mandatory)]
        [ValidatePattern(
            "^(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])(\.(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])){3}$"
        )]
        [string]
        $IPAddressString
    )

    $IPAddressString.Split(".") | foreach { $IPAddress = 0; $IPAddressByte = 0 } {
        [int]::TryParse($_, [ref] $IPAddressByte) | Out-Null
        $IPAddress = $IPAddress -shl 8 -bor $IPAddressByte
    }
    return $IPAddress
}