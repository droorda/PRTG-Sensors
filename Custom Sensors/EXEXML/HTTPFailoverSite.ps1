# Requires -Modules PowerShellLogging

[CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact='Low'
)]
param (
    [System.URI]
    $URI
    ,
    [String]
    $IPaddress
    ,
    # [string]
    # $DomainName
    # ,
    [string]
    $PageTitle
    ,
    [string]
    $Method = "GET"
    ,
    [string]
    $UserAgent = 'Mozilla/5.0 (compatible; PRTG Network Monitor (www.paessler.com); Windows)'
    ,
    [string]
    $RequireKeyword
    ,
    [string]
    $ExcludeKeyword
    ,
    # [int]
    # $DownloadLimit
    # ,
    [ValidateRange(0,999)]
    [int[]]
    $ReturnCode = @(200..299)
    ,
    [ValidateRange(0,20)]
    [int]
    $MaximumRedirection = 0
    ,
    [ValidateRange(0,60000)]
    [int]
    $TimeoutSec = 30
    ,
    $Header
    ,
    [Switch]
    $IgnoreCertificate
    # ,
    # [switch]
    # $Raw
    # [ValidateSet("Ssl3","Tls","Tls11","Tls12")]
    # [string[]]
    # $SecurityProtocolType = @("Tls11","Tls12")

)
begin {
    $ExecutionTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $script:ScriptPath = split-path $SCRIPT:MyInvocation.MyCommand.Path -parent
    $script:ScriptName =            $SCRIPT:MyInvocation.MyCommand.Name.split(".")[0]
    $host.privatedata.VerboseForegroundColor  = 'DarkYellow'

    function Get-MyFunctionLocation {
        $myInvocation
    }


    Write-Verbose "-------------Start $($myInvocation.InvocationName) IN '$((Get-MyFunctionLocation).ScriptName)' : $($ExecutionTimer.Elapsed.ToString()) -----------------"
    Write-Verbose "  From Script:'$($myInvocation.ScriptName)' - At Line:$($myInvocation.ScriptLineNumber) char:$($myInvocation.OffsetInLine)"
    Write-Verbose "  Line '$($myInvocation.Line.Trim())'"
    $myInvocation.BoundParameters.GetEnumerator()  | ForEach-Object { Write-Verbose "  BoundParameter   : '$($_.key)' = '$($_.Value)'" }
    $myInvocation.UnboundArguments | ForEach-Object { Write-Verbose "  UnboundArguments : '$_'" }

    function Ignore-SSLCertificates {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Compiler = $Provider.CreateCompiler()
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource=@'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy
            {
                public class TrustAll : System.Net.ICertificatePolicy
                {
                    public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                    {
                        return true;
                    }
                }
            }
'@
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }


    if (test-path("$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1")) {
        Import-Module "$(split-path $SCRIPT:MyInvocation.MyCommand.Path)\prtgshell.psm1" -DisableNameChecking -Verbose:$False
    } else {
        Write-output "<prtg>"
        Write-output "  <error>1</error>"
        Write-output "  <text>Unable to locate prtgshell.psm1</text>"
        Write-output "</prtg>"
        exit
    }

    if (!$DomainName -and !$URI)  {Set-PrtgError "-DomainName or -URI requred"}
    if (!$IPaddress)  {Set-PrtgError "-IPaddress requred"}
    if ($null -eq $URI.AbsoluteURI) {{Set-PrtgError "invalid URL '$URI' : Should be like https://site.com"}}

    if ($Header) {
        If ($Header -is [System.Collections.Hashtable]) {
            # This is Ideal
        } ElseIf ($Header -is [System.String]) {
            try {
                [System.Collections.Hashtable]$Header = $Header | ConvertFrom-StringData
            } catch {
                Set-PrtgError "invalid header value '$header'"
            }
        } else {
            Set-PrtgError "invalid header type '$($header | Get-Member | Select-Object -ExpandProperty TypeName -Unique)'"
        }
    }

    if ($IgnoreCertificate) {Ignore-SSLCertificates}

    if ([System.Net.IPAddress]::TryParse($IPaddress,[ref][ipaddress]::Loopback)) {
        [System.Net.IPAddress]$IPaddress = $IPaddress
    } else {
        [System.Net.IPAddress]$IPaddress = (Resolve-DnsName -Name $IPaddress).IPAddress | Get-Random
    }

    [System.UriBuilder]$WebRequestURI = $URI
    $WebRequestURI.Host = $IPaddress
    [System.URI]$WebRequestURI = $WebRequestURI.Uri

    $WebRequest = [Net.WebRequest]::Create($WebRequestURI)
    # $WebRequest.Proxy = $Proxy
    # $WebRequest.Credentials = $null
    $WebRequest.Timeout = ($TimeoutSec * 1000)
    $WebRequest.Host = $URI.Host
    # $WebRequest.RequestUri =
    $WebRequest.UserAgent = $UserAgent
    $WebRequest.AllowAutoRedirect = $true
    if ($MaximumRedirection -eq 0) {
        $WebRequest.AllowAutoRedirect =  $false
    } else {
        $WebRequest.AllowAutoRedirect =  $true
        $WebRequest.MaximumAutomaticRedirections = $MaximumRedirection
    }
    $WebRequest.Method = $Method

    Try {
        $LoadTime = Measure-Command {
            $Response = $WebRequest.GetResponse()
            $reqstream = $Response.GetResponseStream()
        }
    } catch {
        Set-PrtgError "Error Connecting to Site $($_.exception.message)"
    }
    $sr = new-object System.IO.StreamReader $reqstream
    $Return = $sr.ReadToEnd()

    Write-Verbose "------------ Response ------------"
    Write-Verbose "StatusCode = $([int]$Response.StatusCode)"
    $Response | out-string | write-Verbose
    $Headers = @{}
    $Response.Headers | ForEach-Object {
        $Headers[$_] = $Response.GetResponseHeader($_)
    }
    Write-Verbose "------------ Headers ------------"
    [pscustomobject]$Headers | Out-String | Write-Verbose

    if ($ReturnCode -notcontains $Response.StatusCode) {
        if (@(301,302) -contains $Response.StatusCode) {
            Set-PrtgError "Returned StatusCode : $($Response.StatusCode) => '$($Response.GetResponseHeader('location'))'"
        } else {
            Set-PrtgError "Returned StatusCode : $($Response.StatusCode)"
        }
    }

    if ($Return.IndexOf("<title>") -gt 0) {
        $title = [regex]::Replace($Return.replace("`n"," "), '.*<title>(.*)<\/title>.*', '$1', 'IgnoreCase').trim() -replace '[^a-zA-Z0-9 ]', ''
        Write-Verbose "Page Title: '$title'"
    }

    if ($PageTitle){
        if ($title -ne $PageTitle) {
            Set-PrtgError "Incorect page Title : '$title'"
        }
    }

    if ($RequireKeyword) {
        if ($Return.IndexOf($RequireKeyword) -lt 0) {
            Set-PrtgError "Could not Find : '$RequireKeyword'"
        }
    }
    if ($ExcludeKeyword) {
        if ($Return.IndexOf($ExcludeKeyword) -ge 0) {
            Set-PrtgError "Found : '$ExcludeKeyword'"
        }
    }
    if ($Header) {
        Foreach ($Name in $Header.Keys) {
            if ($Header[$Name] -ne $Response.GetResponseHeader($Name)) {
                Set-PrtgError "Incorrect Header : [$Name='$($Response.GetResponseHeader($Name))']"
            }
        }
    }


    $XMLOutput = "<prtg>`n"
    $XMLOutput += Set-PrtgResult -Channel "LoadTime"         -Value ([int]$LoadTime.TotalMilliseconds)      -Unit "msec" -sc -MaxWarn 600 -MaxError 1200
    $StatusCode = @{
        MinError = 200
        MaxError = 299
    }
    if ($ReturnCode) {
        $StatusCode.MinError = $ReturnCode | Sort-Object | Select-Object -First 1
        $StatusCode.MaxError = $ReturnCode | Sort-Object | Select-Object -Last 1
    }
    $XMLOutput += Set-PrtgResult -Channel "StatusCode"       -Value ([int]$Response.StatusCode)             -Unit "Count" -sc @StatusCode
    $XMLOutput += Set-PrtgResult -Channel "RawContentLength" -Value ([int]$Return.Length)                   -Unit "Count" -sc
    $XMLOutput += "<text>StatusDescription: $($Response.StatusDescription)</text>`n"
    $XMLOutput += "</prtg>"
    $XMLOutput

}
process {
}
End {
    Write-Verbose "--------------END- $($myInvocation.InvocationName) : $($ExecutionTimer.Elapsed.ToString()) -----------------"
}




