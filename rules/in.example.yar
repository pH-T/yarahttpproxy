rule IncomingExampleRule
{
    meta:
        drop = true // if this rules matches --> drop the connection
        description = "This is just an example for incoming/request matching"
        
    strings:
        $foobar = "foobar"
        $basic_exploit_buffer = "AAAA"
        $regex_md5 = /md5: [0-9a-fA-F]{32}/
        $regex_uppercase_username = /\"Username\":\"[^a-z]*\"/

    condition:
        $foobar 
        or $basic_exploit_buffer
        or $regex_md5 
        or $regex_uppercase_username
}