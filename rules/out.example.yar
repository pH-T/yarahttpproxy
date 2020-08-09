rule OutgoingExampleRule
{
    meta:
        drop = false // if this rules matches --> drop the connection
        description = "This is just an example for outgoing/response matching"
        
    strings:
        $hello_world = /Hello World/ // regex support

    condition:
        $hello_world
}