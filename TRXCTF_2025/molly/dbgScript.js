

function initializeScript()
{
    host.diagnostics.debugLog("Invoking script \n");
}

function invokeScript()
{
    const control = host.namespace.Debugger.Utility.Control;

    control.ExecuteCommand('bp molly_dll+30a3 "r r9 = 0x40; g"')

}   