import "pe"

rule SUSP_PEDLL_ASP_WEBSHELL_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find .NET DLL ASP webshells."

        reference   = "https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/"

        DaysofYARA  = "24/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash        = "df79815b6fa50dfdd626be2d20a9e5d0741e4ceed4fd49da9f62ef4ecbc127a7"

    strings:
        $sa1    = "exec_code" wide
        $ha1    = { // Performance is for loosers.
            02      // IL_0012: ldarg.0
			6F[4]   // IL_0013: callvirt  instance class [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine [Microsoft.JScript]Microsoft.JScript.INeedEngine::GetEngine()
			28[4]   // IL_0018: call      instance class [Microsoft.JScript]Microsoft.JScript.ScriptObject [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine::ScriptObjectStackTop()
			74[4]   // IL_001D: castclass [Microsoft.JScript]Microsoft.JScript.StackFrame
			7B[4]   // IL_0022: ldfld     object[] [Microsoft.JScript]Microsoft.JScript.StackFrame::localVars
			26      // IL_0027: pop
			02      // IL_0028: ldarg.0
			28[4]   // IL_0029: call      instance class [System.Web]System.Web.HttpRequest [System.Web]System.Web.UI.Page::get_Request()
			72[4]   // IL_002E: ldstr     "exec_code"
			28[4]   // IL_0033: call      instance string [System.Web]System.Web.HttpRequest::get_Item(string)
			02      // IL_0038: ldarg.0
			6F[4]   // IL_0039: callvirt  instance class [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine [Microsoft.JScript]Microsoft.JScript.INeedEngine::GetEngine()
			28[4]   // IL_003E: call      object [Microsoft.JScript]Microsoft.JScript.Eval::JScriptEvaluate(object, class [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine)
			26      // IL_0043: pop
			02      // IL_0044: ldarg.0
			6F[4]   // IL_0045: callvirt  instance class [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine [Microsoft.JScript]Microsoft.JScript.INeedEngine::GetEngine()
			28[4]   // IL_004A: call      instance class [Microsoft.JScript]Microsoft.JScript.ScriptObject [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine::ScriptObjectStackTop()
			74[4]   // IL_004F: castclass [Microsoft.JScript]Microsoft.JScript.StackFrame
			7B[4]   // IL_0054: ldfld     object[] [Microsoft.JScript]Microsoft.JScript.StackFrame::localVars
			26      // IL_0059: pop
			02      // IL_005A: ldarg.0
			6F[4]   // IL_005B: callvirt  instance class [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine [Microsoft.JScript]Microsoft.JScript.INeedEngine::GetEngine()
			28[4]   // IL_0060: call      instance class [Microsoft.JScript]Microsoft.JScript.ScriptObject [Microsoft.JScript]Microsoft.JScript.Vsa.VsaEngine::ScriptObjectStackTop()
			74[4]   // IL_0065: castclass [Microsoft.JScript]Microsoft.JScript.StackFrame
			7B      // IL_006A: ldfld     object[] [Microsoft.JScript]
        }

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x10b
        and pe.characteristics & pe.DLL
        and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0
        and uint32be(
            pe.rva_to_offset(
                uint32(
                    pe.rva_to_offset(pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address) + 8
                )
            )
        ) == 0x42534a42
        and all of them
}
