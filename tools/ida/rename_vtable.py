import idaapi
import idautils
import idc
import struct

ACTION_NAME = "leoetlino:rename_vtable"

def do_rename(): # type: (...) -> None
    vtable_ea = idc.ScreenEA()
    class_name = idaapi.ask_str('', -1, 'Enter class name: ')
    if not class_name:
        return

    ea = vtable_ea
    i = 0
    while True:
        function_ea = struct.unpack('<Q', idaapi.get_many_bytes(ea, 8))[0]
        if not idaapi.is_func(idaapi.get_flags(function_ea)):
            break

        function_name = "%s::m%d" % (class_name, i)
        if idc.GetFunctionName(function_ea).startswith('sub_'):
            idc.MakeNameEx(function_ea, function_name, idaapi.SN_NOWARN)
        i += 1

        ea += 8

class rename_vtable_ah_t(idaapi.action_handler_t):
    def activate(self, ctx): # type: (...) -> int
        do_rename()
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_DISABLE_FOR_WIDGET
        return idaapi.AST_ENABLE_FOR_WIDGET

def main(): # type: () -> None
    existing = idaapi.unregister_action(ACTION_NAME)
    idaapi.register_action(
        idaapi.action_desc_t(ACTION_NAME, "Rename vtable", rename_vtable_ah_t(), "F10"))

if __name__ == '__main__':
    main()
