import idaapi
import idautils
import idc
import sys

try:
    del sys.modules['hexrays_utils']
except: pass
from hexrays_utils import *

ACTION_NAME = "leoetlino:rename_vtable"

def do_rename(): # type: (...) -> None
    vtable_ea = idc.ScreenEA()
    class_name = idaapi.ask_str('', -1, 'Enter class name: ')
    if class_name:
        rename_vtable_functions(dict(), vtable_ea, class_name)

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
