# Copyright 2018 leoetlino <leo@leolam.fr>
# Licensed under MIT

import ida_hexrays as hr
import idaapi
import idc
import struct
import typing

def rename_vtable_functions(names, vtable_ea, class_name): # type: (typing.Dict[int, str], int, str) -> None
    ea = vtable_ea
    i = 0
    while True:
        function_ea = struct.unpack('<Q', idaapi.get_many_bytes(ea, 8))[0]
        if '__cxa_pure_virtual' not in idc.GetDisasm(function_ea) and not idaapi.is_func(idaapi.get_flags(function_ea)):
            break

        member_fn_name = names.get(i, "m%d" % i)
        function_name = "%s::%s" % (class_name, member_fn_name)
        current_name = idc.GetFunctionName(function_ea)
        if current_name.startswith('nullsub_'):
            idc.MakeNameEx(function_ea, function_name + '_null', idaapi.SN_NOWARN)
        elif current_name.startswith('sub_') or \
            current_name.startswith("%s::m%d" % (class_name, i)) or \
            "runtimetypeinfo" in current_name.lower():
            idc.MakeNameEx(function_ea, function_name, idaapi.SN_NOWARN)
        i += 1
        ea += 8

def get_string(ea):
    # idaapi.get_strlit_contents is bugged on 7.0 (-1 does not work for the length parameter),
    # so use idc.GetString instead.
    return idc.GetString(ea)

def my_cexpr_t(*args, **kwargs):
    """Replacement of bugged cexpr_t() function (from HexRaysPyTools)"""

    if len(args) == 0:
        return idaapi.cexpr_t()

    if len(args) != 1:
        raise NotImplementedError

    cexpr = idaapi.cexpr_t()
    cexpr.thisown = False
    if type(args[0]) == idaapi.cexpr_t:
        cexpr.assign(args[0])
    else:
        op = args[0]
        cexpr._set_op(op)

        if 'x' in kwargs:
            cexpr._set_x(kwargs['x'])
        if 'y' in kwargs:
            cexpr._set_y(kwargs['y'])
        if 'z' in kwargs:
            cexpr._set_z(kwargs['z'])
    return cexpr

def unwrap_cast(c): # type: (hr.citem_t) -> hr.citem_t
    """Return c or the casted expression if c is a cast."""
    if c.op == hr.cot_cast:
        return c.x
    return c

def make_helper_call(ret_type, name, arg_types): # type: (str, str, typing.List[str]) -> hr.cexpr_t
    """Make a call expression to a helper function (non-existing function with arbitrary name)."""

    helper_expr = hr.cexpr_t()
    helper_expr.ea = idaapi.BADADDR
    helper_expr.op = hr.cot_helper
    helper_expr.helper = name

    call_expr = hr.cexpr_t()
    call_expr.op = hr.cot_call
    call_expr.x = helper_expr
    call_expr.a = hr.carglist_t()

    # EXTREMELY IMPORTANT: set the expression types. Without this, Hex-Rays will crash
    # in mysterious ways.
    t = idaapi.tinfo_t()
    idaapi.parse_decl2(idaapi.cvar.idati, "%s (__cdecl *)(%s);" % (ret_type, ','.join(arg_types)),
                       t, idaapi.PT_TYP)
    helper_expr.type = t
    call_expr.a.functype = t
    call_expr.type = t.get_rettype()

    return call_expr

def make_carg_t(cexpr): # type: (hr.cexpr_t) -> hr.carg_t
    arg = hr.carg_t()
    arg.assign(cexpr)
    return arg

def replace_expr_with(target, new_item): # type: (hr.cexpr_t, hr.cexpr_t) -> None
    """Replace target with new_item. Note: new_item is deleted after a call to this function."""
    new_item.ea = target.ea
    target.cleanup()
    target.replace_by(new_item)

def is_variable(c, vidx):
    return c.op == hr.cot_var and c.v.idx == vidx

def is_number(c, n):
    return c.op == hr.cot_num and c.n._value == n


class DebugVisitor(hr.ctree_parentee_t):
    """A visitor that just prints information about the ctree."""
    def visit(self, tree, parent): # type: (...) -> None
        hr.ctree_parentee_t.apply_to(self, tree, parent)

    def visit_insn(self, c): # type: (...) -> int
        print("DEBUG: insn 0x%016lx: %s" % (c.ea, c.opname))
        return 0
    def visit_expr(self, c): # type: (...) -> int
        print("DEBUG: expr 0x%016lx: %s - type: %s" % (c.ea, c.opname, str(c.type)))
        if c.op == hr.cot_call:
            print("  a.functype: %s" % (str(c.a.functype)))
            print("  x.ea: 0x%016lx - x.type: %s - x.op: %s" % (c.x.ea, str(c.x.type), c.x.opname))
            for i, a in enumerate(c.a):
                print("  arg[%d]: ea: 0x%016lx - type: %s - op: %s" % (i, a.ea, str(a.type), a.opname))
        return 0

class CleanupVisitor(hr.ctree_parentee_t):
    """A visitor that cleans up the ctree by removing cit_empty items."""
    def clean_up(self, tree, parent): # type: (...) -> None
        hr.ctree_parentee_t.apply_to(self, tree, parent)

    def visit_insn(self, c): # type: (...) -> int
        if c.op == hr.cit_block:
            # This is pretty inefficient, but unfortunately we cannot traverse the list
            # and call erase() at the same time.
            # Manually traversing the list with begin(), end() and next() is bugged and throws
            # us in an infinite loop.
            # Trying to mutate the list while iterating over it is a sure way to cause crashes.
            to_delete = []
            for ins in c.cblock:
                if ins.op == hr.cit_empty:
                    to_delete.append(ins)
            for ins in to_delete:
                c.cblock.remove(ins)
        return 0


class ConstraintChecker:
    def __init__(self, fn, optional=False): # type: (...) -> None
        self.fn = fn # type: typing.Callable[[typing.Any, ConstraintVisitor], bool]
        self.optional = optional # type: bool

Constraints = typing.List[ConstraintChecker]
MatchedItems = typing.List[hr.citem_t]
OnMatchCallable = typing.Callable[[MatchedItems], None]

class ConstraintVisitor(hr.ctree_visitor_t):
    """A visitor that checks whether all of the specified constraints are satisfied."""
    def __init__(self, constraints, context_string): # type: (Constraints, str) -> None
        hr.ctree_visitor_t.__init__(self, hr.CV_PARENTS)
        self._constraints = constraints # type: Constraints
        self._temp_constraints = [] # type: Constraints
        self._satisfied_count = 0 # type: int
        self._context_string = context_string
        self._matched_items = [] # type: MatchedItems
        self._on_match = None # type: typing.Optional[OnMatchCallable]

    def add_temp_constraints(self, constraints): # type: (Constraints) -> None
        """Add temporary constraints that will only apply for the current match."""
        self._temp_constraints.extend(constraints)

    def _get_constraint_by_index(self, i): # type: (int) -> ConstraintChecker
        if i < len(self._constraints):
            return self._constraints[i]
        return self._temp_constraints[i - len(self._constraints)]

    def _get_next_constraint(self): # type: () -> typing.Tuple[int, ConstraintChecker]
        return (self._satisfied_count, self._get_constraint_by_index(self._satisfied_count))

    def _get_next_mandatory_constraint(self): # type: () -> typing.Tuple[int, ConstraintChecker]
        i = self._satisfied_count
        checker = self._get_constraint_by_index(i)
        while checker.optional:
            i += 1
            checker = self._get_constraint_by_index(i)
        return (i, checker)

    def _get_constraint_count(self): # type: () -> int
        return len(self._constraints) + len(self._temp_constraints)

    def _reset_match_state(self): # type: () -> None
        del self._temp_constraints[:]
        del self._matched_items[:]
        self._satisfied_count = 0

    def check(self, tree, parent): # type: (...) -> bool
        """Returns true if the pattern was matched."""
        self._reset_match_state()
        self._on_match = None
        hr.ctree_visitor_t.apply_to(self, tree, parent)
        return self._satisfied_count == self._get_constraint_count()

    def match(self, tree, parent, on_match): # type: (hr.citem_t, hr.citem_t, OnMatchCallable) -> None
        """Calls on_match every time the pattern is matched."""
        self._reset_match_state()
        self._on_match = on_match
        hr.ctree_visitor_t.apply_to(self, tree, parent)

    def _handle_match(self, c, parent, i, checker): # type: (...) -> int
        if c.op >= hr.cit_empty or not parent:
            self._matched_items.append(c)
        else:
            self._matched_items.append(parent)

        self._satisfied_count = i + 1
        hr.ctree_visitor_t.prune_now(self)
        # Continue until we have matched everything.
        if self._satisfied_count < self._get_constraint_count():
            return 0

        print("match for %s (end: 0x%016lx)" % (self._context_string, c.ea))
        if self._on_match:
            # We have a match. Call the user callback and reset state.
            self._on_match(self._matched_items)
            self._reset_match_state()
            return 0
        return 1

    def _visit(self, c): # type: (...) -> int
        citem = self.parents.back()
        parent = citem.to_specific_type if citem else None

        i, checker = self._get_next_mandatory_constraint()
        if checker.fn(c, self):
            return self._handle_match(c, parent, i, checker)

        i2, checker = self._get_next_constraint()
        if i != i2 and checker.fn(c, self):
            return self._handle_match(c, parent, i2, checker)

        # Mismatch.
        # If we haven't started matching anything yet, just continue.
        if self._satisfied_count == 0:
            return 0

        print("mismatch at 0x%016lx: %s [wants: %s.%s]" % (c.ea, c.opname, self._context_string,
                                                           checker.fn.__name__))
        self._reset_match_state()
        return 0

    def visit_insn(self, c): # type: (...) -> int
        if c.op == hr.cit_expr:
            return 0
        return self._visit(c)

    def visit_expr(self, c): # type: (...) -> int
        return self._visit(c)
