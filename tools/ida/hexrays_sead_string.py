# Copyright 2018 leoetlino <leo@leolam.fr>
# Licensed under MIT

"""A script to identify common inlined sead::SafeString functions
and replace them with more readable output.
"""

import ida_hexrays as hr
import ida_kernwin
import idaapi
import idc
import typing
import sys

try:
    del sys.modules['hexrays_utils']
except: pass
from hexrays_utils import *

ACTION_NAME = "leoetlino:seadstring"
SAFESTRINGBASE_VTABLE_STRUCT_NAME = "sead::SafeStringBase::vtable"


def is_safestring_struct_name(name):
    return name == "sead::SafeString" or "sead::SafeStringBase<char>"

def is_sead_safestringbase_null_char(c, cfunc): # type: (...) -> bool
    c = unwrap_cast(c)
    if c.op == hr.cot_var and cfunc:
        return "zero_" in cfunc.get_lvars()[c.v.idx].name
    if c.op != hr.cot_obj:
        return c.is_zero_const()
    return idaapi.get_byte(c.obj_ea) == 0

def get_safestring_from_cstr_access(c): # type: (hr.cexpr_t) -> typing.Optional[hr.cexpr_t]
    """Returns the SafeString item from a 'ANY = string.cstr' assignment expression."""

    if c.op != hr.cot_asg:
        return None

    rhs = unwrap_cast(c.y)
    if rhs.op == hr.cot_memptr or rhs.op == hr.cot_memref:
        # rhs: [x: string, m: cstr (0x8)]
        if rhs.m != 0x8:
            return None

        pointed_type = rhs.x.type.get_pointed_object()
        if not pointed_type or not is_safestring_struct_name(pointed_type.get_type_name()):
            return None

        return rhs.x

    elif rhs.op == hr.cot_ptr:
        # VAR = *(const char **)(a2 + 0x80);
        if rhs.x.op != hr.cot_cast:
            return None

        expr = rhs.x.x
        if expr.op != hr.cot_add:
            return None

        if expr.y.op != hr.cot_num:
            return None
        if expr.y.n._value < 0x8:
            return None

        str_expr = my_cexpr_t(expr)
        str_expr.y.n._value -= 0x8
        return str_expr

    elif rhs.op == hr.cot_idx:
        # VAR = string[1];
        if rhs.y.op != hr.cot_num or rhs.y.n._value == 0:
            return None
        if rhs.y.n._value == 1:
            return rhs.x
        expr = my_cexpr_t(rhs)
        expr.y.n._value -= 1
        return expr

    return None

def get_safestring_from_assuretermination_call(c): # type: (hr.cexpr_t) -> typing.Optional[hr.cexpr_t]
    """Returns the SafeString item from a 'string.vptr->assureTermination()' call expression."""
    if c.op != hr.cot_call:
        return None
    if c.a.size() != 1:
        return None
    # if we have a struct...
    if c.x.op == hr.cot_memptr:
        # vtable_deref: [x: string->vtable, m: assureTermination (0x18)]
        vtable_deref = c.x
        if vtable_deref.m != 0x18:
            return None
        # string_deref: [x: string, m: vtable (0x0)]
        string_deref = vtable_deref.x
        if (string_deref.op != hr.cot_memptr and string_deref.op != hr.cot_memref) or string_deref.m != 0:
            return None
        # Check whether vtable is a string vtable.
        pointed_type = string_deref.type.get_pointed_object()
        if not pointed_type or pointed_type.get_type_name() != SAFESTRINGBASE_VTABLE_STRUCT_NAME:
            return None

        return c.a[0].to_specific_type

    # no struct: (*cast<assureTerminationFn>(*cast<string_vt*>(string) + 0x18LL))(string);
    elif c.x.op == hr.cot_ptr:
        # *cast<assureTerminationFn>(...)
        deref = c.x.x
        if deref.op != hr.cot_cast:
            return None

        # fun_pointer: *cast<string_vt*>(string) + 0x18LL
        #               ^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^
        #               fun_pointer.x.x            fun_pointer.y
        fun_pointer = deref.x
        if fun_pointer.op != hr.cot_add or not is_number(fun_pointer.y, 0x18):
            return None

        return c.a[0].to_specific_type

    return None

class Transformer:
    def run(self, vu, tree, parent): # type: (...) -> None
        raise NotImplementedError()

class StringCtorTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            string_vidx = int()

        def is_string_vtable_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False

            lhs = c.x
            if lhs.op != hr.cot_var:
                return False
            pointed_type = lhs.type.get_pointed_object()
            if not pointed_type or pointed_type.get_type_name() != SAFESTRINGBASE_VTABLE_STRUCT_NAME:
                return False

            rhs = c.y
            if rhs.op != hr.cot_ref:
                return False
            if rhs.x.op != hr.cot_obj:
                return False

            ctx.string_vidx = lhs.v.idx
            return True

        cv = ConstraintVisitor([ConstraintChecker(is_string_vtable_assignment)], "ctor")
        variables = [] # type: typing.List[int]
        cv.match(tree, parent, lambda l: variables.append(ctx.string_vidx))
        t = idaapi.tinfo_t()
        idaapi.parse_decl2(idaapi.cvar.idati, "sead::SafeString;", t, idaapi.PT_TYP)
        for vidx in variables:
            vu.set_lvar_type(vu.cfunc.get_lvars()[vidx], t)

class StringStartsWithTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            first_chr = ''
            this_string_item = None
            other_string_item = None

        def has_first_char_check(c, p): # type: (...) -> bool
            if c.op != hr.cit_if:
                return False
            if c.cif.expr.op != hr.cot_eq:
                return False
            lhs = c.cif.expr.x
            rhs = c.cif.expr.y
            if not is_sead_safestringbase_null_char(lhs, vu.cfunc) or rhs.op != hr.cot_num:
                return False
            ctx.first_chr = chr(rhs.n._value)

            if not c.cif.ielse:
                if c.cif.ithen.op != hr.cit_block:
                    return False

                last_item_in_then = c.cif.ithen.cblock.back()
                if last_item_in_then.op != hr.cit_goto:
                    return False

            # There is only one reference to a string variable. Try to find it: &stringVariable
            def has_while(c, p): # type: (...) -> bool
                if c.op != hr.cit_while:
                    return False
                if c.cwhile.expr.op != hr.cot_eq:
                    return False
                lhs = c.cwhile.expr.x
                if lhs.op != hr.cot_idx and lhs.op != hr.cot_ptr:
                    return False
                ctx.this_string_item = my_cexpr_t(lhs.x)
                return True

            def has_string(c, p): # type: (...) -> bool
                if c.op != hr.cot_ref:
                    return False
                ref = c.x
                if ref.op == hr.cot_idx:
                    ref = ref.x
                if ref.op != hr.cot_obj:
                    return False
                if not idaapi.is_strlit(idaapi.get_flags(ref.obj_ea)):
                    return False
                string = get_string(ref.obj_ea)
                ctx.other_string_item = my_cexpr_t(ref)
                return string[0] == ctx.first_chr

            if c.cif.ielse:
                # Sometimes the string ref is inside the loop, and sometimes right before it.
                # Since the whole thing is inside an else block, we just need to check whether
                # both are present (since we will remove the entire block afterwards).
                cv = ConstraintVisitor([ConstraintChecker(has_string)], "compare.2a")
                if not cv.check(c.cif.ielse, c):
                    return False
                cv = ConstraintVisitor([ConstraintChecker(has_while)], "compare.2b")
                if not cv.check(c.cif.ielse, c):
                    return False
            else:
                def has_string_assignment(c, p): # type: (...) -> bool
                    if c.op != hr.cot_asg:
                        return False
                    if c.x.op != hr.cot_var:
                        return False
                    return has_string(c.y, p)

                def has_first_char_assignment(c, p): # type: (...) -> bool
                    if c.op != hr.cot_asg:
                        return False
                    if c.x.op != hr.cot_var:
                        return False
                    if not is_number(c.y, ord(ctx.first_chr)):
                        return False
                    return True

                def has_optional_assignment(c, p): # type: (...) -> bool
                    if has_first_char_assignment(c, p):
                        return False
                    return c.op == hr.cot_asg

                p.add_temp_constraints([
                    # v1 = STRING_REF
                    ConstraintChecker(has_string_assignment),
                    # ANY = ANY (optional)
                    ConstraintChecker(has_optional_assignment, optional=True),
                    # v2 = FIRST_CHAR
                    ConstraintChecker(has_first_char_assignment),
                    # while
                    ConstraintChecker(has_while),
                ])
            return True

        cv = ConstraintVisitor([
            # if (sead::SafeStringBase<char>::cNullChar == 'FIRST_CHAR') { ... } else { STRING_REF }
            # or
            # if (sead::SafeStringBase<char>::cNullChar == 'FIRST_CHAR') { goto } STRING_REF
            ConstraintChecker(has_first_char_check),
        ], "compare")
        cv.match(tree, parent, lambda l: self._on_match(ctx, l))

    def _on_match(self, ctx, matched_items):  # type: (...) -> None
        cif = matched_items[0].cif

        eq = make_helper_call("bool", "stringStartsWith", ["const char* lhs", "const char* rhs"])
        eq.a.push_back(make_carg_t(ctx.this_string_item))
        eq.a.push_back(make_carg_t(ctx.other_string_item))
        replace_expr_with(cif.expr, eq)

        if cif.ielse:
            cif.ielse.cleanup()
            cif.ielse = None
        else:
            for item in matched_items[1:]:
                item.cleanup()


class StringEqualsTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            items_to_delete = [] # type: list
            this_string_item = None
            constant_item = None

        def has_if(c, p): # type: (...) -> bool
            if c.op != hr.cit_if:
                return False
            lhs = c.cif.expr.x
            rhs = c.cif.expr.y
            if not rhs or rhs.op != hr.cot_obj:
                return False
            if not idaapi.is_strlit(idaapi.get_flags(rhs.obj_ea)):
                return False
            ctx.this_string_item = my_cexpr_t(lhs)
            ctx.constant_item = my_cexpr_t(rhs)

            # Match the if body (in an extremely approximate way)
            def has_counter(c, p): # type: (...) -> bool
                if c.op != hr.cot_asg:
                    return False
                if c.x.op != hr.cot_var or not is_number(c.y, 0):
                    return False
                ctx.items_to_delete.append(vu.cfunc.body.find_parent_of(c).to_specific_type)
                return True

            def has_do_while(c, p): # type: (...) -> bool
                if c.op != hr.cit_do:
                    return False
                # don't bother matching the loop body -- just match the condition expression
                if c.cdo.expr.op != hr.cot_sle and c.cdo.expr.op != hr.cot_ule:
                    return False
                if c.cdo.expr.x.op != hr.cot_var or not is_number(c.cdo.expr.y, 0x80000):
                    return False
                ctx.items_to_delete.append(c)
                return True

            return ConstraintVisitor([
                ConstraintChecker(has_counter),
                ConstraintChecker(has_do_while),
            ], "equals.inner").check(c.cif.ithen, c)

        cv = ConstraintVisitor([ConstraintChecker(has_if)], "equals")
        cv.match(tree, parent, lambda l: self._on_match(ctx, l))

    def _on_match(self, ctx, matched_items):  # type: (...) -> None
        cif = matched_items[0].cif

        eq = make_helper_call("bool", "stringNotEquals", ["const char* lhs", "const char* rhs"])
        eq.a.push_back(make_carg_t(ctx.this_string_item))
        eq.a.push_back(make_carg_t(ctx.constant_item))
        replace_expr_with(cif.expr, eq)

        for item in ctx.items_to_delete:
            item.cleanup()


class StringAssignTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            src_str_item = None
            dst_str_item = None

            length_vidx = None # type: typing.Optional[int]
            src_cstr_vidx = None # type: typing.Optional[int]
            dst_cstr_vidx = None # type: typing.Optional[int]

        def has_dst_cstr_variable(c, p): # type: (...) -> bool
            ctx.dst_str_item = get_safestring_from_cstr_access(c)
            if not ctx.dst_str_item:
                return False

            if c.x.op != hr.cot_var:
                return False

            ctx.dst_cstr_vidx = c.x.v.idx
            return True

        def has_assure_termination_call(c, p): # type: (...) -> bool
            src_safestring = get_safestring_from_assuretermination_call(c)
            if not src_safestring:
                return False

            # Create a copy.
            ctx.src_str_item = my_cexpr_t(src_safestring)
            return True

        def has_src_cstr_variable(c, p): # type: (...) -> bool
            if not get_safestring_from_cstr_access(c):
                return False

            lhs = c.x
            if lhs.op != hr.cot_var:
                return False

            ctx.src_cstr_vidx = lhs.v.idx
            return True

        def has_part_2(c, p): # type: (...) -> bool
            if c.op != hr.cit_if:
                return False

            lhs = c.cif.expr.x
            rhs = c.cif.expr.y
            if not is_variable(lhs, ctx.dst_cstr_vidx): # or not is_variable(rhs, ctx.src_cstr_vidx):
                return False

            # First variant: if (dst_cstr == src_str) { return ANY; } part2()
            # or
            # if (dst_cstr == src_str) { X } else { part2() }
            if c.cif.expr.op == hr.cot_eq:
                if c.cif.ielse:
                    if_cv = ConstraintVisitor(self._get_part_2_checks(ctx, vu), "assign.part2")
                    if not if_cv.check(c.cif.ielse, c):
                        return False
                    return True

                def has_return(c, p):
                    return c.op == hr.cit_return
                if_cv = ConstraintVisitor([ConstraintChecker(has_return)], "assign.part2")
                if not if_cv.check(c.cif.ithen, c):
                    return False
                p.add_temp_constraints(self._get_part_2_checks(ctx, vu))
                return True

            # Second variant: if (dst_cstr != src_str) { part2() }
            if c.cif.expr.op != hr.cot_ne:
                return False
            if_cv = ConstraintVisitor(self._get_part_2_checks(ctx, vu), "assign.part2")
            return if_cv.check(c.cif.ithen, c)

        # Not a very strict matcher to avoid complications with variable types.
        cv = ConstraintVisitor([
            # dst_cstr = dst_str.cstr; OR dst_str->cstr
            ConstraintChecker(has_dst_cstr_variable),
            # [optional assignment]
            ConstraintChecker(lambda c, p: c.op == hr.cot_asg, optional=True),
            # src_str->vptr->assureTermination(src_str);
            ConstraintChecker(has_assure_termination_call),
            # src_cstr = src_str.cstr; OR src_str->cstr;
            ConstraintChecker(has_src_cstr_variable),
            # Part 2 checks
            ConstraintChecker(has_part_2),
        ], "assign")

        cv.match(tree, parent, lambda l: self._on_match_replace_with_helper(ctx, l))

    def _on_match_replace_with_helper(self, ctx, items_to_remove): # type: (...) -> None
        for item in items_to_remove[1:]:
            item.cleanup()

        helper_call = make_helper_call("void", "sead::SafeString::operator=", [
            "sead::SafeString* this",
            "const sead::SafeString& src",
        ])
        helper_call.a.push_back(make_carg_t(ctx.dst_str_item))
        helper_call.a.push_back(make_carg_t(ctx.src_str_item))

        replace_expr_with(items_to_remove[0].cexpr, helper_call)

    def _get_part_2_checks(self, ctx, vu): # type: (...) -> Constraints
        def has_src_string_assure_termination(c, p): # type: (...) -> bool
            if not get_safestring_from_assuretermination_call(c):
                return False
            return True

        def has_index_variable(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            if c.x.op != hr.cot_var or not is_number(c.y, 0):
                return False
            ctx.length_vidx = c.x.v.idx
            return True

        def has_cstr_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            if c.x.op != hr.cot_var or c.y.op != hr.cot_add:
                return False
            if not is_number(c.y.y, 1):
                return False
            return True

        def has_while_loop(c, p): # type: (...) -> bool
            if c.op != hr.cit_while:
                return False

            if not is_sead_safestringbase_null_char(c.cwhile.expr.y, vu.cfunc):
                return False

            # Now match the loop body.
            def is_nullchar_check(c):
                if c.op != hr.cit_if or c.cif.expr.op != hr.cot_eq:
                    return False
                if not is_sead_safestringbase_null_char(c.cif.expr.y, vu.cfunc):
                    return False
                return True

            def has_first_nullchar_check(c, p): # type: (...) -> bool
                return is_nullchar_check(c)

            def has_second_nullchar_check(c, p): # type: (...) -> bool
                return is_nullchar_check(c)

            def has_assignment_plus_two(c, p): # type: (...) -> bool
                if c.op != hr.cot_asg:
                    return False
                rhs = c.y
                if rhs.op != hr.cot_add:
                    return False
                return is_variable(rhs.x, ctx.length_vidx) and is_number(rhs.y, 2)

            def has_index_incremented_by_3(c, p): # type: (...) -> bool
                if c.op != hr.cot_asgadd:
                    return False
                return is_variable(c.x, ctx.length_vidx) and is_number(c.y, 3)

            def has_length_check(c, p): # type: (...) -> bool
                if c.op != hr.cit_if or (c.cif.expr.op != hr.cot_sge and c.cif.expr.op == hr.cot_uge):
                    return False
                rhs = unwrap_cast(c.cif.expr.y)
                return is_number(rhs, 0x80000)

            cv = ConstraintVisitor([
                # if (ANY[len] == sead::SafeStringBase<char>::cNullChar)
                ConstraintChecker(has_first_nullchar_check),
                # if (ANY[len + 1] == sead::SafeStringBase<char>::cNullChar)
                ConstraintChecker(has_second_nullchar_check),
                # ANY = len + 2
                ConstraintChecker(has_assignment_plus_two),
                # len += 3
                ConstraintChecker(has_index_incremented_by_3),
                # if (ANY >= 0x80000)
                ConstraintChecker(has_length_check),
            ], "assign.part2.has_while_loop")
            return cv.check(c.cwhile.body, c)

        def has_if(c, p): # type: (...) -> bool
            if c.op != hr.cit_if or (c.cif.expr.op != hr.cot_sge and c.cif.expr.op == hr.cot_uge):
                return False
            lhs = unwrap_cast(c.cif.expr.x)
            return is_variable(lhs, ctx.length_vidx)

        def has_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg or c.x.op != hr.cot_var:
                return False
            rhs = unwrap_cast(c.y)
            return is_variable(rhs, ctx.length_vidx)

        def has_memcpy(c, p): # type: (...) -> bool
            if c.op != hr.cot_call:
                return False
            if c.a.size() != 3:
                return False
            length_arg = unwrap_cast(c.a[2])
            if length_arg.op != hr.cot_var:
                return False
            if length_arg.v.idx != ctx.length_vidx:
                return False
            return idaapi.get_func_name(c.x.obj_ea).startswith("memcpy")

        def writes_null_char(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            if c.x.op != hr.cot_idx and c.x.op != hr.cot_ptr:
                return False
            if not is_sead_safestringbase_null_char(c.y, vu.cfunc):
                return False
            return True

        return [
            # src_string->vptr->assureTermination(src_string)
            ConstraintChecker(has_src_string_assure_termination),
            # [optional assignment]
            ConstraintChecker(lambda c, p: c.op == hr.cot_asg and is_sead_safestringbase_null_char(c.y, vu.cfunc), optional=True),
            # len = 0
            ConstraintChecker(has_index_variable),
            # ANY = cstr + 1
            ConstraintChecker(has_cstr_assignment),
            # while (ANY != sead::SafeStringBase<char>::cNullChar)
            ConstraintChecker(has_while_loop),
            # ANY = ANY [skipped]
            ConstraintChecker(lambda c, p: c.op == hr.cot_asg, optional=True),
            # if (len >= ANY)
            ConstraintChecker(has_if),
            # ANY = len
            ConstraintChecker(has_assignment, optional=True),
            # memcpy_0(dst_cstr, src_cstr, len)
            ConstraintChecker(has_memcpy),
            # dst_cstr[ANY] = sead::SafeStringBase<char>::cNullChar
            ConstraintChecker(writes_null_char),
        ]


class StringAssignConstantTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            dst_str_item = None
            dst_cstr_vidx = None # type: typing.Optional[int]
            constant_item = None
            length_vidx = None # type: typing.Optional[int]

        def has_dst_cstr_variable(c, p): # type: (...) -> bool
            ctx.dst_str_item = get_safestring_from_cstr_access(c)
            if not ctx.dst_str_item:
                return False

            if c.x.op != hr.cot_var:
                return False

            ctx.dst_cstr_vidx = c.x.v.idx
            return True

        def has_part_2(c, p): # type: (...) -> bool
            if c.op != hr.cit_if:
                return False

            if c.cif.ielse or c.cif.expr.op != hr.cot_ne:
                return False

            lhs = c.cif.expr.x
            rhs = c.cif.expr.y
            if not is_variable(lhs, ctx.dst_cstr_vidx) or rhs.op != hr.cot_obj:
                return False

            if not idaapi.is_strlit(idaapi.get_flags(rhs.obj_ea)):
                return False
            ctx.constant_item = my_cexpr_t(rhs)

            if_cv = ConstraintVisitor(self._get_part_2_checks(ctx, vu), "assign_const.part2")
            return if_cv.check(c.cif.ithen, c)

        cv = ConstraintVisitor([
            # dst_cstr = dst_str.cstr; OR dst_str->cstr
            ConstraintChecker(has_dst_cstr_variable),
            # Part 2 checks
            ConstraintChecker(has_part_2),
        ], "assign_const")

        cv.match(tree, parent, lambda l: self._on_match_replace_with_helper(ctx, l))

    def _on_match_replace_with_helper(self, ctx, items_to_remove): # type: (...) -> None
        for item in items_to_remove[1:]:
            item.cleanup()

        helper_call = make_helper_call("void", "sead::BufferedSafeString::operator=", [
            "sead::SafeString* this",
            "const char* other",
        ])
        helper_call.a.push_back(make_carg_t(ctx.dst_str_item))
        helper_call.a.push_back(make_carg_t(ctx.constant_item))

        replace_expr_with(items_to_remove[0].cexpr, helper_call)

    def _get_part_2_checks(self, ctx, vu): # type: (...) -> Constraints
        def has_for_loop(c, p): # type: (...) -> bool
            if c.op != hr.cit_for:
                return False

            init_expr = c.cfor.init
            if init_expr.op != hr.cot_asg or not is_number(init_expr.y, 0):
                return False

            condition = c.cfor.expr
            if condition.op != hr.cot_ne or not is_sead_safestringbase_null_char(condition.y, vu.cfunc):
                return False
            # No need to bother with checking the post expression or the loop body.
            return True

        def has_length_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg or c.x.op != hr.cot_var:
                return False
            ctx.length_vidx = c.x.v.idx
            return True

        def has_if(c, p): # type: (...) -> bool
            if c.op != hr.cit_if or (c.cif.expr.op != hr.cot_sge and c.cif.expr.op == hr.cot_uge):
                return False
            rhs = unwrap_cast(c.cif.expr.y)
            return is_variable(rhs, ctx.length_vidx)

        def has_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg or c.x.op != hr.cot_var or unwrap_cast(c.y).op != hr.cot_var:
                return False
            return True

        def has_memcpy(c, p): # type: (...) -> bool
            if c.op != hr.cot_call:
                return False
            if c.a.size() != 3:
                return False
            length_arg = unwrap_cast(c.a[2])
            if length_arg.op != hr.cot_var:
                return False
            source_arg = unwrap_cast(c.a[1])
            if source_arg.op != hr.cot_obj:
                return False
            return idaapi.get_func_name(c.x.obj_ea).startswith("memcpy")

        def writes_null_char(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            if c.x.op != hr.cot_idx:
                return False
            if not is_sead_safestringbase_null_char(c.y, vu.cfunc):
                return False
            return True

        return [
            ConstraintChecker(has_for_loop),
            ConstraintChecker(has_length_assignment),
            ConstraintChecker(has_if),
            ConstraintChecker(has_assignment, optional=True),
            ConstraintChecker(has_memcpy),
            ConstraintChecker(writes_null_char),
        ]


class MemberFunctionRenamer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            function_ea = 0
            class_name = ""
            instance_ptr_ea = 0

        def recognise_call(c, p): # type: (...) -> bool
            if c.op != hr.cot_call:
                return False
            if c.a.size() < 1:
                return False

            function = c.x
            if function.op != hr.cot_obj:
                return False
            function_name = idaapi.get_name(function.obj_ea)
            if not function_name.startswith("sub_") and "__auto" not in function_name:
                return False

            first_arg = unwrap_cast(c.a[0])
            if first_arg.op != hr.cot_obj:
                return False
            name = idaapi.get_name(first_arg.obj_ea)
            if not name or "::sInstance" not in name:
                return False

            ctx.function_ea = function.obj_ea
            ctx.class_name = name.split("::sInstance")[0]
            ctx.instance_ptr_ea = first_arg.obj_ea
            return True

        cv = ConstraintVisitor([ConstraintChecker(recognise_call)], "member_fn_renamer")
        cv.match(tree, parent, lambda l: self._rename_function(ctx.function_ea, ctx.class_name, ctx.instance_ptr_ea))

    def _rename_function(self, function_ea, class_name, instance_ptr_ea): # type: (int, str, int) -> None
        i = 0
        function_name = "%s::__auto%d" % (class_name, i)
        while not idc.MakeNameEx(function_ea, function_name, idaapi.SN_NOWARN):
            i += 1
            function_name = "%s::__auto%d" % (class_name, i)

        func_tinfo = idaapi.tinfo_t()
        if not idaapi.get_tinfo2(function_ea, func_tinfo):
            return

        arg_tinfo = idaapi.tinfo_t()
        idaapi.get_tinfo2(instance_ptr_ea, arg_tinfo)

        func_data = idaapi.func_type_data_t()
        func_tinfo.get_func_details(func_data)
        func_data[0].type = arg_tinfo

        new_func_tinfo = idaapi.tinfo_t()
        new_func_tinfo.create_func(func_data)
        idaapi.apply_tinfo2(function_ea, new_func_tinfo, idaapi.TINFO_DEFINITE)


class DynamicCastTransformer(Transformer):
    def run(self, vu, tree, parent): # type: (...) -> None
        class ctx:
            dynamic_cast_var = None
            original_var = None
            type_info_obj = None

        def has_ldar_guard_variable(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            lhs = c.x
            rhs = c.y
            if lhs.op != hr.cot_var:
                return False
            if rhs.op != hr.cot_call:
                return False
            if rhs.x.op != hr.cot_helper or str(rhs.x.helper) != "__ldar":
                return False
            if rhs.a.size() != 1:
                return False
            return True

        def has_var_assignment(c, p): # type: (...) -> bool
            if c.op != hr.cot_asg:
                return False
            if c.x.op != hr.cot_var or unwrap_cast(c.y).op != hr.cot_var:
                return False
            ctx.dynamic_cast_var = my_cexpr_t(c.x)
            ctx.original_var = my_cexpr_t(c.y)
            return True

        def has_if(c, p): # type: (...) -> bool
            if c.op != hr.cit_if:
                return False
            expr = c.cif.expr
            if expr.op != hr.cot_land:
                return False

            lhs = expr.x # !( (u64)&`guard variable' & 1 )
            if lhs.op != hr.cot_lnot:
                return False
            negated_expr = lhs.x
            if negated_expr.op != hr.cot_band:
                return False
            if not is_number(negated_expr.y, 1):
                return False
            if negated_expr.x.op != hr.cot_cast:
                return False
            if negated_expr.x.x.op != hr.cot_ref:
                return False
            if negated_expr.x.x.x.op != hr.cot_obj:
                return False

            call = unwrap_cast(expr.y) # _cxa_guard_acquire_0(&`guard variable')
            if call.op != hr.cot_call:
                return False
            if call.a.size() != 1:
                return False
            if call.x.op != hr.cot_obj:
                return False
            if not idaapi.get_func_name(call.x.obj_ea).startswith("__cxa_guard_acquire"):
                return False

            if c.cif.ielse:
                return False

            # Check the if body.
            def has_assignment_to_rtti_var(c, p): # type: (...) -> bool
                if c.op != hr.cot_asg:
                    return False
                if c.x.op != hr.cot_obj:
                    return False
                if unwrap_cast(c.y).op != hr.cot_ref and unwrap_cast(c.y).op != hr.cot_obj:
                    return False
                ctx.type_info_obj = my_cexpr_t(c.x)
                return True

            def releases_guard_variable(c, p): # type: (...) -> bool
                if c.op != hr.cot_call:
                    return False
                if c.a.size() != 1:
                    return False
                if c.x.op != hr.cot_obj:
                    return False
                if not idaapi.get_func_name(c.x.obj_ea).startswith("__cxa_guard_release"):
                    return False
                return True

            return ConstraintVisitor([
                # sead::DirectResource::getRuntimeTypeInfoStatic(void)::typeInfo = (__int64)&off_71023588A0;
                ConstraintChecker(has_assignment_to_rtti_var),
                # _cxa_guard_release_0(&`guard variable');
                ConstraintChecker(releases_guard_variable),
            ], "dynamic_cast.if").check(c.cif.ithen, c)

        cv = ConstraintVisitor([
            # v7 = __ldar( (u8*)&`guard variable' );
            ConstraintChecker(has_ldar_guard_variable),
            # dynamic_cast_variable = original_variable;
            ConstraintChecker(has_var_assignment),
            # if (!( (u64)&`guard variable' & 1) && (u32)_cxa_guard_acquire_0(&`guard variable')
            ConstraintChecker(has_if),
        ], "dynamic_cast")

        self._types_to_set = [] # type: typing.List[typing.Tuple[int, idaapi.tinfo_t]]
        cv.match(tree, parent, lambda l: self._replace_with_check_helper(ctx, l))

        for vidx, typeinfo in self._types_to_set:
            vu.set_lvar_type(vu.cfunc.get_lvars()[vidx], typeinfo)

        # Setting variable types resets the ctree, so transform the ctree one more time,
        # but don't modify variables this time.
        cv.match(tree, parent, lambda l: self._replace_with_check_helper(ctx, l))

    def _replace_with_check_helper(self, ctx, l): # type: (...) -> None
        type_name_ea = ctx.type_info_obj.obj_ea
        name = idaapi.demangle_name(idaapi.get_name(type_name_ea), 0)
        if not name:
            name = idaapi.get_name(type_name_ea)

        type_name = name
        var_type = None
        if "::getRuntimeTypeInfoStatic(void)::typeInfo" in name:
            type_name = name.split("::getRuntimeTypeInfoStatic(void)::typeInfo")[0]
            var_type = idaapi.tinfo_t()
            idaapi.parse_decl2(idaapi.cvar.idati, type_name + "*;", var_type, idaapi.PT_TYP)
            if not str(var_type):
                var_type = None

        call_expr = make_helper_call("void*", "dynamic_cast<" + type_name + ">", ["void*"])
        call_expr.a.push_back(make_carg_t(ctx.original_var))

        asg_expr = hr.cexpr_t()
        asg_expr.op = hr.cot_asg
        asg_expr.x = hr.cexpr_t()
        asg_expr.x.assign(ctx.dynamic_cast_var)
        asg_expr.y = call_expr
        asg_expr.type = var_type if var_type else idaapi.tinfo_t(idaapi.BT_VOID)

        if var_type:
            self._types_to_set.append((ctx.dynamic_cast_var.v.idx, var_type))

        replace_expr_with(l[0].cexpr, asg_expr)
        for item in l[1:]:
            item.cleanup()

transformers = [
    StringCtorTransformer(),
    StringEqualsTransformer(),
    StringStartsWithTransformer(),
    StringAssignTransformer(),
    StringAssignConstantTransformer(),
    MemberFunctionRenamer(),
    # Before you get too excited, no, Nintendo uses a custom RTTI implementation
    # which does NOT include class names :/
    DynamicCastTransformer(),
]

class sead_string_ah_t(ida_kernwin.action_handler_t):
    def activate(self, ctx): # type: (...) -> int
        vu = hr.get_widget_vdui(ctx.widget)
        for t in transformers:
            t.run(vu, vu.cfunc.body, None)
            vu.cfunc.verify(1, True)
            vu.cfunc.remove_unused_labels()
        CleanupVisitor().clean_up(vu.cfunc.body, None)
        # DebugVisitor().visit(vu.cfunc.body, None)
        vu.refresh_ctext()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

def cb(event, *args):
    if event == hr.hxe_populating_popup:
        widget, phandle, vu = args
        res = idaapi.attach_action_to_popup(vu.ct, None, ACTION_NAME)
    return 0

def main(): # type: () -> None
    if hr.init_hexrays_plugin():
        existing = ida_kernwin.unregister_action(ACTION_NAME)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(ACTION_NAME, "sead::SafeString", sead_string_ah_t(), "F12"))
        if not existing:
            hr.install_hexrays_callback(cb)

if __name__ == '__main__':
    main()
