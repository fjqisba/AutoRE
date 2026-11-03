// SPDX-License-Identifier: Apache-2.0
//! 保留原生位值，包括上游拼写 explict / volatil；不重新编号。
macro_rules! flags {
    ($name:ident, $bits:ty, {$($flag:ident = $value:expr),* $(,)?}) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name(pub $bits);
        #[allow(non_upper_case_globals)]
        impl $name {
            $(pub const $flag: Self = Self($value);)*
            pub const fn contains(self, other: Self) -> bool { self.0 & other.0 == other.0 }
            pub const fn intersects(self, other: Self) -> bool { self.0 & other.0 != 0 }
            pub fn set(&mut self, other: Self) { self.0 |= other.0; }
            pub fn remove(&mut self, other: Self) { self.0 &= !other.0; }
        }
        impl std::ops::BitOr for $name { type Output = Self; fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) } }
    }
}
flags!(VarnodeFlags, u32, {
    mark=0x1, constant=0x2, annotation=0x4, input=0x8, written=0x10, insert=0x20,
    implied=0x40, explict=0x80, typelock=0x100, namelock=0x200, nolocalalias=0x400, volatil=0x800,
    externref=0x1000, readonly=0x2000, persist=0x4000, addrtied=0x8000, unaffected=0x10000,
    spacebase=0x20000, indirectonly=0x40000, directwrite=0x80000, addrforce=0x100000, mapped=0x200000,
    indirect_creation=0x400000, return_address=0x800000, coverdirty=0x1000000, precislo=0x2000000,
    precishi=0x4000000, indirectstorage=0x8000000, hiddenretparm=0x10000000, incidental_copy=0x20000000,
    autolive_hold=0x40000000, proto_partial=0x80000000
});
flags!(VarnodeAdditionalFlags, u16, {
    activeheritage=0x1, writemask=0x2, vacconsume=0x4, lisconsume=0x8, ptrcheck=0x10, ptrflow=0x20,
    unsignedprint=0x40, longprint=0x80, stack_store=0x100, locked_input=0x200, spacebase_placeholder=0x400,
    stop_uppropagation=0x800, has_implied_field=0x1000
});
flags!(OpFlags, u32, {
    startbasic=0x1, branch=0x2, call=0x4, returns=0x8, nocollapse=0x10, dead=0x20, marker=0x40,
    booloutput=0x80, boolean_flip=0x100, fallthru_true=0x200, indirect_source=0x400, coderef=0x800,
    startmark=0x1000, mark=0x2000, commutative=0x4000, unary=0x8000, binary=0x10000, special=0x20000,
    ternary=0x40000, return_copy=0x80000, nonprinting=0x100000, halt=0x200000, badinstruction=0x400000,
    unimplemented=0x800000, noreturn=0x1000000, missing=0x2000000, spacebase_ptr=0x4000000,
    indirect_creation=0x8000000, calculated_bool=0x10000000, has_callspec=0x20000000, ptrflow=0x40000000,
    indirect_store=0x80000000
});
flags!(OpAdditionalFlags, u32, {
    special_prop=1, special_print=2, modified=4, warning=8, incidental_copy=0x10,
    is_cpool_transformed=0x20, stop_type_propagation=0x40, hold_output=0x80, concat_root=0x100,
    no_indirect_collapse=0x200, store_unmapped=0x400
});
flags!(BlockFlags, u32, {
    f_goto_goto=1, f_break_goto=2, f_continue_goto=4, f_switch_out=0x10, f_unstructured_targ=0x20,
    f_mark=0x80, f_mark2=0x100, f_entry_point=0x200, f_interior_gotoout=0x400, f_interior_gotoin=0x800,
    f_label_bumpup=0x1000, f_donothing_loop=0x2000, f_dead=0x4000, f_whiledo_overflow=0x8000,
    f_flip_path=0x10000, f_joined_block=0x20000, f_duplicate_block=0x40000
});
flags!(EdgeFlags, u32, {
    f_goto_edge=1, f_loop_edge=2, f_defaultswitch_edge=4, f_irreducible=8, f_tree_edge=0x10,
    f_forward_edge=0x20, f_cross_edge=0x40, f_back_edge=0x80, f_loop_exit_edge=0x100
});
