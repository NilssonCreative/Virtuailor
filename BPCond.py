# This is the breakpoint condition code.
# Every value inside the <<< >>> is an argument that will be replaced by "vtableAddress.py"
# The arguments are:
#    * start_addr -> The offset of the virtual call from the beginning of its segment
#    * register_vtable -> The register who points to the vtable
#    * offset -> The offset of the relevant function from the vtable base pointer


def get_fixed_name_for_object(address, prefix=""):
    """
    :param address: string, the object's address we want to calculate its offset
    :param prefix: string, a prefix for the object name
    :param suffix: string, a suffix for the object name
    :return: returns the new name of the object with calculated offset from the base addr -> "prefix + offset + suffix"
      !! In case the object (in this case function) doesn't starts with "sub_" the returned name will be the old name
    """
    v_func_name = idc.get_func_name(int(address))
    calc_func_name = int(address) - idc.get_segm_start(int(address))
    if v_func_name[:4] == "sub_":
        v_func_name =  prefix + str(calc_func_name)
    elif v_func_name == "":
        v_func_name =  prefix + str(calc_func_name) # The name will be the offset from the beginning of the segment
    return v_func_name

def get_vtable_and_vfunc_addr(is_brac, register_vtable, offset):
    """
    :param is_brac: number, if the call/ assignment is byRef the value is -1
    :param register_vtable: string, the register used in the virtual call
    :param offset: number, the offset of the function in the vtables used in on the bp opcode
    :return: return the addresses of the vtable and the virtual function from the relevant register
    """
    if is_brac == -1: # check it in both start addr and bp if both are [] than anf just than change is_brac
        p_vtable_addr = idc.get_reg_value(register_vtable)
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = get_wide_dword(pv_func_addr)
        return p_vtable_addr, v_func_addr
    else:
        p_vtable_addr = get_wide_dword(idc.get_reg_value(register_vtable))
        pv_func_addr = p_vtable_addr + offset
        v_func_addr = get_wide_dword(pv_func_addr)
        return p_vtable_addr, v_func_addr

def add_comment_to_struct_members(struct_id, vtable_func_offset, start_address):
    """
    Adds a comment to the vtable struct members.
    :param struct_id: ID of the structure.
    :param vtable_func_offset: Offset of the function in the vtable.
    :param start_address: Address where the function was called from.
    :return: Success status of adding the comment.
    """
    cur_cmt = idc.get_member_cmt(struct_id, vtable_func_offset, 1)
    new_cmt = ""
    if cur_cmt:
        if cur_cmt[:23] != "Was called from offset:":
            new_cmt = cur_cmt
        else:
            new_cmt = cur_cmt + ", " + start_address
    else:
        new_cmt = "Was called from offset: " + start_address
    succ1 = idc.set_member_cmt(struct_id, vtable_func_offset, new_cmt, 1)
    return  succ1

def add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset):
    """
    Adds all functions from the vtable to the structure.
    :param start_address: Address where the function was called from.
    :param struct_id: ID of the structure.
    :param p_vtable_addr: Address of the vtable.
    :param offset: Offset of the function in the vtable.
    :return: None
    """
    vtable_func_offset = 0
    vtable_func_value = get_wide_dword(p_vtable_addr)
    # Add all the vtable's functions to the vtable struct
    while vtable_func_value != 0:
        v_func_name = idc.get_func_name(vtable_func_value)
        if v_func_name == '':
            vtable_func_value = get_wide_dword(vtable_func_value)
            v_func_name = idc.get_func_name(vtable_func_value)
            if v_func_name == '':
                print ("Error in adding functions to struct, at BP address::0x%08x" % (start_address))
        # Change function name
        v_func_name = get_fixed_name_for_object(int(vtable_func_value), "vfunc_")
        idaapi.set_name(vtable_func_value, v_func_name, idaapi.SN_FORCE)
        # Add to structure
        succ = idc.add_struc_member(struct_id, v_func_name, vtable_func_offset , FF_DWORD, -1, 4)
        if offset == vtable_func_offset:
            add_comment_to_struct_members(struct_id, vtable_func_offset, start_address)
        vtable_func_offset += 4
        vtable_func_value = get_wide_dword(p_vtable_addr + vtable_func_offset)


def create_vtable_struct(start_address, vtable_name, p_vtable_addr, offset):
    """
    Creates a structure for the vtable.
    :param start_address: Address where the function was called from.
    :param vtable_name: Name of the vtable.
    :param p_vtable_addr: Address of the vtable.
    :param offset: Offset of the function in the vtable.
    :return: None
    """
    struct_name = vtable_name + "_struct"
    struct_id = add_struc(-1, struct_name, 0)
    if struct_id != idc.BADADDR:
        add_all_functions_to_struct(start_address, struct_id, p_vtable_addr, offset)
        idc.op_stroff(idautils.DecodeInstruction(int(idc.get_reg_value("eip"))), 1, struct_id, 0)
    else:
        struct_id = ida_struct.get_struc_id(struct_name)
        # Checks if the struct exists, in this case the function offset will be added to the struct
        if struct_id != idc.BADADDR:
            idc.op_stroff(idautils.DecodeInstruction(int(idc.get_reg_value("eip"))), 1, struct_id, 0)
        else:
            print ("Failed to create struct: " +  struct_name)

def do_logic(virtual_call_addr, register_vtable, offset):
    """
    Performs the main logic for handling the virtual call.
    :param virtual_call_addr: Address of the virtual call.
    :param register_vtable: Register used in the virtual call.
    :param offset: Offset of the function in the vtable.
    :return: None
    """
    # Checks if the assignment was beRef or byVal
    is_brac_assign = idc.print_operand(int(idc.get_reg_value("eip")), 1).find('[')
    # Checks if the assignment was beRef or byVal
    call_addr = int(virtual_call_addr) + idc.get_segm_start(int(idc.get_reg_value("eip")))
    is_brac_call = idc.print_operand(call_addr, 0).find('[')
    is_brac = -1
    if is_brac_assign != -1 and is_brac_call != -1:
        is_brac = 0
    # Get the adresses of the vtable and the virtual function from the relevant register:
    p_vtable_addr, v_func_addr = get_vtable_and_vfunc_addr(is_brac, register_vtable, offset)
    # Change the virtual function name (only in case the function has IDA's default name)
    v_func_name = get_fixed_name_for_object(v_func_addr, "vfunc_")
    idaapi.set_name(v_func_addr, v_func_name, idaapi.SN_FORCE)
    # Change the vtable address name
    vtable_name = get_fixed_name_for_object(p_vtable_addr, "vtable_")
    idaapi.set_name(p_vtable_addr, vtable_name, idaapi.SN_FORCE)
    # Add xref of the virtual call
    idc.add_cref(int(idc.get_reg_value("eip")),v_func_addr , idc.XREF_USER)
    # create the vtable struct
    create_vtable_struct(int(virtual_call_addr), vtable_name, p_vtable_addr, offset)

virtual_call_addr = str(<<<start_addr>>>)  # Offset from the beginning of its segment
#print "start_addr:", virtual_call_addr
register_vtable = "<<<register_vtable>>>"
offset = <<<offset>>>
if offset == "*":
    opnd2 = idc.print_operand(virtual_call_addr, 1)
    reg_offset = 0
    place = opnd2.find('+')
    if place != -1:  # if the function is not the first in the vtable
        sep = opnd2.find('*')
        if sep != -1: # in case the offset is stored as a duplication of a register with a number
            reg_offset = idc.get_reg_value(opnd2[place + 1: sep])
        register = opnd2[opnd2.find('[') + 1: place]
        if reg_offset:
            offset = opnd2[sep + 1: opnd2.find(']')]
            if offset.find('h') != -1:
                int_offset = int(offset[:offset.find('h')], 16)
            else:
                int_offset = int(offset)
            offset = int_offset * reg_offset

        else:
            offset = opnd2[place + 1: opnd2.find(']')]
try:
    do_logic(virtual_call_addr, register_vtable, offset)
except:
    print ("Error! at BP address: 0x%08x", idc.get_reg_value("eip"))

#idc.add_cref(0x000000013FA72ABB, 0x000000013FA71177, idc.XREF_USER | idc.fl_F)
