from __future__ import print_function
import idc
import idautils
import idaapi
import ida_ida

idaapi.require("AddBP")
idaapi.require("vtableAddress")
idaapi.require("GUI")

from vtableAddress import REGISTERS

def get_all_functions():
    """
    Prints all functions in the IDA database along with their addresses.
    :return: None
    """
    for func in idautils.Functions():
        print(hex(func), idc.get_func_name(func))


def get_xref_code_to_func(func_addr):
    """
    Retrieves all code cross-references to a given function.
    :param func_addr: Address of the function.
    :return: Dictionary with function names as keys and lists containing xref information as values.
    """
    a = idautils.XrefsTo(func_addr, 1)
    addr = {}
    for xref in a:
        frm = xref.frm  # ea in func
        start = idc.get_func_attr(frm, idc.FUNCATTR_START)  # to_xref func addr
        func_name = idc.get_func_name(start)  # to_xref func name
        addr[func_name] = [xref.iscode, start]
    return addr


def add_bp_to_virtual_calls(cur_addr, end):
    """
    Adds breakpoints to virtual calls within a given address range.
    :param cur_addr: Starting address of the range.
    :param end: Ending address of the range.
    :return: None
    """
    while cur_addr < end:
        if cur_addr == idc.BADADDR:
            break
        elif idc.print_insn_mnem(cur_addr) == 'call' or idc.print_insn_mnem(cur_addr) == 'BLR':
            if True in [idc.print_operand(cur_addr, 0).find(reg) != -1 for reg in REGISTERS]:  # idc.GetOpnd(cur_addr, 0) in REGISTERS:
                cond, bp_address = vtableAddress.write_vtable2file(cur_addr)
                if cond != '':
                    bp_vtable = AddBP.add(bp_address, cond)
        cur_addr = idc.next_head(cur_addr)


def set_values(start, end):
    """
    Sets the start and end values for the address range.
    :param start: Starting address of the range.
    :param end: Ending address of the range.
    :return: Tuple containing the start and end addresses.
    """
    start = start
    end = end
    return start, end


if __name__ == '__main__':
    """
    Main block of the script. Initializes the GUI, sets the address range, and adds breakpoints to virtual calls.
    """
    start_addr_range = ida_ida.inf_get_min_ea()  # You can change the virtual calls address range
    end_addr_range = ida_ida.inf_get_max_ea()
    oldTo = idaapi.set_script_timeout(0)
    # Initializes the GUI: Deletes the 0x in the beginning and the L at the end:
    gui = GUI.VirtuailorBasicGUI(set_values, {'start': hex(start_addr_range)[2:], 'end': hex(end_addr_range)[2:]})
    gui.exec_()
    if gui.start_line.text != "banana":
        print("Virtuailor - Started")
        add_bp_to_virtual_calls(int(gui.start_line.text(),16), int(gui.stop_line.text(), 16))
        print("Virtuailor - Finished")
