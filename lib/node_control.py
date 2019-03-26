from termcolor import colored


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

'''
Do we exist and are we in a simprocedure
Do we exist and are we in a simprocedure
'''
def in_simproc(p, curr_pc):
    return p.kb.functions.contains_addr(curr_pc) and p.kb.functions.get_by_addr(curr_pc).is_simprocedure


def print_recent_nodes(node_list, chained):
    print(colored("{:<60} {:<20}".format("Node", "File Activity"), 'yellow'))
    for node in node_list:
        node_text = "{0: <60} {1: <20}".format(str(node), (node in chained))
        print(colored(node_text, 'cyan'))


def get_predecessors(nodes_list):
    return_list = []
    for node_list in nodes_list:
        predecessors = node_list[0].predecessors
        for predecessor in predecessors:
            '''
            #THIS IS BAD. FIX THIS
            #NOT ALL RETURNS IN A FUNCTION POINT TO THE SAME ADDRESS
            if predecessor.block is not None and 'ret' in [x.mnemonic for x in predecessor.block.capstone.insns]:
                return_addresses[predecessor.addr] = node_list[0].addr
            '''

            path_stitch = list(node_list)
            path_stitch.insert(0, predecessor)

            return_list.append(path_stitch)
    return return_list


'''
Given a child and parent node, check for shared
whether they are running in the same function.
If there is a call give us all basic blocks in 
that function.
'''


# Very Naive approach toward return pointer problem
def check_get_func_nodes(p_cfg, child, parent):
    new_nodes = []

    # Check for None
    if child.function_address is not None and parent.function_address is not None:
        # Check for new function
        if child.function_address is not parent.function_address:

            new_func = p_cfg.functions.get_by_addr(parent.function_address)

            top_node = p_cfg.get_any_node(parent.function_address)

            for block in new_func.blocks:
                n_node = p_cfg.get_any_node(block.addr)
                new_nodes.append(n_node)

            # Gaurentee top node runes first
            if top_node in new_nodes:
                new_nodes.remove(top_node)

            new_nodes.insert(0, top_node)

    return new_nodes

def visual_step(simgr):

    #Creating string to print
    my_str = ""
    for stash in simgr.stashes:
        if len(simgr.stashes[stash]) > 0:
            my_str += "{} : ".format(stash)
            for path in simgr.stashes[stash]:
                cur_pc = path.se.eval(path.regs.pc)
                my_str += str(hex(path.se.eval(path.regs.pc))) + ','
#            my_str += "\n"
#    print(my_str+'\r'),

    #Check for looping
    for stash in simgr.stashes:
        for path in simgr.stashes[stash]:
            if path.globals['last_set'] == my_str:
#                print(colored('[-] Explorer Stuck... Fixing\r','yellow')),
                simgr.stashes[stash].remove(path)
            else:
                path.globals['last_set'] = my_str

    #Remove paths not in ins list
    #Ignores simprocedures
    if len(simgr.active) > 0:
        #Get ins list
        ins_list = simgr.active[0].globals['addrs']
        for path in simgr.active:
            curr_pc = path.se.eval(path.regs.pc)
            if curr_pc not in ins_list and not in_simproc(path.project, curr_pc):
                if (curr_pc not in [x.se.eval(x.regs.pc) for x in simgr.stashes['pruned']]):
                    simgr.stashes['pruned'].append(path)
                simgr.stashes['active'].remove(path)

    return simgr

'''
Iterate over all the paths looks for any 
stdin/stdout/stderr activity
'''
def check_fds(simgr, node, opt_string=""):
    chained_nodes = []
    node_outputs = []
    #Check for anything
    for stash in simgr.stashes:
        if len(simgr.stashes) > 0:
            for path in simgr.stashes[stash]:
                for i in range(3):
                    posix_string = path.posix.dumps(i).decode('utf-8','ignore')
                    if len(posix_string) > 0 and opt_string in posix_string:
                        if "flag{" in posix_string and "}" in posix_string:
                            '''
                            try:
                                flag_str = posix_string[posix_string.index('flag{'):posix_string.index('}') +1]
                                flag_list.add(flag_str)
                            except:
                                flag_list.add(posix_string)
                            '''
                        node_outputs.append((path.posix.dumps(0).decode("utf-8", 'ignore'),
                                             path.posix.dumps(1).decode("utf-8", 'ignore'),
                                             path.posix.dumps(2).decode("utf-8", 'ignore')))
                        chained_nodes.append(node)
                        break

    return chained_nodes, node_outputs

'''
pretty print a block at the address
'''
def print_block(p_cfg, cur_pc):
    my_nodes = p_cfg.get_all_nodes(cur_pc)
    for node in my_nodes:
        if node.block is not None:
            print(bcolors.OKGREEN)
            node.block.pp()


'''
I need a better check
'''


def check_output(nodes_out):
    strings_list = []
    for output_fds in nodes_out:  # 3
        for output_fd in output_fds:
            while type(output_fd) == tuple:
                output_fd = [x.decode('utf-8', "ignore") for x in output_fd]
            while type(output_fd) == list:
                output_fd = ','.join([x.decode('utf-8', "ignore") if type(x) == 'str' else x for x in output_fd])
            try:
                output_fd = output_fd.decode("utf-8", 'ignore')
            except:
                pass
            #            output_fd.replace('b\'\'','')
            if len(output_fd) > 0:
                strings_list.append(repr(output_fd))
            if "{" in output_fd and "}" in output_fd:
                print(output_fd)
                return strings_list
    return strings_list


'''
get instructions for all calls in a given node
This function goes 1 level deep, and does not recurse
'''


def get_call_ins(p_cfg, node):
    added_isns = []
    instructions = node.block.capstone.insns
    for insc in instructions:
        my_op_str = insc.op_str
        my_mnemonic = insc.mnemonic
        if 'call' in my_mnemonic and " " not in my_op_str and "0x" in my_op_str:
            addr = int(my_op_str, 16)
            try:
                called_func = p_cfg.functions.get_by_addr(addr)
            except:
                # KeyError
                continue
            if len(called_func.name) > 0:
                pass
                #print(colored("Added blocks for {}".format(called_func.name), 'yellow'))
            for block in called_func.blocks:
                added_isns.extend(block.instruction_addrs)
    return added_isns


'''
Could I shorten this? yes
Should I shorten this? no
'''


def is_node_plt(p, node):
    segment = p.loader.find_section_containing(node.addr)
    if segment is not None:
        return '.plt' in segment.name


'''
plt and simprocedures don't work as well as you would
want when doing backwards stitching. This is a performance
instensive workaround
'''


def process_plt_and_sim(p, nodes_list):
    add_list = []
    remove_list = []
    temp_remove = []

    # Iterate through regular nodes
    for node_list in nodes_list:
        if (node_list[0].is_simprocedure or is_node_plt(p, node_list[0])):
            remove_list.append(node_list)
            for item_list in get_predecessors([node_list]):
                add_list.append(item_list)

    while (not all([not x[0].is_simprocedure and not is_node_plt(p, x[0]) for x in add_list])):
        for node_list in add_list:
            if node_list[0].is_simprocedure or is_node_plt(p, node_list[0]):
                temp_remove.append(node_list)
                for item_list in get_predecessors([node_list]):
                    add_list.append(item_list)

        # Can't remove element while in for each
        for node_list in temp_remove:
            add_list.remove(node_list)
        temp_remove = []
    return add_list, remove_list
