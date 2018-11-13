import angr
import argparse
import IPython
import logging
import signal
import os
from termcolor import colored
logging.getLogger('angr').disabled = True
logger = logging.getLogger('angr')
logger.disabled = True
logger.propagate = False

p = None
p_cfg = None
strings_list = []
flag_list = set()
string_iter = 0
node_output_dict = {}
return_addresses = {}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class TimeoutError(Exception):
    pass

class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)


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
            if curr_pc not in ins_list and not in_simproc(curr_pc):
                if (curr_pc not in [x.se.eval(x.regs.pc) for x in simgr.stashes['pruned']]):
                    simgr.stashes['pruned'].append(path)
                simgr.stashes['active'].remove(path)

    return simgr

'''
Iterate over all the paths looks for any 
stdin/stdout/stderr activity
'''
def check_fds(simgr, node, opt_string=""):
    global flag_list
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
                            try:
                                flag_str = posix_string[posix_string.index('flag{'):posix_string.index('}') +1]
                                flag_list.add(flag_str)
                            except:
                                flag_list.add(posix_string)
                        node_outputs.append((path.posix.dumps(0),path.posix.dumps(1),path.posix.dumps(2)))
                        chained_nodes.append(node)
                        break

    return chained_nodes, node_outputs

'''
pretty print a block at the address
'''
def print_block(cur_pc):
    my_nodes = p_cfg.get_all_nodes(cur_pc)
    for node in my_nodes:
        if node.block is not None:
            print(bcolors.OKGREEN)
            node.block.pp()

'''
Given a child and parent node, check for shared
whether they are running in the same function.
If there is a call give us all basic blocks in 
that function.
'''
#Very Naive approach toward return pointer problem
def check_get_func_nodes(child, parent):

    new_nodes = []

    #Check for None
    if child.function_address is not None and parent.function_address is not None:
        #Check for new function
        if child.function_address is not parent.function_address:

            new_func = p_cfg.functions.get_by_addr(parent.function_address)

            top_node = p_cfg.get_any_node(parent.function_address)

            for block in new_func.blocks:
                n_node = p_cfg.get_any_node(block.addr)
                new_nodes.append(n_node)

            #Gaurentee top node runes first
            if top_node in new_nodes:
                new_nodes.remove(top_node)

            new_nodes.insert(0,top_node)
            
    return new_nodes




'''
Do we exist and are we in a simprocedure
'''
def in_simproc(curr_pc):
    return p.kb.functions.contains_addr(curr_pc) and p.kb.functions.get_by_addr(curr_pc).is_simprocedure

def print_recent_nodes(node_list, chained):
    print(colored("{:<60} {:<20}".format("Node", "File Activity"),'yellow'))
    for node in node_list:
        node_text = "{0: <60} {1: <20}".format(str(node), (node in chained))
        print(colored(node_text,'cyan'))
        
def get_predecessors(nodes_list):
    global return_addresses
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
            path_stitch.insert(0,predecessor)

            return_list.append(path_stitch)
    return return_list

'''
Running on known good nodes.
No need to check for output
'''
def run_pass(nodes, explore_timeout, req_string):
    chained_nodes = []
    node_outputs = []
    recent_nodes = []

    node_len = len(nodes)
    node_count = 0

    global strings_list

    #node is a list of nodes now...
    for node_list in nodes:

        os.system('clear')
        print(colored("[ -- Running on {} blocks {}/{} -- ]".format(len(node_list), node_count, node_len),'white'))
        print_recent_nodes(recent_nodes, chained_nodes)

        ins_list = []
        for node in node_list:
            ins_list.extend(list(node.instruction_addrs))
            if node.block is not None:
                ins_list.extend(get_call_ins(node))

        [ins_list.extend(x.instruction_addrs) for x in node_list[-1].successors]

        #Get block addresses

        print(colored("[ -- Instructions --]",'white'))
#        print(colored(str([hex(x) for x in ins_list]),'yellow'))
        start_addr = node_list[0].addr
        end_addr = node_list[-1].addr
        print(colored("[ -- Direction --]",'white'))
        print(colored("{} : {} -> {}".format(node_list[0], hex(start_addr), hex(end_addr)),'yellow'))

        global flag_list
        if len(flag_list) > 0:
            print(colored("[ -- Potential Flags-- ]",'white'))
            for flag in flag_list:
                print(colored(flag,'yellow'))

        global string_iter
        print(colored("[ -- Strings --]",'white'))
        if len(strings_list) > 0:
            for i in range(string_iter,string_iter+5):
                i = i % len(strings_list)
                print(colored(strings_list[i],'cyan'))
            string_iter += 1

        #Build simulator
        state = p.factory.blank_state(addr=start_addr)
        state.globals['addrs'] = ins_list
        state.globals['last_set'] = []
        simgr = p.factory.simgr(state, save_unconstrained=True)

        print(colored("[ -- Block Assembly --]",'white'))
        print_block(node_list[0].addr)
        '''
        for node in node_list:
            print(colored(str(node),'white'))
            print_block(node.addr)
        '''

        #Run it
        try:
            with timeout(explore_timeout):
                while(len(simgr.active) > 0 and any(x.se.eval(x.regs.pc) in ins_list or in_simproc(x.se.eval(x.regs.pc)) for x in simgr.active) ):
                    simgr.step(step_func=visual_step)
                    nodes_ret,nodes_out = check_fds(simgr, node_list, req_string)
                    chained_nodes.extend(nodes_ret)
                    if len(nodes_out) > 0:
                        node_outputs.append(nodes_out)
                        check_output(nodes_out)
                    if len(nodes_ret) > 0:
                        for i in range(len(nodes_ret)):
                            node_output_dict[str(nodes_ret[i])] = nodes_out[i]

        except TimeoutError:
            print(bcolors.FAIL + "[!] TIMEOUT {} : {} -> {}".format(node_list[0], hex(start_addr), hex(end_addr)))
            pass
        
        recent_nodes.insert(0,node_list[0])
        if len(recent_nodes) > 10:
            recent_nodes.remove(recent_nodes[-1])

        node_count += 1
    return chained_nodes,node_outputs


'''
Initial run looking for some file
descriptor writing
'''
def first_pass(nodes, explore_timeout, req_string):
    chained_nodes = []
    recent_nodes = []
    node_outputs = []

    node_len = len(nodes)
    node_count = 0
    for node in nodes:

        os.system('clear')
        print(colored("[ -- Initial Pass {}/{} -- ]".format(node_count, node_len),'white'))
        print_recent_nodes(recent_nodes, chained_nodes)

        #Get block addresses
        ins_list = list(node.instruction_addrs)
        ins_list.extend(get_call_ins(node))
#        [ins_list.extend(x.instruction_addrs) for x in node.predecessors]
        [ins_list.extend(x.instruction_addrs) for x in node.successors]

        print(colored("[ -- Instructions --]",'white'))
#        print(colored(str([hex(x) for x in ins_list]),'yellow'))
        start_addr = node.addr
        end_addr = max(ins_list)
        print(colored("[ -- Direction --]",'white'))
        print(colored("{} : {} -> {}".format(node, hex(start_addr), hex(end_addr)),'yellow'))

        global string_iter
        print(colored("[ -- Strings --]",'white'))
        if len(strings_list) > 0:
            for i in range(string_iter,string_iter+5):
                i = i % len(strings_list)
                print(colored(strings_list[i],'cyan'))
            string_iter += 1


        #Build simulator
        state = p.factory.blank_state(addr=start_addr)
        state.globals['addrs'] = ins_list
        state.globals['last_set'] = []
        simgr = p.factory.simgr(state, save_unconstrained=False)

        print(colored("[ -- Block Assembly --]",'white'))
        print_block(start_addr)
        '''
        for addr in [node.addr for node in node.successors]:
            print(colored("[ -- successors --]",'white'))
            print_block(addr)
        '''

        #Run it
        try:
            with timeout(explore_timeout):
                while(len(simgr.active) > 0 and any(x.se.eval(x.regs.pc) in ins_list or in_simproc(x.se.eval(x.regs.pc)) for x in simgr.active) ):
                    simgr.step(step_func=visual_step)
                    nodes_ret,nodes_out = check_fds(simgr, node, req_string)
                    chained_nodes.extend(nodes_ret)
                    check_output(nodes_out)
                    if len(nodes_ret) > 0:
                        for i in range(len(nodes_ret)):
                            node_output_dict[nodes_ret[i]] = nodes_out[i]

#                    node_outputs.append(nodes_out)
#                    chained_nodes.extend(check_fds(simgr, node))

        except TimeoutError:
            print(bcolors.FAIL + "[!] TIMEOUT {} : {} -> {}".format(node, hex(start_addr), hex(end_addr)))
            pass
        
        recent_nodes.insert(0,node)
        if len(recent_nodes) > 10:
            recent_nodes.remove(recent_nodes[-1])

        node_count += 1
    chained_nodes = set(chained_nodes)
    chained_nodes = list(chained_nodes)
    chained_nodes = [[x] for x in chained_nodes]
    return chained_nodes

'''
I need a better check
'''
def check_output(nodes_out):

    global strings_list
    for output_fds in nodes_out: #3
        for output_fd in output_fds:
            while type(output_fd) == tuple:
                output_fd = [x.decode('utf-8',"ignore") for x in output_fd]
            while type(output_fd) == list:
                output_fd = ','.join([x.decode('utf-8',"ignore") if type(x) == 'str' else x for x in output_fd])
            try:
                output_fd = output_fd.decode("utf-8", 'ignore') 
            except:
                pass
#            output_fd.replace('b\'\'','')
            if len(output_fd) > 0:
                strings_list.append(repr(output_fd))
            if "{" in output_fd and "}" in output_fd:
                print(output_fd)
                return True
    return False


'''
get instructions for all calls in a given node
This function goes 1 level deep, and does not recurse
'''
def get_call_ins(node):
    added_isns = []
    instructions = node.block.capstone.insns
    for insc in instructions:
        my_op_str = insc.op_str
        my_mnemonic = insc.mnemonic
        if 'call' in my_mnemonic and " " not in my_op_str and "0x" in my_op_str:
            addr = int(my_op_str,16)
            try:
                called_func = p_cfg.functions.get_by_addr(addr)
            except:
                #KeyError
                continue
            if len(called_func.name) > 0:
                print(colored("Added blocks for {}".format(called_func.name),'yellow'))
            for block in called_func.blocks:
                added_isns.extend(block.instruction_addrs)
    return added_isns

'''
Could I shorten this? yes
Should I shorten this? no
'''
def is_node_plt(node):
    segment = p.loader.find_section_containing(node.addr)
    if segment is not None:
        return '.plt' in segment.name

'''
plt and simprocedures don't work as well as you would
want when doing backwards stitching. This is a performance
instensive workaround
'''
def process_plt_and_sim(nodes_list):
    add_list = []
    remove_list = []
    temp_remove = []

    #Iterate through regular nodes
    for node_list in nodes_list:
        if( node_list[0].is_simprocedure or is_node_plt(node_list[0])):
            remove_list.append(node_list)
            for item_list in get_predecessors([node_list]):
                add_list.append(item_list)

    while(not all([ not x[0].is_simprocedure and not is_node_plt(x[0]) for x in add_list]) ):
        for node_list in add_list:
            if node_list[0].is_simprocedure or is_node_plt(node_list[0]):
                temp_remove.append(node_list)
                for item_list in get_predecessors([node_list]):
                    add_list.append(item_list)

        #Can't remove element while in for each
        for node_list in temp_remove:
            add_list.remove(node_list)
        temp_remove = []
    return add_list,remove_list
        
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('FILE')
    parser.add_argument('--timeout','-t',default=30,type=int)
    parser.add_argument('--string','-s', default="")

    args = parser.parse_args()

    global p
    global p_cfg
    p = angr.Project(args.FILE, load_options={'auto_load_libs': False})
    print(bcolors.WARNING + '[+] Building CFGFast')
    p_cfg = p.analyses.CFGFast()

    nodes = [x for x in p_cfg.nodes() if len(x.instruction_addrs) > 0]
    try:
        chained_nodes = first_pass(nodes, args.timeout, args.string)
    except KeyboardInterrupt:
        print(colored("[ -- Strings --]",'white'))
        for string_item in strings_list:
            print(colored(string_item,'cyan'))
        print("[~] Exitting")
        exit(0)

    nodes_list = chained_nodes
    round_iter = 1
    node_output = []

    while(len(nodes_list) > 0):

        nodes_list = get_predecessors(nodes_list)

        add_list,remove_list = process_plt_and_sim(nodes_list)

        #Add in extra addressed nodes
        nodes_list.extend(add_list)

        #Take out simprocedures and plts
        for item in remove_list:
            nodes_list.remove(item)

        remove_indexes = []
        for item_index in range(len(nodes_list)):

            if(len(nodes_list[item_index]) > 1 and len(nodes_list[item_index]) > 0 and not is_node_plt(nodes_list[item_index][0]) and not nodes_list[item_index][0].is_simprocedure):
                #Not an amazing fix to just assume we can run the whole called func...
                func_fix_list = check_get_func_nodes(nodes_list[item_index][1], nodes_list[item_index][0])

                #Only if we don't already have nodes from that function, add e'n
                if len(func_fix_list) > 0 and not func_fix_list[0].function_address in [x.function_address for x in nodes_list[item_index][1:]]:
                    func_fix_list.extend(nodes_list[item_index])

                    func_fix_list = get_predecessors([func_fix_list])

                    nodes_list.extend(func_fix_list)
                    remove_indexes.append(item_index)

        for item_index in remove_indexes:
            if item_index < len(nodes_list): #What a terrible fix -- Sorry
                nodes_list.remove(nodes_list[item_index])

        try:
            nodes_list,node_output = run_pass(nodes_list, args.timeout, args.string)
        except KeyboardInterrupt:
            print(colored("[ -- Strings --]",'white'))
            for string_item in strings_list:
                print(colored(string_item,'cyan'))
            print("[~] Exitting")
            exit(0)
        round_iter += 1

    print(colored("[ -- Strings --]",'white'))
    for string_item in strings_list:
        print(colored(string_item,'cyan'))
    print("[~] Exitting")

if __name__ == '__main__':
    main()
