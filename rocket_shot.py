import argparse
import angr
from lib.back_stitcher import *
logging.getLogger('angr').disabled = True
logger = logging.getLogger('angr')
logger.disabled = True
logger.propagate = False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('FILE')
    parser.add_argument('--string','-s', default="")

    args = parser.parse_args()

    p = angr.Project(args.FILE, load_options={'auto_load_libs': False})
    print('[+] Building CFGFast')
    p_cfg = p.analyses.CFGFast()
    node_output = []
    strings_list = set()

    nodes = [x for x in p_cfg.nodes() if len(x.instruction_addrs) > 0]
    try:
        chained_nodes, node_output = first_pass(p, p_cfg, nodes, args.string)
        for y in node_output:
            for x in y:
                strings_list.add(x[0])
                strings_list.add(x[1])
                strings_list.add(x[2])
    except KeyboardInterrupt:
        print(colored("[ -- Strings --]",'white'))
        for string_item in strings_list:
            print(colored(string_item,'cyan'))
        print("[~] Exitting")
        exit(0)

    nodes_list = chained_nodes #[p_cfg.get_any_node(x.addr) for x in chained_nodes]
    round_iter = 1
    for string in strings_list:
        print(string)
    while len(nodes_list) > 0:
        nodes_list = get_predecessors(nodes_list)

        add_list, remove_list = process_plt_and_sim(p, nodes_list)

        #Add in extra addressed nodes
        nodes_list.extend(add_list)

        #Take out simprocedures and plts
        for item in remove_list:
            nodes_list.remove(item)

        remove_indexes = []

        for item_index in range(len(nodes_list)):

            if(len(nodes_list[item_index]) > 1 and len(nodes_list[item_index]) > 0 and not is_node_plt(p, nodes_list[item_index][0]) and not nodes_list[item_index][0].is_simprocedure):
                #Not an amazing fix to just assume we can run the whole called func...
                func_fix_list = check_get_func_nodes(p_cfg, nodes_list[item_index][1], nodes_list[item_index][0])


                #Only if we don't already have nodes from that function, add e'n
                if len(func_fix_list) > 0 and not func_fix_list[0].function_address in [x.function_address for x in nodes_list[item_index][1:]]:
                    func_fix_list.extend(nodes_list[item_index])

                    func_fix_list = get_predecessors([func_fix_list])

                    nodes_list.extend(func_fix_list)
                    #remove_indexes.append(item_index)

        remove_indexes.reverse()
        for item_index in remove_indexes:
            if item_index < len(nodes_list): #What a terrible fix -- Sorry
                nodes_list.remove(nodes_list[item_index])
        try:
            nodes_list, node_output = run_pass(p, p_cfg, nodes_list, args.string)
            for y in node_output:
                for x in y:
                    strings_list.add(x[0])
                    strings_list.add(x[1])
                    strings_list.add(x[2])
        except KeyboardInterrupt:
            print(colored("[ -- Strings --]",'white'))
            for string_item in strings_list:
                print(colored(string_item,'cyan'))
            print("[~] Exitting")
            exit(0)
        round_iter += 1
        strings_list = list(strings_list)
        strings_list.sort()
        strings_list = set(strings_list)
        for string in strings_list:
            print(string)

    print(colored("[ -- Strings --]",'white'))
    for string_item in strings_list:
        print(colored(string_item,'cyan'))
    print("[~] Exitting")


if __name__ == '__main__':
    main()
