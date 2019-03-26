from .node_control import *
from .run_pass import *
import tqdm
import time
import signal

'''
Running on known good nodes.
No need to check for output
'''

def run_pass(p, p_cfg, nodes, req_string):
    chained_nodes = []
    node_outputs = []

    results = []
    for node_list in nodes:

        start_addr = node_list[0].addr
        ins_list = []
        for node in node_list:
            ins_list.extend(list(node.instruction_addrs))
            if node.block is not None:
                ins_list.extend(get_call_ins(p_cfg, node))
        [ins_list.extend(x.instruction_addrs) for x in node_list[-1].successors]

        async_result = do_run.apply_async((p, p_cfg, ins_list, start_addr, [x.addr for x in node_list], req_string),
                                         serializer='pickle')

        results.append(async_result)

    bar = tqdm.tqdm(total=len(results))
    while not all([x.ready() for x in results]):
        done_count = len([x.ready() for x in results if x.ready()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    for result in [x.get(propagate=False) for x in results if not x.failed()]:
        chained_nodes.extend([[p_cfg.get_any_node(y) for y in x] for x in result['chained_nodes']])
        node_outputs.extend(result['node_outputs'])

    chained_nodes = [x for x in chained_nodes if x]
    return chained_nodes, node_outputs


'''
Initial run looking for some file
descriptor writing
'''


def first_pass(p, p_cfg, nodes, req_string):
    chained_nodes = []
    node_outputs = []

    results = []

    for node in nodes:

        ins_list = list(node.instruction_addrs)
        ins_list.extend(get_call_ins(p_cfg, node))
        [ins_list.extend(x.instruction_addrs) for x in node.successors]
        start_addr = node.addr
        node._hash = None
        async_result = do_run.apply_async((p, p_cfg, ins_list, start_addr, [node.addr], req_string), serializer='pickle')

        results.append(async_result)

    bar = tqdm.tqdm(total=len(results))
    while not all([x.ready() for x in results]):
        done_count = len([x.ready() for x in results if x.ready()])
        bar.update(done_count - bar.n)
        time.sleep(1)
    bar.close()

    for result in [x.get(propagate=False) for x in results if not x.failed()]:
        chained_nodes.extend([[p_cfg.get_any_node(y) for y in x] for x in result['chained_nodes']])
        node_outputs.extend(result['node_outputs'])

    chained_nodes = [x for x in chained_nodes if x]
    return chained_nodes, node_outputs
