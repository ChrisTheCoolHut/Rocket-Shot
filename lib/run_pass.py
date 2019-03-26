
from celery import Celery
import pickle
from .node_control import *
#angr logging is way too verbose
import logging

app = Celery('CeleryTask')
app.config_from_object('celeryconfig')

log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False


@app.task
def do_run(proj, p_cfg, ins_list, start_addr, node_list, req_string):
    # Build simulator
    node_list = [p_cfg.get_any_node(x) for x in node_list]
    state = proj.factory.blank_state(addr=start_addr)
    state.globals['addrs'] = ins_list
    state.globals['last_set'] = []
    simgr = proj.factory.simgr(state, save_unconstrained=True)

    chained_nodes =[]
    node_outputs = []
    node_output_dict = {}
    ret_strings = []

    try:
        import sys
        sys.stdout.encoding = 'UTF-8' #AttributeError: 'LoggingProxy' object has no attribute 'encoding'
    except AttributeError as e: #AttributeError: readonly attribute
        pass

    while (len(simgr.active) > 0 and any(
            x.se.eval(x.regs.pc) in ins_list or in_simproc(proj, x.se.eval(x.regs.pc)) for x in simgr.active)):
        simgr.step(step_func=visual_step)
        nodes_ret, nodes_out = check_fds(simgr, node_list, req_string)
        chained_nodes.extend(nodes_ret)
        if len(nodes_out) > 0:
            node_outputs.append(nodes_out)
            ret_strings.extend(check_output(nodes_out))
        if len(nodes_ret) > 0:
            for i in range(len(nodes_ret)):
                node_output_dict[str(nodes_ret[i])] = nodes_out[i]

    chained_nodes = [[y.addr for y in x] for x in chained_nodes]

    ret_dict = {}
    ret_dict['chained_nodes'] = chained_nodes
    ret_dict['node_outputs'] = node_outputs
    ret_dict['nodes_dict'] = node_output_dict
    ret_dict['strings'] = ret_strings

    return ret_dict
