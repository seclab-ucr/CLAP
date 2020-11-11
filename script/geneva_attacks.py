
import copy
from random import randint


# SEQ/ACK add/sub operations (wrap-around considered)
def seq_add(seq_str, val):
    seq = (int(seq_str) + val) % 2**32
    return '%d' % seq


def seq_sub(seq_str, val):
    seq = (int(seq_str) - val) % 2**32
    return '%d' % seq


def gen_rand_int(length):
    return '%d' % randint(0, 2**length)


def calculate_epoch_time(trace, curr_idx):
    if curr_idx == len(trace) - 1:
        return float(trace[curr_idx].frame_time_epoch)
    else:
        return (float(trace[curr_idx+1].frame_time_epoch) + float(trace[curr_idx].frame_time_epoch)) / 2


def calculate_epoch_time_prev(trace, curr_idx):
    if curr_idx == 0:
        return float(trace[curr_idx].frame_time_epoch)
    else:
        return (float(trace[curr_idx-1].frame_time_epoch) + float(trace[curr_idx].frame_time_epoch)) / 2


def inject_geneva_1_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = 10
                    attk_pkt1.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = 10
                    attk_pkt1.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_2_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = 10
                    attk_pkt1.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = 10
                    attk_pkt1.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_3_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = '10'
                    attk_pkt1.ack = gen_rand_int(32)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.dataoff = '10'
                    attk_pkt1.ack = gen_rand_int(32)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_4_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.tcp_opt_wscale = randint(0, 30)
                    attk_pkt1.dataoff = '8'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.tcp_opt_wscale = randint(0, 30)
                    attk_pkt1.dataoff = '8'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_5_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_6_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.ttl = 8
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.ttl = 8
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_7_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.ack = gen_rand_int(32)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.payload_len = randint(0, 1460)
                    attk_pkt1.ack = gen_rand_int(32)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_8_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'S' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.payload_len = randint(0, 1460)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_len = randint(0, 1460)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'S' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.payload_len = randint(0, 1460)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_len = randint(0, 1460)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_9_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.ip_len = 64
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.ip_len = 64
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_10_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.ip_len = 64
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.ip_len = 64
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_11_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_12_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_13_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.tcp_opt_md5header = '1'
                    attk_pkt2.flags = 'R'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'R'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_14_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'RA'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'RA'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_15_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'RA'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'RA'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_16_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.tcp_opt_md5header = '1'
                    attk_pkt2.flags = 'R'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.tcp_opt_md5header = '1'
                    attk_pkt2.flags = 'R'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_17_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FRAPUEN'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FRAPUEN'
                    attk_pkt2.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_18_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FREACN'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FREACN'
                    attk_pkt2.ttl = 10
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_19_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FREACN'
                    attk_pkt2.tcp_opt_md5header = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt2.flags = 'FREACN'
                    attk_pkt2.tcp_opt_md5header = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    k_attk_pkt2.frame_time_epoch = calculate_epoch_time(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_20_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.flags == 'PA' and int(pkt.payload_len) > 8:
                # split the packet into 8 bytes + remaining
                pkt_new_1 = copy.deepcopy(pkt)
                pkt_new_1.ip_len = str(
                    int(pkt_new_1.ip_len) - int(pkt_new_1.payload_len) + 8)
                pkt_new_1.payload_len = '8'
                pkt_new_2 = copy.deepcopy(pkt)
                pkt_new_2.ip_len = str(int(pkt_new_2.ip_len) - 8)
                pkt_new_2.payload_len = str(int(pkt_new_2.payload_len) - 8)
                pkt_new_2.seq = seq_add(pkt_new_2.seq, 8)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(pkt_new_1)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(pkt_new_2)

                k_pkt_new_1 = copy.deepcopy(k_pkt)
                k_pkt_new_1.frame_len = k_pkt_new_1.frame_len - \
                    int(pkt.payload_len) + 8
                k_pkt_new_2 = copy.deepcopy(k_pkt)
                k_pkt_new_2.frame_len = k_pkt_new_2.frame_len - 8
                k_pkt_new_2.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new_1)
                injected_k_trace.append(k_pkt_new_2)
            elif pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                has_been_established = True
                attk_pkt = copy.deepcopy(pkt)
                attk_pkt.seq = gen_rand_int(32)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(attk_pkt)

                k_attk_pkt = copy.deepcopy(k_pkt)
                injected_k_trace.append(k_attk_pkt)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_21_attack(dataset_dict, k_dataset_dict, multipkt=False):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.flags == 'PA' and int(pkt.payload_len) > 12:
                # split the packet into 8 bytes + remaining
                pkt_new_1 = copy.deepcopy(pkt)
                pkt_new_1.ip_len = str(
                    int(pkt_new_1.ip_len) - int(pkt_new_1.payload_len) + 8)
                pkt_new_1.payload_len = '8'
                pkt_new_2 = copy.deepcopy(pkt)
                pkt_new_2.ip_len = str(
                    int(pkt_new_2.ip_len) - int(pkt_new_1.payload_len) + 12)
                pkt_new_2.payload_len = '4'
                pkt_new_2.seq = seq_add(pkt_new_2.seq, 8)
                pkt_new_3 = copy.deepcopy(pkt)
                pkt_new_3.ip_len = str(int(pkt_new_3.ip_len) - 12)
                pkt_new_3.payload_len = str(
                    int(pkt_new_3.payload_len) - 12)
                pkt_new_3.seq = seq_add(pkt_new_3.seq, 12)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(pkt_new_1)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(pkt_new_2)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(pkt_new_3)

                k_pkt_new_1 = copy.deepcopy(k_pkt)
                k_pkt_new_1.frame_len = k_pkt_new_1.frame_len - \
                    int(pkt.payload_len) + 8
                k_pkt_new_1.frame_time_epoch = calculate_epoch_time_prev(
                    k_trace, idx)
                k_pkt_new_2 = copy.deepcopy(k_pkt)
                k_pkt_new_2.frame_len = k_pkt_new_2.frame_len - \
                    int(pkt.payload_len) + 4
                k_pkt_new_3 = copy.deepcopy(k_pkt)
                k_pkt_new_3.frame_len = k_pkt_new_3.frame_len - 12
                k_pkt_new_3.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new_1)
                injected_k_trace.append(k_pkt_new_2)
                injected_k_trace.append(k_pkt_new_3)
            elif pkt.flags == 'A' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                has_been_established = True
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_22_attack(dataset_dict, k_dataset_dict, multipkt=False):
    raise NotImplementedError


def inject_geneva_23_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.flags = 'F'
                    attk_pkt1.ip_len = 78
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.flags = 'F'
                    attk_pkt1.ip_len = 78
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_24_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'S' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.flags = 'SA'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'S' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt1 = copy.deepcopy(pkt)
                    attk_pkt2 = copy.deepcopy(pkt)
                    attk_pkt1.flags = 'SA'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt1)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt2)

                    k_attk_pkt1 = copy.deepcopy(k_pkt)
                    k_attk_pkt1.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_attk_pkt2 = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt1)
                    injected_k_trace.append(k_attk_pkt2)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_geneva_25_attack(dataset_dict, k_dataset_dict, multipkt=False):

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        k_trace = k_dataset_dict[connection_id]
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_been_established = False
        outbound_attk_id = trace[0].get_attack_id()
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if multipkt:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt = copy.deepcopy(pkt)
                    attk_pkt.tcp_opt_uto = randint(0, 65525)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(attk_pkt)

                    k_attk_pkt = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
            else:
                if pkt.flags == 'PA' and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt = copy.deepcopy(pkt)
                    attk_pkt.tcp_opt_uto = randint(0, 65525)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(attk_pkt)

                    k_attk_pkt = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_attk_pkt)
                else:
                    injected_trace.append(pkt)
                    injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info
