
from random import randint
import copy

MAX_ADV_PKT = 5


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


def inject_low_ttl_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_ttl = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_ttl = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_invalid_version_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_version = '5'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_version = '5'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_invalid_header_len_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_ihl = '16'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_ihl = '16'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_longer_length_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_len += 80
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_len += 80
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_shorter_length_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_len = '40'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_len = '40'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_wrong_proto_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.prot = 'UDP'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.prot = 'UDP'
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_wrong_seq_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.seq = seq_sub(attk_pkt.seq, 12345)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.seq = seq_sub(attk_pkt.seq, 12345)
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_wrong_tcp_checksum_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.chksum = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_ack_not_set_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.flags = 'P'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.flags = 'P'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_invalid_dataoff_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.dataoff = '16'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.dataoff = '16'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_invalid_flag_comb_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.flags = 'SF'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.flags = 'SF'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_invalid_ip_opt_attack(dataset_dict, k_dataset_dict, multipkt=False):

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
            attk_pkt = copy.deepcopy(pkt)
            k_attk_pkt = copy.deepcopy(k_pkt)
            if multipkt and len(adv_pkt_info[connection_id]) < MAX_ADV_PKT: 
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id:
                    has_been_established = True
                    attk_pkt.ip_opt_non_standard = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            else:
                if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                    has_been_established = True
                    attk_pkt.ip_opt_non_standard = '1'
                    curr_adv_idx = len(injected_trace)
                    adv_pkt_info[connection_id].append(curr_adv_idx)
                    injected_trace.append(attk_pkt)

                    k_attk_pkt.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    injected_k_trace.append(k_attk_pkt)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_low_ttl_rst_attack_a(dataset_dict, k_dataset_dict):

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
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                has_been_established = True
                attk_pkt1 = copy.deepcopy(pkt)
                attk_pkt2 = copy.deepcopy(pkt)
                attk_pkt1.flags = 'R'
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


def inject_low_ttl_rst_attack_b(dataset_dict, k_dataset_dict):

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
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and pkt.get_attack_id() == outbound_attk_id and not has_been_established:
                has_been_established = True
                attk_pkt1 = copy.deepcopy(pkt)
                attk_pkt2 = copy.deepcopy(pkt)
                attk_pkt1.flags = 'R'
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(attk_pkt2)
                curr_adv_idx = len(injected_trace)
                adv_pkt_info[connection_id].append(curr_adv_idx)
                injected_trace.append(attk_pkt1)

                k_attk_pkt1 = copy.deepcopy(k_pkt)
                k_attk_pkt2 = copy.deepcopy(k_pkt)
                k_attk_pkt1.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_attk_pkt2)
                injected_k_trace.append(k_attk_pkt1)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_been_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info
