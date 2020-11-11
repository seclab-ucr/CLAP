import copy

import random


# SEQ/ACK add/sub operations (wrap-around considered)
def _seq_add(seq_str, val):
    seq = (int(seq_str) + val) % 2**32
    return '%d' % seq


def _seq_sub(seq_str, val):
    seq = (int(seq_str) - val) % 2**32
    return '%d' % seq


def _gen_rand_int(length):
    return '%d' % random.randint(0, 2**length)


def craft_syn_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.ack = '0'
    pkt.dataoff = '20'
    pkt.flags = 'S'
    pkt.urgptr = '0'
    # remove payload
    pkt.ip_len = str(int(pkt.ip_len) - int(pkt.payload_len))
    pkt.payload_len = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_tsval = '-1'
    pkt.tcp_opt_tsecr = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


def craft_fin_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.ack = '0'
    pkt.dataoff = '32'
    pkt.flags = 'F'
    pkt.urgptr = '0'
    # remove payload
    pkt.ip_len = str(int(pkt.ip_len) - int(pkt.payload_len))
    pkt.payload_len = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


def craft_fin_ack_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.dataoff = '32'
    pkt.flags = 'FA'
    pkt.urgptr = '0'
    # remove payload
    pkt.ip_len = str(int(pkt.ip_len) - int(pkt.payload_len))
    pkt.payload_len = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


def craft_rst_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.ack = '0'
    pkt.dataoff = '20'
    pkt.flags = 'R'
    pkt.urgptr = '0'
    # remove payload
    pkt.ip_len = str(int(pkt.ip_len) - int(pkt.payload_len))
    pkt.payload_len = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_tsval = '-1'
    pkt.tcp_opt_tsecr = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


def craft_rst_ack_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.dataoff = '20'
    pkt.flags = 'RA'
    pkt.urgptr = '0'
    # remove payload
    pkt.ip_len = str(int(pkt.ip_len) - int(pkt.payload_len))
    pkt.payload_len = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_tsval = '-1'
    pkt.tcp_opt_tsecr = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


def craft_data_pkt(reference_pkt):
    pkt = copy.deepcopy(reference_pkt)
    pkt.dataoff = '32'
    pkt.flags = 'A'
    pkt.urgptr = '0'
    pkt.ip_id = _gen_rand_int(16)
    pkt.tcp_opt_mss = '-1'
    pkt.tcp_opt_wscale = '-1'
    pkt.tcp_opt_md5header = '-1'
    # half the timestamps
    pkt.tcp_timestamp = str(float(pkt.tcp_timestamp) / 2)
    reference_pkt.tcp_timestamp = str(float(reference_pkt.tcp_timestamp) / 2)
    return pkt


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


###################################################################
# Zeek
###################################################################

def inject_zeek_syn_with_data(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            if pkt.flags == 'S':
                pkt_new = copy.deepcopy(pkt)
                pkt_new.payload_len = str(int(pkt.payload_len) + 1000)
                pkt_new.ip_len = str(int(pkt.ip_len) + 1000)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len += 1000

                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_multiple_syn_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_syn_pkt(pkt)
                pkt_new.seq = _seq_add(pkt_new.seq, 1000000)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(k_trace, idx)
                k_pkt_new.frame_len = 66

                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_pure_fin(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_pkt(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(k_trace, idx)
                k_pkt_new.frame_len = 66

                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_bad_rst_fin(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        choice = random.randint(0, 1)
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(k_trace, idx)

                if choice == 0:
                    pkt_new = craft_rst_pkt(pkt)
                    k_pkt_new.frame_len = 66
                else:
                    pkt_new = craft_fin_ack_pkt(pkt)

                pkt_new.seq = _seq_add(pkt_new.seq, 1000000)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_data_overlapping(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        direction = None
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # only inject packets in one direction
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0:
                if direction is None:
                    direction = pkt.src_ip
                if direction == pkt.src_ip:
                    pkt_new = craft_data_pkt(pkt)
                    pkt_new.seq = _seq_add(pkt_new.seq, 1)
                    pkt_new.ip_len = str(int(pkt_new.ip_len) - 1)
                    pkt_new.payload_len = str(int(pkt_new.payload_len) - 1)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)

                    k_pkt_new = copy.deepcopy(k_pkt)
                    k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_pkt_new.frame_len = 66
                    injected_k_trace.append(k_pkt_new)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_data_without_ack_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        direction = None
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # only inject packets in one direction
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0:
                if direction is None:
                    direction = pkt.src_ip
                if direction == pkt.src_ip:
                    pkt_new = craft_data_pkt(pkt)
                    pkt_new.flags = ''
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)

                    k_pkt_new = copy.deepcopy(k_pkt)
                    k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_pkt_new.frame_len = 66
                    injected_k_trace.append(k_pkt_new)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_data_bad_ack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        direction = None
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # only inject packets in one direction
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0:
                if direction is None:
                    direction = pkt.src_ip
                if direction == pkt.src_ip:
                    pkt_new = craft_data_pkt(pkt)
                    pkt_new.ack = _seq_add(pkt_new.ack, 1000000)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)

                    k_pkt_new = copy.deepcopy(k_pkt)
                    k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                        k_trace, idx)
                    k_pkt_new.frame_len = 66
                    injected_k_trace.append(k_pkt_new)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_seq_jump_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_data_pkt(pkt)
                # an out-of-window data packet
                pkt_new.seq = _seq_add(pkt_new.seq, 1000000)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 100)
                pkt_new.payload_len = '100'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66 + 100
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_zeek_underflow_seq_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        has_seen_data = False
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # make the first data packet into an evasion packet
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0 and not has_seen_data:
                has_seen_data = True
                pkt_new = copy.deepcopy(pkt)
                # make SEQ = ISN - 1
                # pad the payload with 2 extra bytes on the left of the payload
                pkt_new.seq = _seq_sub('0', 1)
                pkt_new.ip_len = str(int(pkt_new.ip_len) + 2)
                pkt_new.payload_len = str(int(pkt_new.payload_len) + 2)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len += 2
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


###################################################################
# Snort
###################################################################

def inject_snort_multiple_syn_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_syn_pkt(pkt)
                pkt_new.seq = _seq_add(pkt_new.seq, 10)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_in_window_fin_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_pkt(pkt)
                pkt_new.seq = _seq_add(pkt_new.seq, 10)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_fin_ack_bad_ack_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_ack_pkt(pkt)
                pkt_new.ack = _seq_add(pkt_new.ack, 1000000)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_fin_ack_md5_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_ack_pkt(pkt)
                pkt_new.tcp_opt_md5header = '1'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_in_window_rst_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_pkt(pkt)
                pkt_new.seq = _seq_add(pkt_new.seq, 10)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_rst_bad_timestamp_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_pkt(pkt)
                pkt_new.tcp_opt_tsval = _seq_sub(
                    pkt_new.tcp_opt_tsval, 1000000)
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_rst_md5_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_pkt(pkt)
                pkt_new.tcp_opt_md5header = '1'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_rst_ack_bad_ack_num_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_ack_pkt(pkt)
                pkt_new.ack = _seq_sub(pkt_new.ack, 100)
                # this packet should be sent in SYN_RECV state, so it's before the ACK
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_trace.append(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                    k_trace, idx)
                k_pkt_new.frame_len = 66
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_partial_in_window_rst_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_ack_pkt(pkt)
                pkt_new.seq = _seq_sub(pkt_new.seq, 10)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                k_pkt_new.frame_len = 76
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_urgent_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        has_seen_data = False
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # make the first data packet into an evasion packet
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0 and not has_seen_data:
                has_seen_data = True
                pkt_new = copy.deepcopy(pkt)
                pkt_new.flags += 'U'
                # make urgent pointer point to somewhere in the payload
                pkt_new.urgptr = '8'
                # add one-byte urgent data
                pkt_new.ip_len = str(int(pkt_new.ip_len) + 1)
                pkt_new.payload_len = str(int(pkt_new.payload_len) + 1)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len += 1
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_snort_time_gap_attack(dataset_dict, k_dataset_dict):
    def last_tsval(trace, curr_idx, direction):
        for i in reversed(range(curr_idx)):
            pkt = trace[i]
            if pkt.src_ip == direction and pkt.tcp_opt_tsval != '-1':
                return pkt.tcp_opt_tsval
        return None

    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        has_seen_data = False
        pkt_idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # make the first data packet into an evasion packet
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0 and not has_seen_data:
                has_seen_data = True
                pkt_new = copy.deepcopy(pkt)
                last_ts = last_tsval(trace, pkt_idx, pkt.src_ip)
                # this strategy only works if the connection is using TCP timstamp
                if last_ts:
                    pkt_new.tcp_opt_tsval = _seq_add(int(last_ts), 0x7fffffff)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)
                else:
                    # this connection is not applicable
                    injected_trace.append(pkt)
            else:
                injected_trace.append(pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


###################################################################
# GFW
###################################################################

def inject_gfw_bad_rst_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        choice = random.randint(0, 1)
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_pkt(pkt)
                if choice == 0:
                    pkt_new.chksum = '1'
                else:
                    pkt_new.tcp_opt_md5header = '1'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_bad_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        direction = None
        choice = random.randint(0, 2)
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # only inject packets in one direction
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0:
                if direction is None:
                    direction = pkt.src_ip
                if direction == pkt.src_ip:
                    pkt_new = craft_data_pkt(pkt)
                    if choice == 0:
                        pkt_new.chksum = '1'
                    elif choice == 1:
                        pkt_new.tcp_opt_md5header = '1'
                    else:
                        pkt_new.tcp_opt_tsval = _seq_sub(
                            pkt_new.tcp_opt_tsval, 1000000)
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                injected_k_trace.append(k_pkt_new)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_data_without_ack_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        direction = None
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # only inject packets in one direction
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0:
                if direction is None:
                    direction = pkt.src_ip
                if direction == pkt.src_ip:
                    pkt_new = craft_data_pkt(pkt)
                    pkt_new.flags.replace('A', '')
                    adv_pkt_info[connection_id].append(len(injected_trace))
                    injected_trace.append(pkt_new)
                    k_pkt_new = copy.deepcopy(k_pkt)
                    injected_k_trace.append(k_pkt_new)
            injected_trace.append(pkt)
            injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_underflow_seq_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        has_seen_data = False
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            # make the first data packet into an evasion packet
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 0 and not has_seen_data:
                has_seen_data = True
                pkt_new = copy.deepcopy(pkt)
                # make SEQ = ISN - 1
                # pad the payload with 2 extra bytes on the left of the payload
                pkt_new.seq = _seq_sub('0', 1)
                pkt_new.ip_len = str(int(pkt_new.ip_len) + 2)
                pkt_new.payload_len = str(int(pkt_new.payload_len) + 2)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_small_segments_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        k_trace = k_dataset_dict[connection_id]
        has_seen_established = False
        has_seen_data = False
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            if 'A' in set(pkt.flags) and int(pkt.payload_len) > 8 and not has_seen_data:
                # split the packet into 8 bytes + remaining
                has_seen_data = True
                pkt_new_1 = copy.deepcopy(pkt)
                pkt_new_1.ip_len = str(
                    int(pkt_new_1.ip_len) - int(pkt_new_1.payload_len) + 8)
                pkt_new_1.payload_len = '8'
                pkt_new_2 = copy.deepcopy(pkt)
                pkt_new_2.ip_len = str(int(pkt_new_2.ip_len) - 8)
                pkt_new_2.payload_len = str(int(pkt_new_2.payload_len) - 8)
                pkt_new_2.seq = _seq_add(pkt_new_2.seq, 8)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new_1)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new_2)

                k_pkt_new1 = copy.deepcopy(k_pkt)
                k_pkt_new2 = copy.deepcopy(k_pkt)
                k_pkt_new1.frame_len = 66 + 8
                k_pkt_new1.frame_len -= 8
                k_pkt_new1.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new1)
                injected_k_trace.append(k_pkt_new2)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_fin_with_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_pkt(pkt)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66 + 10
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_bad_fin_ack_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        choice = random.randint(0, 2)
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_ack_pkt(pkt)
                if choice == 0:
                    pkt_new.chksum = '1'
                elif choice == 1:
                    pkt_new.tcp_opt_md5header = '1'
                else:
                    pkt_new.tcp_opt_tsval = _seq_sub(
                        pkt_new.tcp_opt_tsval, 1000000)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66 + 10
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_fin_ack_data_bad_ack_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_fin_ack_pkt(pkt)
                pkt_new.ack = _seq_add(pkt_new.ack, 1000000)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                injected_trace.append(pkt)
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66 + 10
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_out_of_window_syn_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_syn_pkt(pkt)
                pkt_new.seq = _seq_add(pkt_new.seq, 1000000)
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                # this packet should be sent in SYN_RECV state, so it's before the ACK
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_trace.append(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66 + 10
                k_pkt_new.frame_time_epoch = calculate_epoch_time(
                    k_trace, idx)
                injected_k_trace.append(k_pkt)
                injected_k_trace.append(k_pkt_new)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_retransmitted_syn_data_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_syn_pkt(pkt)
                pkt_new.seq = '0'
                pkt_new.ip_len = str(
                    int(pkt_new.ip_len) - int(pkt_new.payload_len) + 10)
                pkt_new.payload_len = '10'
                # this packet should be sent in SYN_RECV state, so it's before the ACK
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_trace.append(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66 + 10
                k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new)
                injected_k_trace.append(k_pkt)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_rst_bad_timestamp_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_pkt(pkt)
                pkt_new.tcp_opt_tsval = _seq_sub(
                    pkt_new.tcp_opt_tsval, 1000000)
                # this packet should be sent in SYN_RECV state, so it's before the ACK
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_trace.append(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66
                k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new)
                injected_k_trace.append(k_pkt)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info


def inject_gfw_rst_ack_bad_ack_num_attack(dataset_dict, k_dataset_dict):
    injected_dataset_dict, valid_dataset_dict = {}, {}
    injected_k_dataset_dict, valid_k_dataset_dict = {}, {}
    adv_pkt_info = {}
    for connection_id, trace in dataset_dict.items():
        injected_trace = []
        injected_k_trace = []
        adv_pkt_info[connection_id] = []
        has_seen_established = False
        k_trace = k_dataset_dict[connection_id]
        idx = 0
        for idx, (pkt, k_pkt) in enumerate(zip(trace, k_trace)):
            if 'A' in set(pkt.flags) and pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
                pkt_new = craft_rst_ack_pkt(pkt)
                pkt_new.ack = _seq_add(pkt_new.ack, 1000000)
                # this packet should be sent in SYN_RECV state, so it's before the ACK
                adv_pkt_info[connection_id].append(len(injected_trace))
                injected_trace.append(pkt_new)
                injected_trace.append(pkt)

                k_pkt_new = copy.deepcopy(k_pkt)
                k_pkt_new.frame_len = 66
                k_pkt_new.frame_time_epoch = calculate_epoch_time_prev(
                    k_trace, idx)
                injected_k_trace.append(k_pkt_new)
                injected_k_trace.append(k_pkt)
            else:
                injected_trace.append(pkt)
                injected_k_trace.append(k_pkt)
        if has_seen_established:
            injected_dataset_dict[connection_id] = injected_trace
            injected_k_dataset_dict[connection_id] = injected_k_trace
            valid_dataset_dict[connection_id] = trace
            valid_k_dataset_dict[connection_id] = k_trace
    return injected_dataset_dict, valid_dataset_dict, injected_k_dataset_dict, valid_k_dataset_dict, adv_pkt_info
