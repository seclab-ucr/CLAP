from inject_attack import read_dataset, dump_injected_dataset

import argparse
import random
import copy

from collections import Counter
import operator

# https://elixir.bootlin.com/linux/latest/source/net/netfilter/nf_conntrack_proto_tcp.c
nf_conntrack_states = [
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT",
    "CLOSE_WAIT",
    "LAST_ACK",
    "TIME_WAIT",
    "CLOSE",
    "SYN_SENT2",
]

SEQ_THRESHOLD = 1000000


def read_kitsune_ds(fpath):
    with open(fpath, 'r') as fin:
        data = fin.readlines()
    dataset_dict = {}
    kitsune_header = data[0]
    del data[0]
    for row in data:
        connection_id = row.split("\t")[0]
        if connection_id not in dataset_dict:
            dataset_dict[connection_id] = [row]
        else:
            dataset_dict[connection_id].append(row)
    return dataset_dict, kitsune_header


def dump_kitsune_ds(ds_dict, fpath, header):
    with open(fpath, 'w') as fout, open(fpath + '.tsv', 'w') as fout2:
        fout.write(header)
        fout2.write('\t'.join(header.split('\t')[2:]))
        for _, trace in ds_dict.items():
            for pkt_idx in range(len(trace)):
                fout.write(trace[pkt_idx])
                fout2.write(
                    '\t'.join(trace[pkt_idx].strip('\n').split('\t')[2:] + ['']*11) + '\n')


def distill_ds(dataset_dict, kitsune_dataset_dict, deduplicate=False, debug=False):
    new_ds = {}
    kitsune_new_ds = {}
    for connection_id, trace in dataset_dict.items():
        distilled_trace = []
        distilled_k_trace = kitsune_dataset_dict[connection_id]
        has_seen_established = False
        for i in range(len(trace)):
            pkt = trace[i]
            if deduplicate and i != 0:
                if trace[i-1].get_hash() == pkt.get_hash():
                    continue
            if pkt.sk_state.startswith('ESTABLISHED') and not has_seen_established:
                has_seen_established = True
            distilled_trace.append(pkt)
        if has_seen_established:
            new_ds[connection_id] = distilled_trace
            kitsune_new_ds[connection_id] = distilled_k_trace
    assert len(new_ds) == len(kitsune_new_ds), "Inequal sizes!"
    print("Size after distilling: %d" % len(new_ds))
    return new_ds, kitsune_new_ds


def alter_ds(dataset_dict_original, k_dataset_dict_original, task, opt=None, debug=False):
    seq_counter = []
    ack_counter = []
    dataset_dict = {}
    k_dataset_dict = {}

    for connection_id, trace in dataset_dict_original.items():
        k_trace = k_dataset_dict_original[connection_id]
        assert len(trace) == len(k_trace), "[ERROR] Different sizes!"

        if task == 'remove_abnormal':
            should_skip = False
            for pkt in trace:
                if int(pkt.seq) > SEQ_THRESHOLD:
                    should_skip = True
                    break
            if should_skip:
                continue
            altered_trace = trace

        if task == 'incremental_seq_ack_strict':
            altered_trace = []
            outbound_flags, inbound_flags = set(), set()
            outbound_seq, inbound_seq = [], []
            outbound_ack, inbound_ack = [], []
            outbound_attk_id = trace[0].get_attack_id()
            tuples = set()
            debug_flag = False

            for i in range(len(trace)):
                pkt = trace[i]
                if pkt.get_attack_id() == outbound_attk_id:
                    tuples.add(pkt.get_tuple_id()[0])
                    tuples.add(pkt.get_tuple_id()[1])
                    for f in pkt.flags:
                        outbound_flags.add(f)
                    outbound_seq.append(int(pkt.seq))
                    if 'A' in set(pkt.flags):
                        outbound_ack.append(int(pkt.ack))
                else:
                    tuples.add(pkt.get_tuple_id()[0])
                    tuples.add(pkt.get_tuple_id()[1])
                    for f in pkt.flags:
                        inbound_flags.add(f)
                    inbound_seq.append(int(pkt.seq))
                    if 'A' in set(pkt.flags):
                        inbound_ack.append(int(pkt.ack))

            if len(tuples) != 2:
                continue

            if 'S' not in outbound_flags:
                debug_flag = True
                initial_client_seq = min(outbound_seq + inbound_ack) - 1
            else:
                initial_client_seq = int(trace[0].seq)

            for i in range(len(trace)):
                pkt = trace[i]
                if pkt.get_attack_id() != outbound_attk_id:
                    initial_server_seq = int(pkt.seq)
                    first_inbound_pkt_idx = i
                    break
            if 'S' not in inbound_flags:
                debug_flag = True
                initial_server_seq = min(inbound_seq + outbound_ack) - 1

            invalid_seq = False
            for i in range(len(trace)):
                curr_pkt = trace[i]
                new_pkt = copy.deepcopy(curr_pkt)
                curr_ack = int(curr_pkt.ack)
                curr_seq = int(curr_pkt.seq)
                if curr_pkt.get_attack_id() == outbound_attk_id:
                    # meaning this is outbound packet
                    delta_seq = ((curr_seq - initial_client_seq) % 2**32)
                    delta_ack = ((curr_ack - initial_server_seq) % 2**32)
                    new_pkt.seq = '%d' % delta_seq
                    if curr_seq == initial_client_seq - 1:
                        invalid_seq = True
                    if i == 0 or 'A' not in set(curr_pkt.flags):
                        if i == 0 and debug_flag:
                            new_pkt.ack = '1'
                        else:
                            new_pkt.ack = '0'
                    else:
                        new_pkt.ack = '%d' % delta_ack
                else:
                    # meaning this is inbound packet
                    delta_seq = ((curr_seq - initial_server_seq) % 2**32)
                    delta_ack = ((curr_ack - initial_client_seq) % 2**32)
                    new_pkt.seq = '%d' % delta_seq
                    if curr_seq == initial_server_seq - 1:
                        invalid_seq = True
                    if i == 0 or 'A' not in set(curr_pkt.flags):
                        new_pkt.ack = '0'
                    if i == first_inbound_pkt_idx and 'S' in set(curr_pkt.flags) and 'A' in set(curr_pkt.flags):
                        new_pkt.ack = '1'
                    else:
                        new_pkt.ack = '%d' % delta_ack

                if not invalid_seq:
                    seq_counter.append(int(new_pkt.seq))
                    ack_counter.append(int(new_pkt.ack))
                altered_trace.append(new_pkt)

            if invalid_seq:
                continue

        if task == 'incremental_seq_ack_strict_old':
            altered_trace = []

            outbound_attk_id = trace[0].get_attack_id()
            initial_client_seq = int(trace[0].seq)
            for i in range(len(trace)):
                pkt = trace[i]
                if pkt.get_attack_id() != outbound_attk_id:
                    initial_server_seq = int(pkt.seq)
                    first_inbound_pkt_idx = i
                    break
            for i in range(len(trace)):
                curr_pkt = trace[i]
                new_pkt = copy.deepcopy(curr_pkt)
                curr_ack = int(curr_pkt.ack)
                curr_seq = int(curr_pkt.seq)
                if curr_pkt.get_attack_id() == outbound_attk_id:
                    # meaning this is outbound packet
                    new_pkt.seq = '%d' % (
                        (curr_seq - initial_client_seq) % 2**32)
                    if i == 0 or i == first_inbound_pkt_idx:
                        new_pkt.ack = '0'
                    else:
                        new_pkt.ack = '%d' % (
                            (curr_ack - initial_server_seq) % 2**32)
                else:
                    # meaning this is inbound packet
                    new_pkt.seq = '%d' % (
                        (curr_seq - initial_server_seq) % 2**32)
                    if i == 0 or i == first_inbound_pkt_idx:
                        new_pkt.ack = '0'
                    else:
                        new_pkt.ack = '%d' % (
                            (curr_ack - initial_client_seq) % 2**32)

                altered_trace.append(new_pkt)

        if task == 'coarse_grained_label':
            for pkt in trace:
                for tcp_state in nf_conntrack_states:
                    if tcp_state in pkt.sk_state:
                        if 'OOW' in pkt.sk_state:
                            pkt.sk_state = tcp_state + '_OOW'
                        else:
                            pkt.sk_state = tcp_state + '_IW'
            altered_trace = trace

        if task == 'coarse_grained_label_limited':
            for pkt in trace:
                if pkt.sk_state.startswith('ESTABLISHED') or pkt.sk_state.startswith("SYN_"):
                    continue
                for tcp_state in nf_conntrack_states:
                    if tcp_state in pkt.sk_state:
                        pkt.sk_state = tcp_state
            altered_trace = trace

        if task == 'coarse_grained_label_very_limited':
            for pkt in trace:
                if pkt.sk_state.startswith('ESTABLISHED'):
                    continue
                for tcp_state in nf_conntrack_states:
                    if tcp_state in pkt.sk_state:
                        pkt.sk_state = tcp_state
            altered_trace = trace

        if task == 'most_coarse_grained_label':
            for pkt in trace:
                for tcp_state in nf_conntrack_states:
                    if tcp_state in pkt.sk_state:
                        pkt.sk_state = tcp_state
            altered_trace = trace

        if task == 'coarse_grained_label_seperate':
            for pkt in trace:
                sk_state_str = pkt.sk_state
                tcp_state_str = ''
                for tcp_state in nf_conntrack_states:
                    if tcp_state in sk_state_str:
                        tcp_state_str = tcp_state
                        break
                seq_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-9] or 'OOW' in sk_state_str.split('_')[-8] else 'IW'
                ack_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-4] or 'OOW' in sk_state_str.split('_')[-3] else 'IW'
                pkt.sk_state = '_'.join(
                    [tcp_state_str, seq_in_window, ack_in_window])
            altered_trace = trace

        if task == 'coarse_grained_label_seperate_limited':
            for pkt in trace:
                sk_state_str = pkt.sk_state
                tcp_state_str = ''
                for tcp_state in nf_conntrack_states:
                    if tcp_state in sk_state_str:
                        tcp_state_str = tcp_state
                        break
                seq_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-9] or 'OOW' in sk_state_str.split('_')[-8] else 'IW'
                ack_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-4] or 'OOW' in sk_state_str.split('_')[-3] else 'IW'
                overall_in_window = 'OOW' if seq_in_window == 'OOW' or ack_in_window == 'OOW' else 'IW'
                if pkt.sk_state.startswith('ESTABLISHED'):
                    pkt.sk_state = '_'.join(
                        [tcp_state_str, seq_in_window, ack_in_window])
                else:
                    pkt.sk_state = '_'.join([tcp_state_str, overall_in_window])
            altered_trace = trace

        if task == 'coarse_grained_label_overall':
            for pkt in trace:
                sk_state_str = pkt.sk_state
                tcp_state_str = ''
                for tcp_state in nf_conntrack_states:
                    if tcp_state in sk_state_str:
                        tcp_state_str = tcp_state
                        break
                seq_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-9] or 'OOW' in sk_state_str.split('_')[-8] else 'IW'
                ack_in_window = 'OOW' if 'OOW' in sk_state_str.split(
                    '_')[-4] or 'OOW' in sk_state_str.split('_')[-3] else 'IW'
                overall_in_window = 'OOW' if seq_in_window == 'OOW' or ack_in_window == 'OOW' else 'IW'
                pkt.sk_state = '_'.join([tcp_state_str, overall_in_window])
            altered_trace = trace

        if task == 'filter_capture_loss':
            found_loss = False
            if len(trace) == 1:
                trace[0].arrival_timestamp = '0.0'
                trace[0].tcp_timestamp = '0.0'
                altered_trace = trace
                continue
            new_ts = ['0.0']
            new_arr_ts = ['0.0']
            for i in range(1, len(trace)):
                tcp_ts_delta = float(
                    trace[i].tcp_timestamp) - float(trace[i-1].tcp_timestamp)
                tcp_arr_ts_delta = float(
                    trace[i].arrival_timestamp) - float(trace[i-1].arrival_timestamp)
                new_ts.append(str(tcp_ts_delta))
                new_arr_ts.append(str(tcp_arr_ts_delta))
            if found_loss:
                print("Found a large inter-packet time gap: %f" % tcp_ts_delta)
                print("Found a large inter-packet time gap: %f" %
                      tcp_arr_ts_delta)
                continue
            else:
                for i in range(len(trace)):
                    trace[i].tcp_timestamp = new_ts[i]
                    trace[i].arrival_timestamp = new_arr_ts[i]
                altered_trace = trace

        assert len(altered_trace) == len(
            k_trace), "[ERROR] Different size of traces: (%s, %s) -- (%d, %d)" % (task, connection_id, len(altered_trace), len(k_trace))
        dataset_dict[connection_id] = altered_trace
        k_dataset_dict[connection_id] = k_trace

    if debug:
        if task == 'incremental_seq_ack_strict':
            print(sorted(seq_counter, key=lambda r: r[0], reverse=True)[:1000])
            print(sorted(ack_counter, reverse=True)[:100])
            input("Press Enter to continue...")
    assert len(dataset_dict) == len(k_dataset_dict), "Different sizes!"
    print("[TASK: %s] Size before/after preprocessing: %d | %d" %
          (task, len(dataset_dict_original), len(dataset_dict)))
    return dataset_dict, k_dataset_dict


def partition_ds(dataset_dict, kitsune_dataset_dict, ratio):
    all_connection_ids = list(dataset_dict.keys())
    random.shuffle(all_connection_ids)
    n = len(all_connection_ids)
    split_idx = int(n/ratio)
    train_ids = all_connection_ids[:-split_idx]
    test_ids = all_connection_ids[-split_idx:]
    train_set, test_set = {}, {}
    kitsune_train_set, kitsune_test_set = {}, {}
    for id in train_ids:
        train_set[id] = dataset_dict[id]
        kitsune_train_set[id] = kitsune_dataset_dict[id]
    for id in test_ids:
        test_set[id] = dataset_dict[id]
        kitsune_test_set[id] = kitsune_dataset_dict[id]
    return train_set, test_set, kitsune_train_set, kitsune_test_set


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Use this script to inject attacks.')
    parser.add_argument('--dataset', type=str, help='Path to dataset.')
    parser.add_argument('--kitsune-dataset', type=str,
                        help='Path to dataset.')
    parser.add_argument('--distilled-dataset', type=str,
                        help='Path to dump dataset w/ injected attack.')
    parser.add_argument('--distill-by-handshake', action='store_true',
                        help='Type of connections to distill.')
    parser.add_argument('--ratio', type=int, default=-1,
                        help='Ratio to split the dataset.')
    parser.add_argument('--deduplicate', action='store_true', default=False,
                        help='Whether to filter duplicate packets in trace.')
    parser.add_argument('--incremental-seq-ack-strict', action='store_true', default=False,
                        help='Whether to change seq/ack in trace.')
    parser.add_argument('--incremental-seq-ack-strict-old', action='store_true', default=False,
                        help='Whether to change seq/ack in trace.')
    parser.add_argument('--coarse-grained-label', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--coarse-grained-label-limited', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--coarse-grained-label-very-limited', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--most-coarse-grained-label', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--coarse-grained-label-seperate', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--coarse-grained-label-seperate-limited', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--coarse-grained-label-overall', action='store_true', default=False,
                        help='Whether to alter labels in trace.')
    parser.add_argument('--use-direction', action='store_true', default=False,
                        help='Whether to use the direction while dumping.')
    parser.add_argument('--filter-huge-ack-seq', action='store_true', default=False,
                        help='Whether to use the direction while dumping.')
    parser.add_argument('--filter-capture-loss', action='store_true', default=False,
                        help='Whether to use the direction while dumping.')
    parser.add_argument('--dummy', action='store_true', help='Dummy (unused) arg')
    args = parser.parse_args()

    ds = read_dataset(args.dataset)
    kitsune_ds, kitsune_header = read_kitsune_ds(args.kitsune_dataset)

    if args.distill_by_handshake:
        ds, kitsune_ds = distill_ds(ds, kitsune_ds, args.deduplicate)

    if args.incremental_seq_ack_strict:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'incremental_seq_ack_strict')

    if args.incremental_seq_ack_strict_old:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'incremental_seq_ack_strict_old')

    if args.most_coarse_grained_label:
        ds, kitsune_ds = alter_ds(ds, kitsune_ds, 'most_coarse_grained_label')

    if args.coarse_grained_label:
        ds, kitsune_ds = alter_ds(ds, kitsune_ds, 'coarse_grained_label')

    if args.coarse_grained_label_seperate:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'coarse_grained_label_seperate')

    if args.coarse_grained_label_seperate_limited:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'coarse_grained_label_seperate_limited')

    if args.coarse_grained_label_overall:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'coarse_grained_label_overall')

    if args.coarse_grained_label_limited:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'coarse_grained_label_limited')

    if args.coarse_grained_label_very_limited:
        ds, kitsune_ds = alter_ds(
            ds, kitsune_ds, 'coarse_grained_label_very_limited')

    if args.filter_capture_loss:
        ds, kitsune_ds = alter_ds(ds, kitsune_ds, 'filter_capture_loss')

    if args.ratio != -1:
        rnn_train_set, rnn_test_set, kitsune_train_set, kitsune_test_set = partition_ds(
            ds, kitsune_ds, args.ratio)
        dump_injected_dataset(
            rnn_train_set, args.distilled_dataset + '.train.rnn', use_direction=args.use_direction)
        dump_injected_dataset(
            rnn_test_set, args.distilled_dataset + '.test.rnn', use_direction=args.use_direction)

        train_set, kitsune_train_set = alter_ds(
            rnn_train_set, kitsune_train_set, 'remove_abnormal')
        test_set, kitsune_test_set = alter_ds(
            rnn_test_set, kitsune_test_set, 'remove_abnormal')
        dump_injected_dataset(
            train_set, args.distilled_dataset + '.train', use_direction=args.use_direction)
        dump_injected_dataset(
            test_set, args.distilled_dataset + '.test', use_direction=args.use_direction)
        dump_kitsune_ds(
            kitsune_train_set, args.distilled_dataset + '.train.kitsune', kitsune_header)
        dump_kitsune_ds(
            kitsune_test_set, args.distilled_dataset + '.test.kitsune', kitsune_header)
