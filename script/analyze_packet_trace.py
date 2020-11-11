#!/usr/bin/env python

import os
from scapy.all import *
from scapy.error import Scapy_Exception
from utils import MyPacket

# Error code table
ERR_NO_TCP_PKT = -2
ERR_PCAP_MALFORMAT = -3
ERR_NO_SK_STATE_FOUND = -4
ERR_INVALID_SK_STATE = -5
ERR_NUM_PKTS_MISMATCH = -6
ERR_UNKNOWN_ERR = -7
ERR_NO_PCAP_ID_FOUND = -8
ERR_NO_TWO_WAY_COMM = -9
ERR_NO_ESTABLISHED = -10
ERR_REPLAY = -11
ERR_MORE_THAN_TWO_ENDPOINTS = -12

TCP_STATE_SYN_NOT_DETECTED = "SYN_NOT_DETECTED"
TCP_STATE_NOT_TCP_PKT = "NOT_TCP_PKT"
TCP_STATE_UNKNOWN_ERR = "ERR_UNKNOWN"
TCP_STATE_ESTABLIAHSED = "ESTABLISHED"
TCP_SUBSTATE_EMPTY = "EMPTY_STATE"
REPLAY_ERR = "ERR_REPLAY"

ALL_TCP_OPT_SET = set()
ALL_IP_OPT_SET = set()


def get_filenames(path, time_order=False):
    filenames = os.listdir(path)
    if time_order:
        fnames_w_timestamp = {}
        for fname in filenames:
            pcap_fname = fname.strip(".pcap")
            date, time, num_packet = pcap_fname.split("_")[-3:]
            timestamp = int(date + time + num_packet)
            fnames_w_timestamp[fname] = timestamp
        sorted_fnames = [k for k, v in sorted(
            fnames_w_timestamp.items(), key=lambda x: x[1])]
        return sorted_fnames
    else:
        return filenames


def read_symtcp_tcp_state_mapping_file(fpath):
    sk_mapping = {}
    with open(fpath) as fin:
        data = fin.readlines()
    for line in data:
        line = line.strip("\n")
        src_ip, src_port, dst_ip, dst_port, seq, ack = line.split(",")[:6]
        dataoff, flags, window, chksum, urgptr = line.split(",")[-6:-1]
        attack_id = ','.join([src_ip, src_port, dst_ip, dst_port])
        attack_packet_id = ','.join([dataoff, flags, window, chksum, urgptr])
        reverse_attack_id = ','.join([dst_ip, dst_port, src_ip, src_port])
        sk_state = line.split(",")[-1]
        if attack_id in sk_mapping:
            sk_mapping[attack_id][attack_packet_id] = sk_state
        else:
            sk_mapping[attack_id] = {attack_packet_id: sk_state}
        if reverse_attack_id in sk_mapping:
            sk_mapping[reverse_attack_id][attack_packet_id] = sk_state
        else:
            sk_mapping[reverse_attack_id] = {attack_packet_id: sk_state}
    return sk_mapping


def read_wami_tcp_state_mapping_file(fpath):
    tcp_state_mapping = {}
    with open(fpath) as fin:
        data = fin.readlines()
    for line in data:
        line = line.strip("\n")
        states = line.split(',')
        pcap_id = states[0]
        del states[0]
        tcp_state_mapping[pcap_id] = states
    return tcp_state_mapping


def find_sk_state(attack_id, sk_mapping, debug=False):
    if debug:
        print(attack_id)
        for k, v in sk_mapping.items():
            input(str(k) + str(v))
    try:
        sk_state = sk_mapping[attack_id]
        if debug:
            input("[DEBUG] Attack ID %s is in sk_state %s" %
                  (attack_id), str(sk_state))
        return sk_mapping[attack_id]
    except KeyError:
        if debug:
            input("[ERROR] attack_id %s not found!" % str(attack_id))
        return ERR_NO_SK_STATE_FOUND


def find_wami_tcp_pkt_state(attack_id, sk_mapping, debug=False):
    if debug:
        print(attack_id)
        for k, v in sk_mapping.items():
            input(str(k) + str(v))
    try:
        pcap_id, pkt_idx = attack_id.split(',')
        pkt_idx = int(pkt_idx)
        states = sk_mapping[pcap_id]
        state = states[pkt_idx]
        if debug:
            input("[DEBUG] Attack ID %s has sk_state %s" %
                  (attack_id), str(state))
        return state
    except KeyError:
        if debug:
            input("[ERROR] attack_id %s not found!" % str(attack_id))
        return ERR_NO_SK_STATE_FOUND


def verify_if_tcp_checksum_is_correct(pkt, debug=False):
    original_chksum = pkt[TCP].chksum
    del pkt[TCP].chksum
    pkt = pkt.__class__(bytes(pkt))
    scapy_chksum = pkt[TCP].chksum
    pkt[TCP].chksum = original_chksum
    if debug:
        input("Original: %s; recalculated: %s" %
              (str(original_chksum), str(scapy_chksum)))
    if original_chksum == scapy_chksum:
        return True
    else:
        input("%s, %s" % (original_chksum, scapy_chksum))
        print("[INFO] Wrong chceksum!")
        return False


def verify_if_ip_checksum_is_correct(pkt, debug=False):
    original_chksum = pkt[IP].chksum
    del pkt[IP].chksum
    pkt = pkt.__class__(bytes(pkt))
    scapy_chksum = pkt[IP].chksum
    pkt[IP].chksum = original_chksum
    if debug:
        input("Original: %s; recalculated: %s" %
              (str(original_chksum), str(scapy_chksum)))
    if original_chksum == scapy_chksum:
        return True
    else:
        input("[INFO] Wrong IP chceksum!")
        return False


def parse_pcap_file(pcap_file_path, sk_mapping, pcap_fname_type="symtcp", debug=False):
    global ALL_IP_OPT_SET, ALL_TCP_OPT_SET
    try:
        packets = rdpcap(pcap_file_path)
    except Exception as err:
        print("[ERROR] Pcap reading error: %s" % err)
        return ERR_PCAP_MALFORMAT

    pkt_trace = []

    pcap_fname = os.path.basename(pcap_file_path).replace(".pcap", "")

    # A bunch of checks to make sure the pcap is good
    if pcap_fname_type == "symtcp":
        date, time, num_packet = pcap_fname.split("_")[-3:]
        timestamp = date + time
    if pcap_fname_type == "wami":
        if sk_mapping:
            date, pcap_id = pcap_fname.rsplit("-")
            num_packet = "-1"
            timestamp = pcap_id
            if pcap_id not in sk_mapping:
                return ERR_NO_PCAP_ID_FOUND
            if len(packets) != len(sk_mapping[pcap_id]):
                return ERR_NUM_PKTS_MISMATCH
            if TCP_STATE_NOT_TCP_PKT in set(sk_mapping[pcap_id]):
                return ERR_NO_TCP_PKT
            if TCP_STATE_UNKNOWN_ERR in set(sk_mapping[pcap_id]):
                return ERR_UNKNOWN_ERR
            if REPLAY_ERR in set(sk_mapping[pcap_id]):
                return ERR_REPLAY
            if TCP_SUBSTATE_EMPTY in set(sk_mapping[pcap_id]):
                return ERR_INVALID_SK_STATE
            if len(packets) == 1:
                return -99
            if len(packets) > 200:
                return -50  # TODO: change to error code
        else:
            pcap_id = pcap_fname.strip('.pcap').split('_')[-1]
            num_packet = "-1"
            timestamp = pcap_id

    # Let's then check if this pcap does contain two-way commnications.
    # If not, we should skip this pcap.
    src_tuple_set = set()
    dst_tuple_set = set()
    tuples_set = set()
    for pkt in packets:
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport
        src_tuple = ':'.join([src_ip, str(src_port)])
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        dst_tuple = ':'.join([dst_ip, str(dst_port)])
        src_tuple_set.add(src_tuple)
        dst_tuple_set.add(dst_tuple)
        tuples_set.add(src_tuple)
        tuples_set.add(dst_tuple)
    if len(src_tuple_set) == len(dst_tuple_set) == 1:
        return ERR_NO_TWO_WAY_COMM
    if len(tuples_set) != 2:
        return ERR_MORE_THAN_TWO_ENDPOINTS

    for pkt_idx in range(len(packets)):
        pkt = packets[pkt_idx]
        if IP not in pkt or TCP not in pkt:
            continue

        # Let's process each packet
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        seq = pkt[TCP].seq
        ack = pkt[TCP].ack
        dataoff = pkt[TCP].dataofs*4
        flags = pkt[TCP].flags
        window = pkt[TCP].window
        arrival_timestamp = pkt.time
        tcp_timestamp = pkt[TCP].time
        ip_len = pkt[IP].len
        ip_ttl = pkt[IP].ttl
        ip_ihl = pkt[IP].ihl*4
        ip_id = pkt[IP].id
        ip_version = pkt[IP].version
        ip_tos = pkt[IP].tos
        ip_opt_non_standard = '0'
        ip_options = dict(pkt[IP].options)
        tcp_options = dict(pkt[TCP].options)
        ALL_IP_OPT_SET = ALL_IP_OPT_SET.union(set(list(ip_options.keys())))
        ALL_TCP_OPT_SET = ALL_TCP_OPT_SET.union(set(list(tcp_options.keys())))
        tcp_opt_mss = tcp_options['MSS'] if 'MSS' in tcp_options else '-1'
        tcp_opt_tsval = tcp_options['Timestamp'][0] if 'Timestamp' in tcp_options else '-1'
        tcp_opt_tsecr = tcp_options['Timestamp'][1] if 'Timestamp' in tcp_options else '-1'
        tcp_opt_wscale = tcp_options['WScale'] if 'WScale' in tcp_options else '-1'
        tcp_opt_uto = tcp_options['UserTimeout'] if 'UserTimeout' in tcp_options else '-1'
        # assuming this is correct
        tcp_opt_md5header = '0' if 'MD5header' in tcp_options else '-1'
        tcp_opt_non_standard = '0'

        # Kitsune-related features (for baseline)
        kitsune_frame_time_epoch = pkt.time
        kitsune_frame_len = len(pkt)
        kitsune_eth_src = pkt.src
        kitsune_eth_dst = pkt.dst
        kitsune_ip_src = pkt[IP].src
        kitsune_ip_dst = pkt[IP].dst
        kitsune_tcp_sport = pkt[TCP].sport
        kitsune_tcp_dport = pkt[TCP].dport

        if verify_if_ip_checksum_is_correct(pkt):
            ip_chksum = '0'
        else:
            ip_chksum = '1'

        chksum = '0'

        # This calc is based on the assumption that IP header is 20byte long
        payload_len = ip_len - ip_ihl - dataoff

        urgptr = pkt[TCP].urgptr

        if pcap_fname_type == "symtcp":
            attack_id = ','.join(
                [src_ip, str(src_port), dst_ip, str(dst_port)])
        if pcap_fname_type == "wami":
            attack_id = ','.join([pcap_id, str(pkt_idx)])
        if debug:
            print("[DEBUG] attack_id: %s" % attack_id)

        if pcap_fname_type == "symtcp":
            sk_state = find_sk_state(
                attack_id, sk_mapping, debug=False)
        if pcap_fname_type == "wami":
            if sk_mapping:
                sk_state = find_wami_tcp_pkt_state(
                    attack_id, sk_mapping, debug=False)
                if sk_state == TCP_STATE_SYN_NOT_DETECTED:
                    continue
                if sk_state == TCP_SUBSTATE_EMPTY:
                    return ERR_INVALID_SK_STATE
            else:
                sk_state = "DUMMY"

        curr_pkt = MyPacket(src_ip, src_port, dst_ip,
                            dst_port, seq, ack, dataoff,
                            flags, window, chksum, urgptr,
                            timestamp, payload_len, sk_state,
                            pcap_fname, ip_len, ip_ttl, ip_ihl,
                            ip_chksum, ip_version, ip_tos, ip_id, ip_opt_non_standard,
                            tcp_opt_mss, tcp_opt_tsval, tcp_opt_tsecr,
                            tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header, tcp_opt_non_standard,
                            tcp_timestamp, arrival_timestamp, kitsune_frame_time_epoch, kitsune_frame_len,
                            kitsune_eth_src, kitsune_eth_dst, kitsune_ip_src, kitsune_ip_dst, kitsune_tcp_sport,
                            kitsune_tcp_dport)
        if debug:
            curr_pkt.print_debug()

        pkt_trace.append(curr_pkt)

    if len(pkt_trace) == 0:
        print("No TCP packet found!")
        return ERR_NO_TCP_PKT
    return pkt_trace


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Use this script to pre-process the raw datasets.')
    parser.add_argument('--pcap-dir', type=str,
                        help='Directory to collect packet trace files.')
    parser.add_argument('--sk-mapping-path', type=str,
                        help='Filename of sk_state mapping file.')
    parser.add_argument('--dataset-fpath', type=str, default='dummy_path',
                        help='Filename of dumped dataset file.')
    parser.add_argument('--kitsune-dataset-fpath', type=str, default='dummy_path',
                        help='Filename of dumped dataset file.')
    parser.add_argument('--dataset-type', type=str, default="symtcp",
                        help='Type of pcap dataset.')
    parser.add_argument('--debug', action='store_true',
                        help='Whether to dump the debugging information.')
    parser.add_argument('--use-dummy-state', action='store_true',
                        help='Whether to use dummy states.')
    parser.add_argument('--use-small-dataset', action='store_true')
    args = parser.parse_args()

    if args.dataset_type == "symtcp":
        pcap_filenames = get_filenames(args.pcap_dir, time_order=True)
    if args.dataset_type == "wami":
        pcap_filenames = get_filenames(args.pcap_dir, time_order=False)
    print("[INFO] Total number of pcap files: %d" % len(pcap_filenames))

    if args.use_dummy_state:
        sk_mapping = None
    else:
        if args.dataset_type == "symtcp":
            sk_mapping = read_symtcp_tcp_state_mapping_file(
                args.sk_mapping_path)
        elif args.dataset_type == "wami":
            sk_mapping = read_wami_tcp_state_mapping_file(args.sk_mapping_path)
            pcap_filenames = []
            for pcap_id, _ in sk_mapping.items():
                if args.use_small_dataset:
                    pcap_filenames.append('smallFlows-%s.pcap' % pcap_id)
                else:
                    pcap_filenames.append('202004071400-%s.pcap' % pcap_id)
        print("[INFO] Size of sk_state mapping: %d" % len(sk_mapping))

    pcap_filenames = sorted(pcap_filenames)
    attack_corpus = []
    cnt = 0

    if args.dataset_type == "wami":
        with open(args.dataset_fpath, 'w') as fout, open(args.kitsune_dataset_fpath, 'w') as fout2:
            fout.write(
                "ATTACK_ID,PACKET_ID,SRC_IP,SRC_PORT,DST_IP,DST_PORT,SEQ,ACK,DATAOFF,FLAGS,WINDOW,CHKSUM,URGPTR,SK_STATE,PAYLOAD_LEN,PCAP_IP,IP_LEN,IP_TTL,IP_IHL,IP_CHKSUM,IP_VERSION,IP_TOS,IP_ID,IP_OPT_NON_STANDARD,TCP_OPT_MSS,TCP_OPT_TSVAL,TCP_OPT_TSECR,TCP_OPT_WSCALE,TCP_OPT_UTO,TCP_OPT_MD5HEADER,TCP_OPT_NON_STANDARD,TCP_TIMESTAMP,ARRIVAL_TIMESTAMP\n")
            fout2.write('\t'.join(['attack_id', 'packet_id', 'frame.time_epoch', 'frame.len', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
                                   'udp.dstport', 'icmp.type', 'icmp.code', 'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac', 'arp.dst.proto_ipv4', 'ipv6.src', 'ipv6.dst\n']))
            attack_count = 0
            for pcap_fname in pcap_filenames:
                cnt += 1
                print("[INFO] Processing pcap #%d w/ filename %s..." %
                      (cnt, pcap_fname))
                pcap_fpath = '/'.join([args.pcap_dir, pcap_fname])
                pkt_trace = parse_pcap_file(
                    pcap_fpath, sk_mapping, pcap_fname_type='wami', debug=args.debug)
                if not isinstance(pkt_trace, int):
                    attack_packet_count = 0
                    for pkt in pkt_trace:
                        curr_pkt_str = pkt.get_data_str(
                            attack_count, attack_packet_count)
                        fout.write(curr_pkt_str + '\n')
                        fout2.write(pkt.get_kitsune_str(
                            attack_count, attack_packet_count) + '\n')
                        attack_packet_count += 1
                    attack_count += 1
