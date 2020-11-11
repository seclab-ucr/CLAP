from utils import MyPacket, MyKitsunePacket

import copy
import argparse
from random import randint

from symtcp_attacks import *
from liberate_attacks import *
from geneva_attacks import *


def read_dataset(fpath, mode='4tuple'):
    with open(fpath, 'r') as fin:
        data = fin.readlines()
    dataset_dict = {}
    del data[0]
    for row in data:
        row = row.strip()
        if mode == '4tuple':
            connection_id, _, src_ip, src_port, \
                dst_ip, dst_port, seq, ack, dataoff, \
                flags, window, chksum, urgptr, \
                tcp_state, payload_len, timestamp, ip_len, \
                ip_ttl, ip_ihl, ip_chksum, ip_version, \
                ip_tos, ip_id, ip_opt_non_standard, tcp_opt_mss, tcp_opt_tsval, \
                tcp_opt_tsecr, tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header, \
                tcp_opt_non_standard, tcp_timestamp, arrival_timestamp = row.split(
                    ',')
            pcap_fname = timestamp
            pkt = MyPacket(src_ip, src_port, dst_ip, dst_port,
                           seq, ack, dataoff, flags, window,
                           chksum, urgptr, timestamp, payload_len,
                           tcp_state, pcap_fname, int(ip_len), int(ip_ttl),
                           int(ip_ihl), ip_chksum, ip_version, ip_tos,
                           ip_id, ip_opt_non_standard, tcp_opt_mss, tcp_opt_tsval, tcp_opt_tsecr,
                           tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header, tcp_opt_non_standard,
                           tcp_timestamp, arrival_timestamp)
        if mode == 'packet_id':
            connection_id, _, direction, seq, ack, dataoff, \
                flags, window, chksum, urgptr, \
                tcp_state, payload_len, timestamp, ip_len, \
                ip_ttl, ip_ihl, ip_chksum, ip_version, \
                ip_tos, ip_id, ip_opt_non_standard, tcp_opt_mss, tcp_opt_tsval, \
                tcp_opt_tsecr, tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header, \
                tcp_opt_non_standard, tcp_timestamp, arrival_timestamp = row.split(
                    ',')
            pcap_fname = timestamp
            pkt = MyPacket(direction, int(direction), direction, int(direction),
                           seq, ack, dataoff, flags, window,
                           chksum, urgptr, timestamp, payload_len,
                           tcp_state, pcap_fname, int(ip_len), int(ip_ttl),
                           int(ip_ihl), ip_chksum, ip_version, ip_tos,
                           ip_id, ip_opt_non_standard, tcp_opt_mss, tcp_opt_tsval, tcp_opt_tsecr,
                           tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header,
                           tcp_opt_non_standard, tcp_timestamp, arrival_timestamp)
        if connection_id not in dataset_dict:
            dataset_dict[connection_id] = [pkt]
        else:
            dataset_dict[connection_id].append(pkt)
    return dataset_dict


def read_kitsune_dataset(fpath):
    dataset_dict = {}
    with open(fpath, 'r') as fin:
        data = fin.readlines()
    del data[0]
    for row in data:
        row = row.rstrip()
        connection_id, packet_id, time_epoch, frame_len, \
            eth_src, eth_dst, ip_src, ip_dst, tcp_srcport, \
            tcp_dstport = row.split('\t')
        pkt = MyKitsunePacket(time_epoch, frame_len, eth_src,
                              eth_dst, ip_src, ip_dst, tcp_srcport,
                              tcp_dstport)
        if connection_id not in dataset_dict:
            dataset_dict[connection_id] = [pkt]
        else:
            dataset_dict[connection_id].append(pkt)
    return dataset_dict


def dump_adv_pkt_info(adv_pkt_info_dict, injected_ds, fpath):
    with open(fpath + '.info', 'w') as fout:
        for conn_id, pkt_idx_lst in adv_pkt_info_dict.items():
            if conn_id not in injected_ds:
                continue
            injected_trace = injected_ds[conn_id]
            outbound_attk_id = injected_trace[0].get_attack_id()
            new_pkt_idx_lst = copy.deepcopy(pkt_idx_lst)
            for pkt_idx, pkt in enumerate(injected_trace):
                if pkt.get_attack_id() != outbound_attk_id:
                    for i, (_, old_adv_pkt_idx) in enumerate(zip(new_pkt_idx_lst, pkt_idx_lst)):
                        if pkt_idx < old_adv_pkt_idx:
                            new_pkt_idx_lst[i] -= 1
            fout.write("%s\t%s\n" % (conn_id, str(new_pkt_idx_lst)))


def dump_injected_dataset(dataset_dict, fpath, use_direction=False):
    with open(fpath, 'w') as fout:
        if not use_direction:
            fout.write(
                "ATTACK_ID,PACKET_ID,SRC_IP,SRC_PORT,DST_IP,DST_PORT,SEQ,ACK,DATAOFF,FLAGS,WINDOW,CHKSUM,URGPTR,SK_STATE,PAYLOAD_LEN,TIMESTAMP,IP_LEN,IP_TTL,IP_IHL,IP_CHKSUM,IP_VERSION,IP_TOS,IP_ID,IP_OPT_NON_STANDARD,TCP_OPT_MSS,TCP_OPT_TSVAL,TCP_OPT_TSECR,TCP_OPT_WSCALE,TCP_OPT_UTO,TCP_OPT_MD5HEADER,TCP_OPT_NON_STANDARD,TCP_TIMESTAMP,ARRIVAL_TIMESTAMP\n")
        else:
            fout.write(
                "ATTACK_ID,PACKET_ID,DIRECTION,SEQ,ACK,DATAOFF,FLAGS,WINDOW,CHKSUM,URGPTR,SK_STATE,PAYLOAD_LEN,TIMESTAMP,IP_LEN,IP_TTL,IP_IHL,IP_CHKSUM,IP_VERSION,IP_TOS,IP_ID,IP_OPT_NON_STANDARD,TCP_OPT_MSS,TCP_OPT_TSVAL,TCP_OPT_TSECR,TCP_OPT_WSCALE,TCP_OPT_UTO,TCP_OPT_MD5HEADER,TCP_OPT_NON_STANDARD,TCP_TIMESTAMP,ARRIVAL_TIMESTAMP\n")
        for connection_id, trace in dataset_dict.items():
            outbound_pkt_idx, inbound_pkt_idx = 0, 0
            outbound_pkt_cnt, inbound_pkt_cnt = 0, 0
            outbound_attk_id = trace[0].get_attack_id()
            # 1st pass
            for pkt_idx in range(len(trace)):
                if trace[pkt_idx].get_attack_id() == outbound_attk_id:
                    outbound_pkt_cnt += 1
                else:
                    inbound_pkt_cnt += 1
            # 2nd pass
            for pkt_idx in range(len(trace)):
                if use_direction:
                    if trace[pkt_idx].get_attack_id() == outbound_attk_id:
                        fout.write(trace[pkt_idx].get_data_str(connection_id, float(
                            outbound_pkt_idx)/outbound_pkt_cnt, direction='0') + '\n')
                        outbound_pkt_idx += 1
                    else:
                        fout.write(trace[pkt_idx].get_data_str(connection_id, float(
                            inbound_pkt_idx)/inbound_pkt_cnt, direction='1') + '\n')
                        inbound_pkt_idx += 1
                else:
                    fout.write(trace[pkt_idx].get_data_str(
                        connection_id, pkt_idx) + '\n')


def dump_injected_k_dataset(ds_dict, fpath):
    with open(fpath, 'w') as fout:
        fout.write('\t'.join(['frame.time_epoch', 'frame.len', 'eth.src', 'eth.dst',
                              'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
                              'udp.dstport', 'icmp.type', 'icmp.code', 'arp.opcode',
                              'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac',
                              'arp.dst.proto_ipv4', 'ipv6.src', 'ipv6.dst\n']))
        for connection_id, trace in ds_dict.items():
            for pkt_idx in range(len(trace)):
                fout.write(trace[pkt_idx].get_dump_str() + '\n')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Use this script to inject attacks.')
    parser.add_argument('--dataset', type=str, help='Path to dataset.')
    parser.add_argument('--attack-dataset', type=str,
                        help='Path to dump dataset w/ injected attack.')
    parser.add_argument('--attack-type', type=str,
                        help='Type of attack to inject.')
    parser.add_argument('--inject-opt', type=str,
                        help='Additional options.')
    parser.add_argument('--benign-dataset', type=str,
                        help='Path to dump benign and valid dataset.')
    parser.add_argument('--use-direction', action='store_true',
                        help='Write direction into dataset.')
    parser.add_argument('--multipkt', action='store_true',
                        help='Whether to inject multiple packets.')
    args = parser.parse_args()

    ds = read_dataset(args.dataset, mode='packet_id')
    k_ds = read_kitsune_dataset(args.dataset + '.kitsune')

    # SymTCP strategies
    # (Zeek)
    if args.attack_type == 'SymTCP_Zeek_SYNWithData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_syn_with_data(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_MultipleSYN':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_multiple_syn_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_PureFIN':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_pure_fin(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_BadRSTFIN':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_bad_rst_fin(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_DataOverlapping':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_data_overlapping(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_DataWithoutACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_data_without_ack_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_DataBadACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_data_bad_ack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_SEQJump':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_seq_jump_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Zeek_UnderflowSEQ':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_zeek_underflow_seq_attack(
            ds, k_ds)
    # (Snort)
    elif args.attack_type == 'SymTCP_Snort_MultipleSYN':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_multiple_syn_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_InWindowFIN':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_in_window_fin_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_FINACKBadACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_fin_ack_bad_ack_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_FINACKMD5':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_fin_ack_md5_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_InWindowRST':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_in_window_rst_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_RSTBadTimestamp':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_rst_bad_timestamp_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_RSTMD5':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_rst_md5_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_RSTACKBadACKNum':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_rst_ack_bad_ack_num_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_PartialInWindowRST':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_partial_in_window_rst_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_UrgentData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_urgent_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_Snort_TimeGap':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_snort_time_gap_attack(
            ds, k_ds)
    # (GFW)
    elif args.attack_type == 'SymTCP_GFW_BadRST':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_bad_rst_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_BadData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_bad_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_DataWithoutACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_data_without_ack_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_UnderflowSEQ':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_underflow_seq_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_SmallSegments':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_small_segments_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_FINWithData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_fin_with_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_BadFINACKData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_bad_fin_ack_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_FINACKDataBadACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_fin_ack_data_bad_ack_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_OutOfWindowSYNData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_out_of_window_syn_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_RetransmittedSYNData':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_retransmitted_syn_data_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_RSTBadTimestamp':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_rst_bad_timestamp_attack(
            ds, k_ds)
    elif args.attack_type == 'SymTCP_GFW_RSTACKBadACKNum':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_gfw_rst_ack_bad_ack_num_attack(
            ds, k_ds)
    # TCPwn (unused)
    elif args.attack_type == 'TCPwn_DupACK':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_dup_ack_attack(
            ds, k_ds)
    # Liberate (unused)
    elif args.attack_type == 'Liberate_IP_LowTTL':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_low_ttl_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_IP_InvalidVersion':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_invalid_version_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_IP_InvalidHeaderLen':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_invalid_header_len_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_IP_LongerLength':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_longer_length_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_IP_ShorterLength':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_shorter_length_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_TCP_WrongSEQ':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_wrong_seq_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_TCP_WrongChksum':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_wrong_tcp_checksum_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_TCP_ACKNotSet':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_ack_not_set_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_TCP_InvalidDataoff':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_invalid_dataoff_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_TCP_InvalidFlagComb':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_invalid_flag_comb_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Liberate_IP_LowTTLRSTa':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_low_ttl_rst_attack_a(
            ds, k_ds)
    elif args.attack_type == 'Liberate_IP_LowTTLRSTb':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_low_ttl_rst_attack_b(
            ds, k_ds)
    # Geneva
    elif args.attack_type == 'Geneva_Strategy_1':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_1_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_2':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_2_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_3':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_3_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_4':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_4_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_5':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_5_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_6':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_6_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_7':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_7_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_8':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_8_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_9':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_9_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_10':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_10_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_11':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_11_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_12':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_12_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_13':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_13_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_14':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_14_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_15':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_15_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_16':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_16_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_17':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_17_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_18':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_18_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_19':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_19_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_20':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_20_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_21':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_21_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_22':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_22_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_23':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_23_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_24':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_24_attack(
            ds, k_ds, multipkt=args.multipkt)
    elif args.attack_type == 'Geneva_Strategy_25':
        injected_ds, valid_ds, injected_k_ds, valid_k_ds, adv_pkt_info = inject_geneva_25_attack(
            ds, k_ds, multipkt=args.multipkt)

    dump_injected_dataset(injected_ds, args.attack_dataset, use_direction=args.use_direction)
    dump_adv_pkt_info(adv_pkt_info, injected_ds, args.attack_dataset)
    dump_injected_k_dataset(
        injected_k_ds, args.attack_dataset + '.kitsune')

    if args.benign_dataset:
        dump_injected_dataset(valid_ds, args.benign_dataset,
                              use_direction=args.use_direction)
        dump_injected_k_dataset(
            valid_k_ds, args.benign_dataset + '.kitsune')
