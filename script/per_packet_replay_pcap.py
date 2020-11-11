from scapy import error
from scapy.all import Raw, IP, TCP, sendp, send, sr1, Ether, conf, L3RawSocket
from scapy.utils import rdpcap

import argparse
import os
from subprocess import check_output
import logging
from random import randint

from analyze_packet_trace import read_wami_tcp_state_mapping_file


LOCALHOST_IP = "127.0.0.1"
LOOPBACK_MAC_ADDR = "00:00:00:00:00:00"
ENO1_MAC_ADDR = "18:66:da:49:2d:b3"
INITIAL_SPORT = 45000
DEFAULT_DPORT = 50000
IDX_TCP_STATE_IN_CONNTRACK_STR = 3

# Logging
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                    datefmt='%H:%M:%S')
logger = logging.getLogger("master")
logger.setLevel(logging.DEBUG)
fileHandler = logging.FileHandler("../log/per_pkt_replay.log", mode='w')
logger.addHandler(fileHandler)


def dump(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    logger.info("%s:%d -> %s:%d" %
                (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport))
    logger.info("SEQ: %d" % pkt[TCP].seq)
    logger.info("ACK: %d" % pkt[TCP].ack)
    logger.info("Data offset: %d" % (pkt[TCP].dataofs * 4))
    logger.info("TCP flags: %s" % (pkt[TCP].flags or 'None'))
    logger.info("Window: %d" % (pkt[TCP].window))
    logger.info("Checksum: %d" % (pkt[TCP].chksum or 0))
    logger.info("Urgent pointer: %d" % (pkt[TCP].urgptr or 0))
    logger.info("Src MAC: %s" % pkt[Ether].src)
    logger.info("Dst MAC: %s" % pkt[Ether].dst)
    logger.info("Payload length: %d" % len(pkt[TCP].payload))


def read_conntrack_state(five_tuple, debug=False):
    src, sport, dst, dport, proto = five_tuple
    conntrack_query_cmd = "conntrack -L -p %s --orig-src %s --sport %s --orig-dst %s --dport %s" % (
        proto, src, sport, dst, dport)
    if debug:
        logger.debug("Conntrack command: %s" % conntrack_query_cmd)
    state_ret_str = check_output(conntrack_query_cmd, shell=True)
    try:
        tcp_state = state_ret_str.decode(
            'UTF-8').split()[IDX_TCP_STATE_IN_CONNTRACK_STR]
        if debug:
            logger.debug("TCP State: %s" % tcp_state)
        return tcp_state
    except Exception as err:
        if debug:
            logger.error("TCP State Reading Error: %s" % err)
        return "ERR_UNKNOWN"


def read_conntrack_state_proc(five_tuple, debug=False):
    def get_tcp_state(ret_str, src, sport, dst, dport, proto, debug=False):
        def remove_unused_states(fields):
            new_fields = []
            for i in range(len(fields)):
                if not (fields[i].startswith('[') and fields[i].endswith(']')):
                    new_fields.append(fields[i])
            return new_fields

        entries = ret_str.split('\n')
        original_dir = 'None'
        reply_dir = 'None'
        for r in entries:
            fields = r.strip().split()
            fields = remove_unused_states(fields)
            if len(fields) != 17:
                continue
            if fields[2] == proto and fields[6].endswith(src) and fields[7].endswith(dst) and fields[8].endswith(sport) and fields[9].endswith(dport):
                return fields[5]
            if fields[2] == proto and fields[-7].endswith(src) and fields[-6].endswith(dst) and fields[-5].endswith(sport) and fields[-4].endswith(dport):
                return fields[5]
        if debug:
            print("[ORI] state %s" % original_dir)
            print("[REPLY] state %s" % (reply_dir))
        return "EMPTY_STATE"

    src, sport, dst, dport, proto = five_tuple
    conntrack_query_cmd = "cat /proc/net/nf_conntrack"
    if debug:
        logger.debug("Conntrack command: %s" % conntrack_query_cmd)
    state_ret_str = check_output(conntrack_query_cmd, shell=True)
    try:
        state_ret_str = state_ret_str.decode('UTF-8')
        tcp_state = get_tcp_state(state_ret_str, src, sport, dst, dport, proto)
        if debug:
            logger.debug("TCP State: %s" % tcp_state)
        return tcp_state
    except Exception as err:
        if debug:
            logger.error("TCP State Reading Error: %s" % err)
        return "ERR_UNKNOWN"


def replay_a_pcap(pcap_fpath, sport, dport, interface, rewrite_tuple=False, conntrack_mode='proc', debug=False):
    def get_tuple(pkt):
        return (pkt[IP].src, str(pkt[IP].sport), pkt[IP].dst, str(pkt[IP].dport), "tcp")

    if debug:
        pcap_fname = pcap_fpath.split('/')[-1]
        logger.debug("Pcap filename: %s" % pcap_fname)
    pkts = rdpcap(pcap_fpath)
    state_list = []

    tuple_set = set()
    pkt_cnt = 0

    # Pre-filtering
    if len(pkts) == 1:
        return ['CONNECTION_IS_TOO_SHORT']
    if len(pkts) > 200:
        return ["CONNECTION_IS_TOO_LONG"]

    for pkt in pkts:
        pkt_cnt += 1

        if IP not in pkt or TCP not in pkt:
            if debug:
                logger.error("Non-TCP packet found in this PCAP file!")
            return ["NOT_TCP_PKT"]

        if rewrite_tuple:
            pkt[IP].src = LOCALHOST_IP
            pkt[IP].dst = LOCALHOST_IP
            pkt[IP].sport = sport
            pkt[IP].dport = dport
            pkt[Ether].src = ENO1_MAC_ADDR
            pkt[Ether].dst = ENO1_MAC_ADDR

        # Stuff the payload to make up what is missing in striped pacps
        ip_ihl = pkt[IP].ihl*4
        dataofs = pkt[TCP].dataofs*4
        payload_len = pkt[IP].len - ip_ihl - dataofs
        payload = 'a' * payload_len

        # Rememeber to use Scapy's L3 API here
        # TODO: why?
        del pkt[TCP].chksum
        del pkt[IP].chksum
        try:
            send(pkt[IP]/Raw(load=payload))
        except Exception:
            return ['ERR_REPLAY']

        conntrack_tuple = get_tuple(pkt)
        tuple_set.add(','.join(conntrack_tuple))

        if conntrack_mode == 'cli':
            curr_state = read_conntrack_state(conntrack_tuple, debug=True)
        elif conntrack_mode == 'proc':
            curr_state = read_conntrack_state_proc(conntrack_tuple, debug=True)

        if curr_state == 'ERR_UNKNOWN':
            return ['ERR_UNKNOWN']
        if curr_state == 'EMPTY_STATE':
            return ['EMPTY_STATE']

        if debug:
            logger.debug("===== Packet information =====")
            dump(pkt)

        state_list.append(curr_state)

    if len(tuple_set) == 1:
        return ['ONE_WAY_COMMUNICATION']
    if len(tuple_set) > 2:
        return ['MULTI_PARTY_COMMUNICATION']

    return state_list


def generate_state_record_str(pcap_fname, state_list):
    _, pcap_id = pcap_fname.strip('.pcap').split('-')
    return ",".join([pcap_id] + state_list)


def read_pcaps(pcap_dir):
    return os.listdir(pcap_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Replay every pcap file for collecting corresponding TCP state.')
    parser.add_argument('-D', '--pcap-dir',
                        help='directory to load all pcap files')
    parser.add_argument('-F', '--pcap-file',
                        help='path to load the test pcap file')
    parser.add_argument('-I', '--interface', help='interface to listen on')
    parser.add_argument(
        '-O', '--output', help='output log file to dump states')
    parser.add_argument(
        '-R', '--rewrite-tuple', action='store_true', help='wthether to change original five tuple in pcap to localhost')
    parser.add_argument(
        '--sk-mapping', type=str, help='wthether to resume instead of restarting')
    parser.add_argument('--inst-id', type=int,
                        default=-1, help='# of instance')
    parser.add_argument(
        '--rename', action='store_true', help='wthether to rename filenames')
    args = parser.parse_args()

    # This must be done to make sent packets visible to conntrack
    # TODO: why?
    conf.L3socket = L3RawSocket
    conf.iface = args.interface

    if os.geteuid() != 0:
        exit("[ERROR] This script must be run as root. Exiting...")

    if args.pcap_dir and not args.pcap_file:
        pcap_list = read_pcaps(args.pcap_dir)
        if args.rename:
            for i in range(len(pcap_list)):
                original_pcap_fname = pcap_list[i]
                new_pcap_fname = 'dummy-' + pcap_list[i].split('-')[-1]
                os.rename(args.pcap_dir + original_pcap_fname,
                          args.pcap_dir + new_pcap_fname)
                pcap_list[i] = new_pcap_fname
    if args.pcap_file and not args.pcap_dir:
        pcap_fname = args.pcap_file.split('/')[-1]
        args.pcap_dir = '/'.join(args.pcap_file.split('/')[:-1])
        pcap_list = [pcap_fname]

    curr_sport = randint(INITIAL_SPORT, DEFAULT_DPORT)
    curr_dport = DEFAULT_DPORT

    if args.sk_mapping:
        sk_mapping = read_wami_tcp_state_mapping_file(args.sk_mapping)

    with open(args.output, 'w') as fout:
        cnt = 0
        for pcap_fname in pcap_list:
            cnt += 1
            if args.inst_id != -1:
                if cnt % 5 != args.inst_id:
                    print("[INFO] Skipping #%d..." % cnt)
                    continue
            if args.sk_mapping:
                pcap_id = pcap_fname.split('-')[-1].strip('.pcap')
                if pcap_id in sk_mapping:
                    continue
            try:
                pcap_fpath = '/'.join([args.pcap_dir, pcap_fname])
                state_list = replay_a_pcap(
                    pcap_fpath, curr_sport, curr_dport, args.interface, rewrite_tuple=args.rewrite_tuple, debug=True)
                state_str = generate_state_record_str(pcap_fname, state_list)
                fout.write(state_str + '\n')
                curr_sport += 1

                # Reuse the port range [INITIAL_SPORT, DEFAULT_DPORT]
                if curr_sport >= curr_dport:
                    curr_sport = INITIAL_SPORT
                # input("[DEBUG] Press Enter to continue...")
            except error.Scapy_Exception as err:
                print("An error: %s" % str(err))
                continue
