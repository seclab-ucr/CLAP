import matplotlib.pyplot as plt
import torch
from torch import nn, optim
import torch.nn.functional as F
import numpy as np

from torch.autograd import Variable
import torch.nn.functional as F
import pandas
import random
import time
import argparse
import collections
from torch.nn.utils.rnn import PackedSequence

from sklearn import metrics

from collections import Counter

import statistics

ERR_TOO_SHORT_SEQ = -1

TRIMMED_COL_NAMES = [
    'ATTACK_ID',
    'DIRECTION',
    'SEQ',
    'ACK',
    'DATAOFF',
    'FLAGS',
    'WINDOW',
    'CHKSUM',
    'URGPTR',
    'SK_STATE',
    'PAYLOAD_LEN',
    'IP_LEN',
    'IP_TTL',
    'IP_IHL',
    'IP_CHKSUM',
    'IP_VERSION',
    'IP_TOS',
    'IP_ID',
    'IP_OPT_NON_STANDARD',
    'TCP_OPT_MSS',
    'TCP_OPT_TSVAL',
    'TCP_OPT_TSECR',
    'TCP_OPT_WSCALE',
    'TCP_OPT_UTO',
    'TCP_OPT_MD5HEADER',
    'TCP_OPT_NON_STANDARD',
    'TCP_TIMESTAMP',
    'ARRIVAL_TIMESTAMP',
]

TCP_FLAGS_MAP = {
    "F": 0,
    "S": 1,
    "R": 2,
    "P": 3,
    "A": 4,
    "U": 5,
    "E": 6,
    "C": 7,
}

IP_VERSION_MAP = {
    '4': 0,
    '6': 1,
    '-1': 2,
}

TCP_OPT_MD5HEADER_MAP = {
    '0': 0,
    '1': 1,
    '-1': 2,
}

TRAIN_TEST_SPLIT = 10

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


class MyKitsunePacket(object):
    def __init__(self, frame_time_epoch, frame_len, eth_src,
                 eth_dst, ip_src, ip_dst,
                 tcp_sport, tcp_dport,
                 debug=False):
        self.frame_time_epoch = float(frame_time_epoch)
        self.frame_len = int(frame_len)
        self.eth_src = str(eth_src)
        self.eth_dst = str(eth_dst)
        self.ip_src = str(ip_src)
        self.ip_dst = str(ip_dst)
        self.tcp_sport = int(tcp_sport)
        self.tcp_dport = int(tcp_dport)

    def get_dump_str(self, conn_idx=None, packet_idx=None):
        if conn_idx is not None:
            return '\t'.join([str(conn_idx), str(packet_idx), str(self.frame_time_epoch),
                              str(self.frame_len), str(self.eth_src),
                              str(self.eth_dst), str(
                self.ip_src), str(self.ip_dst),
                str(self.tcp_sport), str(self.tcp_dport)] + [''] * 11)
        else:
            return '\t'.join([str(self.frame_time_epoch), str(self.frame_len), str(self.eth_src),
                              str(self.eth_dst), str(
                              self.ip_src), str(self.ip_dst),
                              str(self.tcp_sport), str(self.tcp_dport)] + [''] * 11)


class MyPacket(object):
    def __init__(self, src_ip, src_port,
                 dst_ip, dst_port, seq,
                 ack, dataoff, flags,
                 window, chksum, urgptr,
                 timestamp, payload_len, sk_state,
                 filename, ip_len, ip_ttl, ip_ihl,
                 ip_chksum, ip_version, ip_tos, ip_id, ip_opt_non_standard,
                 tcp_opt_mss, tcp_opt_tsval, tcp_opt_tsecr,
                 tcp_opt_wscale, tcp_opt_uto, tcp_opt_md5header,
                 tcp_opt_non_standard, tcp_timestamp, arrival_timestamp,
                 kitsune_frame_time_epoch=None, kitsune_frame_len=None,
                 kitsune_eth_src=None, kitsune_eth_dst=None, kitsune_ip_src=None,
                 kitsune_ip_dst=None, kitsune_tcp_sport=None, kitsune_tcp_dport=None,
                 debug=False):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.dataoff = dataoff
        self.flags = flags
        self.window = window
        self.chksum = chksum
        self.urgptr = urgptr
        self.timestamp = timestamp
        self.payload_len = payload_len
        self.sk_state = sk_state
        self.filename = filename
        self.ip_len = ip_len
        self.ip_ttl = ip_ttl
        self.ip_ihl = ip_ihl
        self.ip_chksum = ip_chksum
        self.ip_version = ip_version
        self.ip_tos = ip_tos
        self.ip_id = ip_id
        self.ip_opt_non_standard = ip_opt_non_standard
        self.tcp_opt_mss = tcp_opt_mss
        self.tcp_opt_tsval = tcp_opt_tsval
        self.tcp_opt_tsecr = tcp_opt_tsecr
        self.tcp_opt_wscale = tcp_opt_wscale
        self.tcp_opt_uto = tcp_opt_uto
        self.tcp_opt_md5header = tcp_opt_md5header
        self.tcp_opt_non_standard = tcp_opt_non_standard
        self.tcp_timestamp = tcp_timestamp
        self.arrival_timestamp = arrival_timestamp
        self.kitsune_frame_time_epoch = kitsune_frame_time_epoch
        self.kitsune_frame_len = kitsune_frame_len
        self.kitsune_eth_src = kitsune_eth_src
        self.kitsune_eth_dst = kitsune_eth_dst
        self.kitsune_ip_src = kitsune_ip_src
        self.kitsune_ip_dst = kitsune_ip_dst
        self.kitsune_tcp_sport = kitsune_tcp_sport
        self.kitsune_tcp_dport = kitsune_tcp_dport
        if debug:
            self.print_debug()

    def set_sk_state(self, sk_state):
        self.sk_state = sk_state

    def get_attack_id(self):
        attack_id = ','.join(
            [self.src_ip, str(self.src_port), self.dst_ip, str(self.dst_port)])
        return attack_id

    def get_tuple_id(self):
        src = ','.join([self.src_ip, str(self.src_port)])
        dst = ','.join([self.dst_ip, str(self.dst_port)])
        return src, dst

    def get_reverse_attack_id(self):
        reverse_attack_id = ','.join(
            [self.dst_ip, str(self.dst_port), self.src_ip, str(self.src_port)])
        return reverse_attack_id

    def get_attack_packet_id(self):
        attack_packet_id = ','.join([str(self.dataoff), str(self.flags), str(
            self.window), str(self.chksum), str(self.urgptr)])
        return attack_packet_id

    def get_filename(self):
        return self.filename

    def get_hash(self):
        return ','.join([str(self.src_ip), str(self.src_port), str(self.dst_ip),
                         str(self.dst_port), str(self.seq), str(self.ack),
                         str(self.dataoff), str(self.flags), str(self.window),
                         str(self.chksum), str(
                             self.urgptr), str(self.timestamp),
                         str(self.timestamp), str(
                             self.payload_len), str(self.sk_state),
                         str(self.filename), str(
                             self.ip_len), str(self.ip_ttl),
                         str(self.ip_ihl), str(self.ip_chksum)])

    def get_data_str(self, idx, packet_idx, direction=None):
        if not direction:
            return ','.join([str(idx), str(packet_idx), self.get_attack_id(), str(self.seq),
                             str(self.ack), self.get_attack_packet_id(), str(
                                 self.sk_state),
                             str(self.payload_len), self.timestamp, str(
                                 self.ip_len),
                             str(self.ip_ttl), str(
                                 self.ip_ihl), str(self.ip_chksum),
                             str(self.ip_version), str(
                                 self.ip_tos), str(self.ip_id), str(self.ip_opt_non_standard),
                             str(self.tcp_opt_mss), str(self.tcp_opt_tsval),
                             str(self.tcp_opt_tsecr), str(
                                 self.tcp_opt_wscale), str(self.tcp_opt_uto),
                             str(self.tcp_opt_md5header), str(
                                 self.tcp_opt_non_standard), str(self.tcp_timestamp),
                             str(self.arrival_timestamp)])
        else:
            return ','.join([str(idx), str(packet_idx), str(direction), str(self.seq),
                             str(self.ack), self.get_attack_packet_id(), str(
                                 self.sk_state),
                             str(self.payload_len), self.timestamp, str(
                                 self.ip_len),
                             str(self.ip_ttl), str(
                                 self.ip_ihl), str(self.ip_chksum),
                             str(self.ip_version), str(
                                 self.ip_tos), str(self.ip_id), str(self.ip_opt_non_standard),
                             str(self.tcp_opt_mss), str(self.tcp_opt_tsval),
                             str(self.tcp_opt_tsecr), str(
                                 self.tcp_opt_wscale), str(self.tcp_opt_uto),
                             str(self.tcp_opt_md5header), str(
                                 self.tcp_opt_non_standard), str(self.tcp_timestamp),
                             str(self.arrival_timestamp)])

    def get_kitsune_str(self, idx, pkt_idx):
        return '\t'.join([str(idx), str(pkt_idx), str(self.kitsune_frame_time_epoch), str(self.kitsune_frame_len),
                          str(self.kitsune_eth_src), str(
                              self.kitsune_eth_dst), str(self.kitsune_ip_src),
                          str(self.kitsune_ip_dst), str(self.kitsune_tcp_sport), str(self.kitsune_tcp_dport)])

    def print_debug(self):
        print("Dumping packet fields...")
        print("%s:%d -> %s:%d" %
              (self.src_ip, self.src_port, self.dst_ip, self.dst_port))
        print("SEQ: %s" % self.seq)
        print("ACK: %s" % self.ack)
        print("Data offset: %d" % self.dataoff)
        print("TCP flags: %s" % self.flags)
        print("Window: %d" % self.window)
        print("Checksum: %s" % self.chksum)
        print("Urgent pointer: %s" % self.urgptr)
        print("Timestamp: %s" % self.timestamp)
        print("Payload length: %d" % self.payload_len)
        print("sk_state: %s" % str(self.sk_state))
        print("Filename: %s" % self.filename)
        print("IP length: %s" % str(self.ip_len))
        print("IP TTL: %s" % str(self.ip_ttl))
        print("IP IHL: %s" % str(self.ip_ihl))
        print("IP Checksum: %s" % str(self.ip_chksum))
        print("IP Version: %s" % str(self.ip_version))
        print("IP TOS: %s" % str(self.ip_tos))
        print("IP ID: %s" % str(self.ip_id))
        input("Dump ended.")


# Copied from torch's official implementation, with return value
# being a tuple that contains gate states (vs. only hidden states)
def gru_cell(input, hidden, w_ih, w_hh, b_ih, b_hh):
    gi = torch.mm(input, w_ih.t()) + b_ih
    gh = torch.mm(hidden, w_hh.t()) + b_hh
    i_r, i_i, i_n = gi.chunk(3, 1)
    h_r, h_i, h_n = gh.chunk(3, 1)

    resetgate = torch.sigmoid(i_r + h_r)
    inputgate = torch.sigmoid(i_i + h_i)
    newgate = torch.tanh(i_n + resetgate * h_n)
    hy = newgate + inputgate * (hidden - newgate)

    return hy, resetgate, inputgate


# Also copied from torch's official FastRNN benchmark, with additional gates returned
def lstm_cell(input, hidden, w_ih, w_hh, b_ih, b_hh):
    # type: (Tensor, Tuple[Tensor, Tensor], Tensor, Tensor, Tensor, Tensor) -> Tuple[Tensor, Tensor]
    hx, cx = hidden
    gates = torch.mm(input, w_ih.t()) + torch.mm(hx, w_hh.t()) + b_ih + b_hh

    ingate, forgetgate, cellgate, outgate = gates.chunk(4, 1)

    ingate = torch.sigmoid(ingate)
    forgetgate = torch.sigmoid(forgetgate)
    cellgate = torch.tanh(cellgate)
    outgate = torch.sigmoid(outgate)

    cy = (forgetgate * cx) + (ingate * cellgate)
    hy = outgate * torch.tanh(cy)

    return hy, cy, ingate, forgetgate, cellgate, outgate


class GRUCell(nn.modules.rnn.RNNCellBase):
    def __init__(self, input_size, hidden_size, bias=True):
        super(GRUCell, self).__init__(
            input_size, hidden_size, bias, num_chunks=3)

    def forward(self, x, hx):
        # type: (Tensor, Optional[Tensor]) -> Tensor
        self.check_forward_input(x)
        self.check_forward_hidden(x, hx, '')
        return gru_cell(
            x, hx,
            self.weight_ih, self.weight_hh,
            self.bias_ih, self.bias_hh,
        )


class LSTMCell(nn.modules.rnn.RNNCellBase):
    def __init__(self, input_size, hidden_size, bias=True):
        super(LSTMCell, self).__init__(
            input_size, hidden_size, bias, num_chunks=4)

    def forward(self, x, hx):
        # type: (Tensor, Optional[Tuple[Tensor, Tensor]]) -> Tuple[Tensor, Tensor]
        self.check_forward_input(x)
        self.check_forward_hidden(x, hx[0], '')
        self.check_forward_hidden(x, hx[1], '')
        return lstm_cell(
            x, hx,
            self.weight_ih, self.weight_hh,
            self.bias_ih, self.bias_hh,
        )


class GRUModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, num_layers, device, bidirectional):
        super(GRUModel, self).__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.num_layers = num_layers
        self.device = device
        self.bidirectional = bidirectional

        print("===== GRUModel args =====")
        print("input_size: %s" % str(input_size))
        print("hidden_size: %s" % str(hidden_size))
        print("output_size: %s" % str(output_size))
        print("num_layers: %s" % str(num_layers))
        print("device: %s" % str(device))

        self.gru_in = GRUCell(input_size, hidden_size)
        self.gru_middle = GRUCell(hidden_size, hidden_size)
        if bidirectional:
            self.fc = nn.Linear(hidden_size * 2, output_size)
        else:
            self.fc = nn.Linear(hidden_size, output_size)
        self.dropout = nn.Dropout(p=0.1)

    def forward(self, inputs):
        is_packed = isinstance(inputs, PackedSequence)
        if is_packed:
            inputs, batch_sizes, sorted_indices, unsorted_indices = inputs
            max_batch_size = batch_sizes[0]
            max_batch_size = int(max_batch_size)

        # These states need to be returned
        outputs = []
        gates = []
        hn = []

        # Temporary states
        hs = []

        # Initialize hidden states
        for layer_idx in range(self.num_layers):
            hs.append(self.init_hidden())

        for seq_idx in range(inputs.size(1)):
            curr_seq = inputs[:, seq_idx, :]

            # Stacked GRU
            for layer_idx in range(self.num_layers):
                if layer_idx == 0:  # input layer
                    hs[layer_idx], resetgate, inputgate = self.gru_in(
                        curr_seq, hs[layer_idx])
                else:  # non-input layer
                    hs[layer_idx], resetgate, inputgate = self.gru_middle(
                        hs[layer_idx-1], hs[layer_idx])

            outputs.append(hs[-1])

            gates.append([resetgate.detach(), inputgate.detach()])
            hn.append(hs[-1].detach())

        if self.bidirectional:
            # Temporary states
            hs2 = []

            # Initialize hidden states
            for layer_idx in range(self.num_layers):
                hs2.append(self.init_hidden())

            for seq_idx in reversed(range(inputs.size(1))):
                forward_seq_idx = inputs.size(1) - seq_idx - 1
                curr_seq = inputs[:, seq_idx, :]

                # Stacked GRU
                for layer_idx in range(self.num_layers):
                    if layer_idx == 0:  # input layer
                        hs2[layer_idx], resetgate, inputgate = self.gru_in(
                            curr_seq, hs2[layer_idx])
                    else:  # non-input layer
                        hs2[layer_idx], resetgate, inputgate = self.gru_middle(
                            hs2[layer_idx-1], hs2[layer_idx])

                outputs[forward_seq_idx] = torch.cat(
                    (outputs[forward_seq_idx], hs2[-1]), 1)
                gates[forward_seq_idx] = [torch.cat((gates[forward_seq_idx][0], resetgate.detach(
                )), 1), torch.cat((gates[forward_seq_idx][1], inputgate.detach()), 1)]
                hn[forward_seq_idx] = torch.cat(
                    (hn[forward_seq_idx], hs2[-1].detach()), 1)

        for idx in range(len(outputs)):
            outputs[idx] = self.fc(outputs[idx])
        outputs = torch.stack(outputs, dim=1)

        return [outputs, gates, hn]

    def init_hidden(self, batch_size=1):
        if torch.cuda.is_available():
            h0 = Variable(torch.zeros(self.num_layers, batch_size, self.hidden_size)).to(
                self.device, dtype=torch.float)
        else:
            h0 = Variable(torch.zeros(self.num_layers,
                                      batch_size, self.hidden_size))

        return h0[0, :, :]


class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, num_layers, device, bidirectional):
        super(LSTMModel, self).__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.num_layers = num_layers
        self.device = device
        self.bidirectional = bidirectional

        print("===== LSTMModel args =====")
        print("input_size: %s" % str(input_size))
        print("hidden_size: %s" % str(hidden_size))
        print("output_size: %s" % str(output_size))
        print("num_layers: %s" % str(num_layers))
        print("device: %s" % str(device))

        self.lstm_in = LSTMCell(input_size, hidden_size)
        self.lstm_middle = LSTMCell(hidden_size, hidden_size)
        if bidirectional:
            self.fc = nn.Linear(hidden_size * 2, output_size)
        else:
            self.fc = nn.Linear(hidden_size, output_size)
        self.dropout = nn.Dropout(p=0.1)

    def forward(self, inputs):
        # These states need to be returned
        outputs = []
        gates = []
        hn = []

        # Temporary states
        hs = []
        cs = []

        # Initialize hidden states
        for layer_idx in range(self.num_layers):
            hs.append(self.init_hidden())
            cs.append(self.init_hidden())

        for seq_idx in range(inputs.size(1)):
            curr_seq = inputs[:, seq_idx, :]

            # Stacked LSTM
            for layer_idx in range(self.num_layers):
                if layer_idx == 0:  # input layer
                    hs[layer_idx], cs[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_in(
                        curr_seq, (hs[layer_idx], cs[layer_idx]))
                    hs[layer_idx] = self.dropout(hs[layer_idx])
                elif layer_idx != self.num_layers - 1:  # non-input layer
                    hs[layer_idx], cs[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_middle(
                        hs[layer_idx-1], (hs[layer_idx], cs[layer_idx]))
                    hs[layer_idx] = self.dropout(hs[layer_idx])
                else:
                    hs[layer_idx], cs[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_middle(
                        hs[layer_idx-1], (hs[layer_idx], cs[layer_idx]))

            outputs.append(hs[-1])

            gates.append([inputgate.detach(), forgetgate.detach(),
                          cellgate.detach(), outgate.detach()])
            hn.append(cs[-1].detach())

        if self.bidirectional:
            # Temporary states
            hs2 = []
            cs2 = []

            # Initialize hidden states
            for layer_idx in range(self.num_layers):
                hs2.append(self.init_hidden())
                cs2.append(self.init_hidden())

            for seq_idx in reversed(range(inputs.size(1))):
                forward_seq_idx = inputs.size(1) - seq_idx - 1
                curr_seq = inputs[:, seq_idx, :]

                # Stacked LSTM
                for layer_idx in range(self.num_layers):
                    if layer_idx == 0:  # input layer
                        hs2[layer_idx], cs2[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_in(
                            curr_seq, (hs2[layer_idx], cs2[layer_idx]))
                        hs2[layer_idx] = self.dropout(hs2[layer_idx])
                    elif layer_idx != self.num_layers - 1:  # non-input layer
                        hs2[layer_idx], cs2[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_middle(
                            hs2[layer_idx-1], (hs2[layer_idx], cs2[layer_idx]))
                        hs2[layer_idx] = self.dropout(hs2[layer_idx])
                    else:
                        hs2[layer_idx], cs2[layer_idx], inputgate, forgetgate, cellgate, outgate = self.lstm_middle(
                            hs2[layer_idx-1], (hs2[layer_idx], cs2[layer_idx]))

                outputs[forward_seq_idx] = torch.cat(
                    (outputs[forward_seq_idx], hs2[-1]), 1)
                gates[forward_seq_idx] = [torch.cat((gates[forward_seq_idx][0], inputgate.detach()), 1), torch.cat((gates[forward_seq_idx][1], forgetgate.detach(
                )), 1), torch.cat((gates[forward_seq_idx][2], cellgate.detach()), 1), torch.cat((gates[forward_seq_idx][3], outgate.detach()), 1)]
                hn[forward_seq_idx] = torch.cat(
                    (hn[forward_seq_idx], cs2[-1].detach()), 1)

        for idx in range(len(outputs)):
            outputs[idx] = self.fc(outputs[idx])
        outputs = torch.stack(outputs, dim=1)

        return [outputs, gates, hn]

    def init_hidden(self, batch_size=1):
        if torch.cuda.is_available():
            h0 = Variable(torch.zeros(self.num_layers, batch_size, self.hidden_size)).to(
                self.device, dtype=torch.float)
        else:
            h0 = Variable(torch.zeros(self.num_layers,
                                      batch_size, self.hidden_size))

        return h0[0, :, :]


class AEModel(nn.Module):
    def __init__(self, input_size, bottleneck_size=5, model_type='mid'):
        super(AEModel, self).__init__()
        self.input_size = input_size
        self.model_type = model_type
        if self.model_type == 'small':
            l1 = int(float(input_size)/3)
            l2 = bottleneck_size
            print("[INFO][Model] Input: %d ---> L1: %d ---> L2: %d --> L3: %d --> Output: %d" %
                  (input_size, l1, l2, l1, input_size))
            self.fc1 = nn.Linear(input_size, l1)
            self.fc2 = nn.Linear(l1, l2)
            self.fc3 = nn.Linear(l2, l1)
            self.fc4 = nn.Linear(l1, input_size)
        elif self.model_type == 'mid':
            l1 = int(float(input_size)/1.5)
            l2 = int(float(input_size)/3)
            l3 = bottleneck_size
            print("[INFO][Model] Input: %d ---> L1: %d ---> L2: %d --> L3: %d --> L4: %d --> L5: %d --> Output: %d" %
                  (input_size, l1, l2, l3, l2, l1, input_size))
            self.fc1 = nn.Linear(input_size, l1)
            self.fc2 = nn.Linear(l1, l2)
            self.fc3 = nn.Linear(l2, l3)
            self.fc4 = nn.Linear(l3, l2)
            self.fc5 = nn.Linear(l2, l1)
            self.fc6 = nn.Linear(l1, input_size)
        elif self.model_type == 'large':
            l1 = int(float(input_size)/1.5)
            l2 = int(float(input_size)/2.5)
            l3 = int(float(input_size)/5)
            l4 = bottleneck_size
            print("[INFO][Model] Input: %d ---> L1: %d ---> L2: %d ---> L3: %d ---> L4: %d ---> L5: %d --> L6: %d --> L7: %d --> Output: %d" %
                  (input_size, l1, l2, l3, l4, l3, l2, l1, input_size))
            self.fc1 = nn.Linear(input_size, l1)
            self.fc2 = nn.Linear(l1, l2)
            self.fc3 = nn.Linear(l2, l3)
            self.fc4 = nn.Linear(l3, l4)
            self.fc5 = nn.Linear(l4, l3)
            self.fc6 = nn.Linear(l3, l2)
            self.fc7 = nn.Linear(l2, l1)
            self.fc8 = nn.Linear(l1, input_size)

    def encode(self, x):
        if self.model_type == 'small':
            h1 = F.relu(self.fc1(x))
            h2 = self.fc2(h1)
            return h2
        elif self.model_type == 'mid':
            h1 = F.relu(self.fc1(x))
            h2 = F.relu(self.fc2(h1))
            h3 = self.fc3(h2)
            return h3
        elif self.model_type == 'large':
            h1 = F.relu(self.fc1(x))
            h2 = F.relu(self.fc2(h1))
            h3 = F.relu(self.fc3(h2))
            h4 = self.fc4(h3)
            return h4

    def decode(self, z):
        if self.model_type == 'small':
            h1 = F.relu(self.fc3(z))
            h2 = self.fc4(h1)
            return torch.sigmoid(h2)
        elif self.model_type == 'mid':
            h1 = F.relu(self.fc4(z))
            h2 = F.relu(self.fc5(h1))
            h3 = self.fc6(h2)
            return torch.sigmoid(h3)
        elif self.model_type == 'large':
            h1 = F.relu(self.fc5(z))
            h2 = F.relu(self.fc6(h1))
            h3 = F.relu(self.fc7(h2))
            h4 = self.fc8(h3)
            return torch.sigmoid(h4)

    def forward(self, x):
        h = self.encode(x.view(-1, self.input_size))
        r = self.decode(h)
        return r


def read_dataset(path, batch_size=1, preprocess=False, debug=False, cutoff=-1, seq_cutoff=-1, split_train_test=False, stats=None, shuffle=False, add_additional_features=False, use_conn_id=False):
    def parse_flags(flags):
        flags_lst = [0] * len(TCP_FLAGS_MAP)
        if not isinstance(flags, str):
            return flags_lst
        flags_set = set(flags)
        for flag, idx in TCP_FLAGS_MAP.items():
            if flag in flags_set:
                flags_lst[idx] = 1
        return flags_lst

    def parse_ip_version(ip_version):
        ip_version_lst = [0] * len(IP_VERSION_MAP)
        for version, idx in IP_VERSION_MAP.items():
            if int(version) == ip_version:
                ip_version_lst[idx] = 1
        return ip_version_lst

    def parse_md5header(md5header):
        md5header_lst = [0] * len(TCP_OPT_MD5HEADER_MAP)
        for md5_state, idx in TCP_OPT_MD5HEADER_MAP.items():
            if int(md5_state) == md5header:
                md5header_lst[idx] = 1
        return md5header_lst

    def rescale(ori_val, stats):
        maxn, minn, mean = stats['max'], stats['min'], stats['mean']
        if maxn == minn:
            if ori_val < minn:
                return -0.1
            elif ori_val > maxn:
                return 1.1
            else:
                return 0.0
        else:
            return (float(ori_val - minn) / (maxn - minn))

    def summarize(dataframe, col_name, numeral_system=10, debug=True):
        if numeral_system != 10:
            x = dataframe[col_name].tolist()[0]
            col_list = [int(str(r), numeral_system)
                        for r in dataframe[col_name].tolist()]
        else:
            col_list = dataframe[col_name].tolist()
        col_stats = {'max': max(col_list), 'min': min(
            col_list), 'mean': sum(col_list)/float(len(col_list))}
        return col_stats

    def add_oor_feature(bounds, val, records):
        maxn, minn, mean = bounds['max'], bounds['min'], bounds['mean']
        if val < minn or val > maxn:
            records.append(1.0)
        else:
            records.append(0.0)

    def preprocess(attack_records, numeric_stats, sk_labels_map, debug=False, add_additional_features=False):
        preprocessed_records = []
        labels = []

        for idx, row in attack_records.iterrows():
            curr_record = []

            if use_conn_id:
                curr_record.append(int(row['ATTACK_ID']))

            if 'DIRECTION' in row:
                curr_record.append(float(row['DIRECTION']))

            if 'SEQ' in row:
                rescaled_seq = rescale(int(row['SEQ']), numeric_stats['SEQ'])
                curr_record.append(rescaled_seq)

            if 'ACK' in row:
                rescaled_ack = rescale(int(row['ACK']), numeric_stats['ACK'])
                curr_record.append(rescaled_ack)

            if 'DATAOFF' in row:
                rescaled_dataoff = rescale(
                    int(row['DATAOFF']), numeric_stats['DATAOFF'])
                curr_record.append(rescaled_dataoff)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['DATAOFF'], row['DATAOFF'], curr_record)

            if 'FLAGS' in row:
                curr_record.extend(parse_flags(row['FLAGS']))

            if 'WINDOW' in row:
                rescaled_window = rescale(
                    int(row['WINDOW']), numeric_stats['WINDOW'])
                curr_record.append(rescaled_window)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['WINDOW'], row['WINDOW'], curr_record)

            if 'CHKSUM' in row:
                curr_record.append(float(row['CHKSUM']))

            if 'URGPTR' in row:
                rescaled_urg = rescale(
                    int(str(row['URGPTR'])), numeric_stats['URGPTR'])
                curr_record.append(rescaled_urg)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['URGPTR'], row['URGPTR'], curr_record)

            labels.append(sk_labels_map[row['SK_STATE']])

            if 'PAYLOAD_LEN' in row:
                rescaled_payload_len = rescale(
                    int(row['PAYLOAD_LEN']), numeric_stats['PAYLOAD_LEN'])
                curr_record.append(rescaled_payload_len)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['PAYLOAD_LEN'], row['PAYLOAD_LEN'], curr_record)

            if 'IP_LEN' in row:
                rescaled_ip_len = rescale(
                    int(row['IP_LEN']), numeric_stats['IP_LEN'])
                curr_record.append(rescaled_ip_len)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['IP_LEN'], row['IP_LEN'], curr_record)

            if 'IP_TTL' in row:
                rescaled_ip_ttl = rescale(
                    int(row['IP_TTL']), numeric_stats['IP_TTL'])
                curr_record.append(rescaled_ip_ttl)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['IP_TTL'], row['IP_TTL'], curr_record)

            if 'IP_IHL' in row:
                rescaled_ip_ihl = rescale(
                    int(row['IP_IHL']), numeric_stats['IP_IHL'])
                curr_record.append(rescaled_ip_ihl)
                add_oor_feature(
                    numeric_stats['IP_IHL'], row['IP_IHL'], curr_record)

            if add_additional_features:
                if row['IP_IHL'] + row['DATAOFF'] + row['PAYLOAD_LEN'] == row['IP_LEN']:
                    curr_record.append('0.0')
                else:
                    curr_record.append('1.0')

            if 'IP_CHKSUM' in row:
                curr_record.append(float(row['IP_CHKSUM']))

            if 'IP_VERSION' in row:
                curr_record.extend(parse_ip_version(row['IP_VERSION']))

            if 'IP_TOS' in row:
                rescaled_ip_tos = rescale(
                    int(row['IP_TOS']), numeric_stats['IP_TOS'])
                curr_record.append(rescaled_ip_tos)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['IP_TOS'], row['IP_TOS'], curr_record)

            if 'IP_OPT_NON_STANDARD' in row:
                curr_record.append(float(row['IP_OPT_NON_STANDARD']))

            if 'TCP_OPT_MSS' in row:
                rescaled_tcp_opt_mss = rescale(
                    int(row['TCP_OPT_MSS']), numeric_stats['TCP_OPT_MSS'])
                curr_record.append(rescaled_tcp_opt_mss)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_OPT_MSS'], row['TCP_OPT_MSS'], curr_record)

            if 'TCP_OPT_TSVAL' in row:
                rescaled_tcp_opt_tsval = rescale(
                    int(row['TCP_OPT_TSVAL']), numeric_stats['TCP_OPT_TSVAL'])
                curr_record.append(rescaled_tcp_opt_tsval)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_OPT_TSVAL'], row['TCP_OPT_TSVAL'], curr_record)

            if 'TCP_OPT_TSECR' in row:
                rescaled_tcp_opt_tsecr = rescale(
                    int(row['TCP_OPT_TSECR']), numeric_stats['TCP_OPT_TSECR'])
                curr_record.append(rescaled_tcp_opt_tsecr)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_OPT_TSECR'], row['TCP_OPT_TSECR'], curr_record)

            if 'TCP_OPT_WSCALE' in row:
                rescaled_tcp_opt_wscale = rescale(
                    int(row['TCP_OPT_WSCALE']), numeric_stats['TCP_OPT_WSCALE'])
                curr_record.append(rescaled_tcp_opt_wscale)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_OPT_WSCALE'], row['TCP_OPT_WSCALE'], curr_record)

            if 'TCP_OPT_UTO' in row:
                rescaled_tcp_opt_uto = rescale(
                    int(row['TCP_OPT_UTO']), numeric_stats['TCP_OPT_UTO'])
                curr_record.append(rescaled_tcp_opt_uto)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_OPT_UTO'], row['TCP_OPT_UTO'], curr_record)

            if 'TCP_OPT_MD5HEADER' in row:
                curr_record.extend(parse_md5header(row['TCP_OPT_MD5HEADER']))

            if 'TCP_OPT_NON_STANDARD' in row:
                curr_record.append(float(row['TCP_OPT_NON_STANDARD']))

            if 'TCP_TIMESTAMP' in row:
                rescaled_tcp_timestamp = rescale(
                    float(row['TCP_TIMESTAMP']), numeric_stats['TCP_TIMESTAMP'])
                curr_record.append(rescaled_tcp_timestamp)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['TCP_TIMESTAMP'], row['TCP_TIMESTAMP'], curr_record)

            if 'ARRIVAL_TIMESTAMP' in row:
                rescaled_arrival_timestamp = rescale(
                    float(row['ARRIVAL_TIMESTAMP']), numeric_stats['ARRIVAL_TIMESTAMP'])
                curr_record.append(rescaled_arrival_timestamp)
                if add_additional_features:
                    add_oor_feature(
                        numeric_stats['ARRIVAL_TIMESTAMP'], row['ARRIVAL_TIMESTAMP'], curr_record)

            preprocessed_records.append(curr_record)

        return np.array(preprocessed_records, dtype=np.float32), np.array(labels, dtype=np.int)

    dataset = []
    dataframe = pandas.read_csv(path, sep=',', header='infer')
    labels_stats = []
    print("Reading dataset from path: %s" % path)

    if preprocess:
        trimmed_dataframe = dataframe[TRIMMED_COL_NAMES]
        print("[INFO][Preprocessing] Column names: %s" %
              str(list(trimmed_dataframe.columns)))

        sk_state_labels_map = {}
        sk_state_labels = sorted(list(set(dataframe['SK_STATE'].tolist())))
        for i in range(len(sk_state_labels)):
            sk_state_labels_map[sk_state_labels[i]] = i

        if stats is None or debug:
            seq_stats = summarize(dataframe, 'SEQ')
            ack_stats = summarize(dataframe, 'ACK')
            urg_stats = summarize(dataframe, 'URGPTR')
            dataoff_stats = summarize(dataframe, 'DATAOFF')
            window_stats = summarize(dataframe, 'WINDOW')
            payload_len_stats = summarize(dataframe, 'PAYLOAD_LEN')
            ip_len_stats = summarize(dataframe, 'IP_LEN')
            ip_ttl_stats = summarize(dataframe, 'IP_TTL')
            ip_ihl_stats = summarize(dataframe, 'IP_IHL')
            ip_tos_stats = summarize(dataframe, 'IP_TOS')
            ip_id_stats = summarize(dataframe, 'IP_ID')
            tcp_opt_mss_stats = summarize(dataframe, 'TCP_OPT_MSS')
            tcp_opt_tsval_stats = summarize(dataframe, 'TCP_OPT_TSVAL')
            tcp_opt_tsecr_stats = summarize(dataframe, 'TCP_OPT_TSECR')
            tcp_opt_wscale_stats = summarize(dataframe, 'TCP_OPT_WSCALE')
            tcp_opt_uto_stats = summarize(dataframe, 'TCP_OPT_UTO')
            tcp_timestamp = summarize(dataframe, 'TCP_TIMESTAMP')
            arrival_timestamp = summarize(dataframe, 'ARRIVAL_TIMESTAMP')
            new_numeric_stats = {"SEQ": seq_stats, "ACK": ack_stats, "URGPTR": urg_stats,
                                 "DATAOFF": dataoff_stats, "WINDOW": window_stats, "PAYLOAD_LEN": payload_len_stats,
                                 "IP_LEN": ip_len_stats, "IP_TTL": ip_ttl_stats, "IP_IHL": ip_ihl_stats,
                                 "IP_TOS": ip_tos_stats, "IP_ID": ip_id_stats, "TCP_OPT_MSS": tcp_opt_mss_stats,
                                 "TCP_OPT_TSVAL": tcp_opt_tsval_stats, "TCP_OPT_TSECR": tcp_opt_tsecr_stats,
                                 "TCP_OPT_WSCALE": tcp_opt_wscale_stats, "TCP_OPT_UTO": tcp_opt_uto_stats,
                                 "TCP_TIMESTAMP": tcp_timestamp, "ARRIVAL_TIMESTAMP": arrival_timestamp}
        if debug:
            print("Debug stats: %s" % str(new_numeric_stats))
        if stats is None:
            numeric_stats = new_numeric_stats
        else:
            numeric_stats = stats

        attack_id_list = sorted(
            list(set(trimmed_dataframe['ATTACK_ID'].tolist())))

        cnt = 0
        for attack_id in attack_id_list:
            if cutoff != -1:
                cnt += 1
                if cnt > cutoff:
                    break
            attack_records = trimmed_dataframe.loc[trimmed_dataframe['ATTACK_ID'] == attack_id]
            preprocessed_attack_records, labels = preprocess(
                attack_records, numeric_stats, sk_state_labels_map, debug=debug, add_additional_features=add_additional_features)
            if seq_cutoff != -1:
                seq_cutoff = min(seq_cutoff, len(labels))
                preprocessed_attack_records = preprocessed_attack_records[:seq_cutoff]
                labels = labels[:seq_cutoff]
            labels_stats.extend(labels)
            dataset.append([preprocessed_attack_records, labels])

        labels_stats_counter = Counter(labels_stats)
        print("[INFO][Preprocessing] Label map: %s" % str(sk_state_labels_map))
        print("[INFO][Preprocessing] Label stats: %s" %
              str(labels_stats_counter))

    if shuffle:
        random.shuffle(dataset)

    if split_train_test:
        train_set = dataset[:-len(dataset)//TRAIN_TEST_SPLIT]
        test_set = dataset[-len(dataset)//TRAIN_TEST_SPLIT:]
        train_loader = torch.utils.data.DataLoader(
            train_set, batch_size=batch_size, shuffle=False)
        test_loader = torch.utils.data.DataLoader(
            test_set, batch_size=batch_size, shuffle=False)
        return train_loader, test_loader, sk_state_labels_map, numeric_stats, labels_stats_counter
    else:
        data_loader = torch.utils.data.DataLoader(
            dataset, batch_size=batch_size, shuffle=False)
        return data_loader, sk_state_labels_map, numeric_stats, labels_stats_counter


def pause():
    input("Press Enter to continue...")


def rnn_loss_function(outputs, labels, weight=None, debug=False):
    if debug:
        print(outputs.shape)
        print(labels.shape)
    if weight is not None:
        averaged_cross_entropy = F.cross_entropy(
            outputs, labels, weight=weight, reduction='mean')
    else:
        averaged_cross_entropy = F.cross_entropy(
            outputs, labels, reduction='mean')
    return averaged_cross_entropy


def ae_loss_function(recon_x, x, debug=False):
    if debug:
        print(recon_x.shape)
        print(x.shape)
    loss = nn.L1Loss(reduction="mean")
    return loss(recon_x, x)


def get_pred(rnn_outputs):
    _, preds = torch.max(rnn_outputs.data, 2)
    return preds


def print_per_label_accu(correct_labels, incorrect_labels, state_map):
    def create_reversed_map(state_map):
        reversed_map = {}
        for k, v in state_map.items():
            reversed_map[v] = k
        return reversed_map

    state_map = create_reversed_map(state_map)
    accu_map = {}
    for state_id, state in state_map.items():
        if state_id not in correct_labels:
            correct = 0
        else:
            correct = correct_labels[state_id]
        if state_id not in incorrect_labels:
            incorrect = 0
        else:
            incorrect = incorrect_labels[state_id]
        accu_map[state] = {'correct': correct, 'incorrect': incorrect}
        if correct + incorrect == 0:
            accu_map[state]['accuracy'] = 0.0
        else:
            accu_map[state]['accuracy'] = float(
                correct) / (correct + incorrect)
    print(accu_map)
    return accu_map


def generate_ngram_seq(seq, n_gram, only_outbound, use_conn_id=False, debug=False):
    if only_outbound:
        if use_conn_id:
            IDX_CONN_ID, IDX_DIRECTION = 0, 1
        else:
            IDX_DIRECTION = 0
        filtered_seq = []
        conn_ids = set()
        for profile in seq:
            if profile.view(-1)[IDX_DIRECTION] == 0.0:
                if use_conn_id:
                    conn_ids.add(profile.view(-1)[IDX_CONN_ID].item())
                    profile = profile.view(-1)[IDX_DIRECTION:].view(1, 1, -1)
                filtered_seq.append(profile)
        if use_conn_id:
            assert len(conn_ids) == 1, "[NGRAM] More than 1 conn_id in seq!"
            conn_id = int(list(conn_ids)[0])
        seq = filtered_seq

    if len(seq) < n_gram:
        return ERR_TOO_SHORT_SEQ

    ngram_seq = []
    start, end = 0, n_gram
    while end <= len(seq) - 1:
        ngram_sample = torch.cat(seq[start:end])
        if use_conn_id:
            ngram_seq.append((conn_id, torch.flatten(ngram_sample)))
        else:
            ngram_seq.append(torch.flatten(ngram_sample))
        start += 1
        end += 1

    return ngram_seq


def generate_ngram_seq_dataset(loader, n_gram, batch_size=64, debug=False, only_outbound=True):
    dataset = []
    for sample_idx, seq in enumerate(loader):
        ngram_seq = generate_ngram_seq(
            seq, n_gram, only_outbound=only_outbound)
        if ngram_seq == ERR_TOO_SHORT_SEQ:
            continue
        dataset.extend(ngram_seq)
    if debug:
        print("[INFO][Train] Shape of seq sample: %s" % str(dataset[0].shape))
        print("[INFO][Train] Size of dataset: %d" % len(dataset))
    return torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)


def generate_contextual_profile_dataset(data_loader, device, rnn_model, context_mode, partition_mode, rnn_model_type, label_map, addi_data_loader=None):
    if partition_mode == "none":
        contextual_dataset = []
    else:
        contextual_dataset = {}

    for batch_idx, [x, labels] in enumerate(data_loader):
        x = x.to(device, dtype=torch.float)
        labels = labels.to(device)
        curr_seq = []

        if context_mode != 'baseline':
            outputs, gates, hn = rnn_model(x)
            preds = get_pred(outputs)

        for i in range(x.size(1)):
            x_features = x[:, i, :]

            if context_mode != 'baseline':
                if 'lstm' in rnn_model_type:
                    resetgate, inputgate, cellgate, outgate = gates[i]
                else:
                    resetgate, inputgate = gates[i]
                hiddenstate = hn[i]
                pred_label = preds[:, i].item()
                gt_label = labels[:, i].item()

            if context_mode == "baseline":
                profile = x_features.detach()
            elif context_mode == "use_hn":
                profile = torch.cat(
                    (x_features.detach(), hiddenstate.detach()), dim=1)
            elif context_mode == "use_all":
                if 'lstm' in rnn_model_type:
                    profile = torch.cat(
                        (x_features.detach(), hiddenstate.detach(), resetgate.detach(), inputgate.detach(), cellgate.detach(), outgate.detach()), dim=1)
                else:
                    profile = torch.cat(
                        (x_features.detach(), hiddenstate.detach(), resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "only_gates":
                profile = torch.cat(
                    (resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "only_hn":
                profile = hiddenstate.detach()
            elif context_mode == "use_all_gates":
                profile = torch.cat(
                    (x_features.detach(), resetgate.detach(), inputgate.detach(), cellgate.detach(), outgate.detach()), dim=1)
            elif context_mode == "use_gates":
                profile = torch.cat(
                    (x_features.detach(), resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "use_gates_label":
                state_str = label_map[pred_label]
                label_vec = [0] * (len(nf_conntrack_states) + 1)
                for i in range(len(nf_conntrack_states)):
                    if nf_conntrack_states[i] in state_str:
                        label_vec[i] = 1.0
                if 'IW' in state_str:
                    label_vec[-1] = 1.0
                label_vec = torch.tensor(label_vec).to(device)
                label_vec = label_vec.view(1, len(nf_conntrack_states)+1)
                profile = torch.cat(
                    (x_features.detach(), label_vec.detach(), resetgate.detach(), inputgate.detach()), dim=1)

            if partition_mode == "none":
                curr_seq.append(profile)
            elif partition_mode == "pred_label":
                if pred_label not in contextual_dataset:
                    contextual_dataset[pred_label] = [profile]
                else:
                    contextual_dataset[pred_label].append(profile)
            elif partition_mode == "gt_label":
                if gt_label not in contextual_dataset:
                    contextual_dataset[gt_label] = [profile]
                else:
                    contextual_dataset[gt_label].append(profile)

        if partition_mode == "none":
            contextual_dataset.append(curr_seq)

    return contextual_dataset


def generate_contextual_profile_dataset_fused(data_loader, device, rnn_model, context_mode, partition_mode, rnn_model_type, label_map, addi_data_loader):
    if partition_mode == "none":
        contextual_dataset = []
    else:
        contextual_dataset = {}

    for batch_idx, ([x, labels], [x2, _]) in enumerate(zip(data_loader, addi_data_loader)):
        x = x.to(device, dtype=torch.float)
        x2 = x2.to(device, dtype=torch.float)
        labels = labels.to(device)
        curr_seq = []

        if context_mode != 'baseline':
            outputs, gates, hn = rnn_model(x)
            preds = get_pred(outputs)

        for i in range(x.size(1)):
            x_features = x[:, i, :]
            x2_features = x2[:, i, :]

            if context_mode != 'baseline':
                if 'lstm' in rnn_model_type:
                    resetgate, inputgate, cellgate, outgate = gates[i]
                else:
                    resetgate, inputgate = gates[i]
                hiddenstate = hn[i]
                pred_label = preds[:, i].item()
                gt_label = labels[:, i].item()

            if context_mode == "baseline":
                profile = x2_features.detach()
            elif context_mode == "use_hn":
                profile = torch.cat(
                    (x2_features.detach(), hiddenstate.detach()), dim=1)
            elif context_mode == "use_all":
                if 'lstm' in rnn_model_type:
                    profile = torch.cat(
                        (x2_features.detach(), hiddenstate.detach(), resetgate.detach(), inputgate.detach(), cellgate.detach(), outgate.detach()), dim=1)
                else:
                    profile = torch.cat(
                        (x2_features.detach(), hiddenstate.detach(), resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "only_gates":
                profile = torch.cat(
                    (resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "only_hn":
                profile = hiddenstate.detach()
            elif context_mode == "use_all_gates":
                profile = torch.cat(
                    (x2_features.detach(), resetgate.detach(), inputgate.detach(), cellgate.detach(), outgate.detach()), dim=1)
            elif context_mode == "use_gates":
                profile = torch.cat(
                    (x2_features.detach(), resetgate.detach(), inputgate.detach()), dim=1)
            elif context_mode == "use_gates_label":
                state_str = label_map[pred_label]
                label_vec = [0] * (len(nf_conntrack_states) + 1)
                for i in range(len(nf_conntrack_states)):
                    if nf_conntrack_states[i] in state_str:
                        label_vec[i] = 1.0
                if 'IW' in state_str:
                    label_vec[-1] = 1.0
                label_vec = torch.tensor(label_vec).to(device)
                label_vec = label_vec.view(1, len(nf_conntrack_states)+1)
                profile = torch.cat(
                    (x2_features.detach(), label_vec.detach(), resetgate.detach(), inputgate.detach()), dim=1)

            if partition_mode == "none":
                curr_seq.append(profile)
            elif partition_mode == "pred_label":
                if pred_label not in contextual_dataset:
                    contextual_dataset[pred_label] = [profile]
                else:
                    contextual_dataset[pred_label].append(profile)
            elif partition_mode == "gt_label":
                if gt_label not in contextual_dataset:
                    contextual_dataset[gt_label] = [profile]
                else:
                    contextual_dataset[gt_label].append(profile)

        if partition_mode == "none":
            contextual_dataset.append(curr_seq)

    return contextual_dataset


def get_losslist(overall_data_loader, vae_model, vae_input_size, n_gram, debug=False, only_outbound=True, use_conn_id=False, draw_trend=True):
    def get_windowed_top_loss(loss_list, max_idx, window_size=5):
        if len(loss_list) < window_size:
            return sum(loss_list) / len(loss_list)
        start, end = max_idx, max_idx
        while end - start < window_size and (start > 0 or end < len(loss_list) - 1):
            if start > 0:
                start -= 1
            if end < len(loss_list) - 1:
                end += 1
        assert len(loss_list[start:end]) == end - start, "Size unmatch!"
        return sum(loss_list[start:end]) / len(loss_list[start:end])

    if isinstance(overall_data_loader, dict):
        attack_test_loss = {}
        attack_cnt = {}
        attack_loss_list = {}
        for label, data_loader in overall_data_loader.items():
            attack_test_loss[label] = 0.0
            attack_cnt[label] = 0
            attack_loss_list[label] = []
            for batch_idx, profile in enumerate(data_loader):
                attack_cnt[label] += 1
                profile = profile.view(1, vae_input_size)
                recon_profile = vae_model[label](profile)
                loss = ae_loss_function(recon_profile, profile)
                curr_loss = loss.item()
                attack_loss_list[label].append(curr_loss)
                attack_test_loss[label] += curr_loss

        return attack_cnt, attack_test_loss, attack_loss_list
    else:
        attack_test_loss, seq_test_loss = 0, 0
        seq_cnt, attack_cnt = 0, 0
        attack_loss_list, seq_loss_list = [], []
        if draw_trend:
            x, y = {}, {}
        for batch_idx, seq in enumerate(overall_data_loader):
            ngram_seq = generate_ngram_seq(
                seq, n_gram, only_outbound=only_outbound, use_conn_id=use_conn_id, debug=debug)
            if debug:
                input(ngram_seq)
            if ngram_seq == ERR_TOO_SHORT_SEQ:
                continue
            if len(ngram_seq) == 0:
                continue
            seq_cnt += len(ngram_seq)
            attack_cnt += 1

            max_loss = 0.0
            total_loss = 0.0
            max_idx = 0
            curr_loss_list = []
            for idx, ngram in enumerate(ngram_seq):
                if use_conn_id:
                    conn_id, ngram = ngram
                ngram = ngram.view(1, vae_input_size)
                recon_ngram = vae_model(ngram)
                loss = ae_loss_function(recon_ngram, ngram)
                curr_loss = loss.item()
                total_loss += curr_loss
                seq_test_loss += curr_loss
                seq_loss_list.append(curr_loss)
                curr_loss_list.append(curr_loss)

            if debug:
                input("Sample #%d max recon error: %f" % (batch_idx, max_loss))
            if draw_trend:
                if len(curr_loss_list) > 50:
                    x[str(conn_id)] = [i for i in range(
                        1, len(curr_loss_list) + 1)]
                    y[str(conn_id)] = curr_loss_list

            max_loss = max(curr_loss_list)
            top_loss_idx = sorted(range(len(curr_loss_list)),
                                  key=lambda i: curr_loss_list[i], reverse=True)[:5]
            max_loss_idx = top_loss_idx[0]
            windowed_mean_loss = get_windowed_top_loss(
                curr_loss_list, max_loss_idx, 5)
            mean_loss = total_loss / len(ngram_seq)
            median_loss = statistics.median(curr_loss_list)
            r1 = 0.0
            r2 = 0.0
            r3 = 0.0
            r4 = 1.0
            weighted_loss = r1 * max_loss + r2 * mean_loss + \
                r3 * median_loss + r4 * windowed_mean_loss
            attack_test_loss += weighted_loss
            if debug:
                input("max_loss: %f (max_id: %d); average_loss: %f" %
                      (max_loss, max_idx, weighted_loss))
            if use_conn_id:
                attack_loss_list.append(
                    (weighted_loss, str(top_loss_idx), str(conn_id), len(ngram_seq)))
            else:
                attack_loss_list.append(
                    (weighted_loss, str(top_loss_idx), len(ngram_seq)))

        if draw_trend:
            return attack_cnt, seq_cnt, attack_test_loss, seq_test_loss, attack_loss_list, seq_loss_list, x, y
        else:
            return attack_cnt, seq_cnt, attack_test_loss, seq_test_loss, attack_loss_list, seq_loss_list


def plot_roc_curve(fpr, tpr, score, fig_path, ds_title):
    plt.title('ROC Curve for %s Attack' % ds_title)
    plt.plot(fpr, tpr, 'b', label='AUC = %0.2f' % score)
    plt.legend(loc='lower right')
    plt.plot([0, 1], [0, 1], 'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.savefig(fig_path)
    plt.close()


def plot_roc_curve_comparison(fpr1, tpr1, fpr2, tpr2, score1, score2, fig_path, ds_title):
    plt.title('ROC Curve on %s Attack' % ds_title)
    plt.plot(fpr1, tpr1, 'grey', label='Baseline, AUC = %0.2f' %
             score1, linestyle='dashed')
    plt.plot(fpr2, tpr2, 'b', label='Our Approach, AUC = %0.2f' % score2)
    plt.legend(loc='lower right')
    plt.plot([0, 1], [0, 1], 'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.savefig(fig_path)
    plt.close()


def read_loss_list(loss_list, balance_by_label=False, deduplicate=False):
    with open(loss_list, "r") as fin:
        data = fin.readlines()

    if deduplicate:
        data = list(set(data))
    y = []
    scores = []
    random.shuffle(data)

    top_loss_lst = {}
    use_top_loss = False

    for row in data:
        if len(row) <= 1:
            continue

        if len(row.rstrip('\n').split("\t")) == 4:
            loss, idx, leng, label = row.rstrip('\n').split("\t")
        elif len(row.rstrip('\n').split("\t")) == 5:
            use_top_loss = True
            loss, idx, conn_id, leng, label = row.rstrip('\n').split("\t")
        else:
            print(row)
            input("WTF? %d" % len(row.rstrip('\n').split("\t")))

        if use_top_loss:
            top_loss_lst[conn_id] = eval(idx)
        y.append(int(label))
        scores.append(float(loss))

    if balance_by_label:
        label_set = collections.Counter(y)
        attack_cnt = label_set[1]
        benign_cnt = label_set[0]
        smaller = min(attack_cnt, benign_cnt)
        print("[INFO] Attack count: %d" % attack_cnt)
        print("[INFO] Benign count: %d" % benign_cnt)
        if use_top_loss:
            return y[:smaller], scores[:smaller], top_loss_lst
        else:
            return y[:smaller], scores[:smaller]
    else:
        if use_top_loss:
            return y, scores, top_loss_lst
        else:
            return y, scores


def calculate_acc(outputs, labels, debug=False):
    _, preds = torch.max(outputs.data, 1)
    if debug:
        correct_list = (preds == labels)
        print(correct_list)
        print(labels)
        print(labels[correct_list])
        print(labels[correct_list == False])
        input("Press Enter to continue...")

    correct_list = (preds == labels)
    correct_cnt = correct_list.sum()
    total_cnt = labels.size(0)

    correct_labels = labels[correct_list]
    incorrect_labels = labels[correct_list == False]

    return correct_cnt, total_cnt, correct_labels, incorrect_labels
