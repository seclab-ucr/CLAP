import matplotlib as mpl
import argparse
import pprint
from math import ceil

import matplotlib
import matplotlib.pyplot as plt

pp = pprint.PrettyPrinter(indent=2)

font = {'family': 'sans-serif',
        'weight': 'bold',
        'size': 14}

matplotlib.rcParams['hatch.linewidth'] = 0.9

matplotlib.rc('font', **font)

NAME_MAP = {
    "Geneva_Strategy_1*max*": "Invalid Data-Offset,Bad TCP Checksum",
    "Geneva_Strategy_2*max*": "Invalid Data-Offset,Low TTL",
    "Geneva_Strategy_3*max*": "Invalid Data-Offset,Bad ACK Num",
    "Geneva_Strategy_4*max*": "Invalid TCP WScale-Option,Invalid Data-Offset",
    "Geneva_Strategy_5*max*": "Bad Payload Length,Bad TCP Checksum",
    "Geneva_Strategy_6*max*": "Bad Payload Length,Low TTL",
    "Geneva_Strategy_7*max*": "Bad Payload Length,Bad ACK Num",
    "Geneva_Strategy_8*max*": "/,Bad Payload Length",
    "Geneva_Strategy_9*max*": "Bad IP Length,/",
    "Geneva_Strategy_10*max*": "Injected RST,Bad IP Length",
    "Geneva_Strategy_11*max*": "Injected RST,Bad TCP Checksum",
    "Geneva_Strategy_12*max*": "Injected RST,Low TTL",
    "Geneva_Strategy_13*max*": "Bad TCP MD5-Option,Injected RST",
    "Geneva_Strategy_14*max*": "Injected RST-ACK,Bad TCP Checksum",
    "Geneva_Strategy_15*max*": "Injected RST-ACK,Low TTL",
    "Geneva_Strategy_16*max*": "Bad TCP MD5-Option,Injected RST",
    "Geneva_Strategy_17*max*": "Invalid Flags #1,Bad TCP Checksum",
    "Geneva_Strategy_18*max*": "Invalid Flags #2,Low TTL",
    "Geneva_Strategy_19*max*": "Invalid Flags #2,Bad TCP MD5-Option",
    "Geneva_Strategy_23*max*": "Injected FIN,Bad IP Length",
    "Geneva_Strategy_24*max*": "Injected SYN-ACK,Bad TCP MD5-Option",
    "Geneva_Strategy_23*max*": "Bad TCP UTO-Option,Bad TCP MD5-Option",
    "Liberate_IP_InvalidHeaderLen*max*": "Invalid IP Header Length,Max",
    "Liberate_IP_InvalidHeaderLen*min*": "Invalid IP Header Length,Min",
    "Liberate_IP_InvalidVersion*max*": "Invalid IP Version,Max",
    "Liberate_IP_InvalidVersion*max*": "Invalid IP Version,Min",
    "Liberate_IP_LongerLength*max*": "Bad IP Length (Too Long),Max",
    "Liberate_IP_LongerLength*min*": "Bad IP Length (Too Long),Min",
    "Liberate_IP_ShorterLength*max*": "Bad IP Length (Too Short),Max",
    "Liberate_IP_ShorterLength*min*": "Bad IP Length (Too Short),Min",
    "Liberate_IP_LowTTL*max*": "Low TTL,Max",
    "Liberate_IP_LowTTL*min*": "Low TTL,Min",
    "Liberate_IP_LowTTLRSTa*max*": "RST w/ Low TTL #1,max",
    "Liberate_IP_LowTTLRSTa*min*": "RST w/ Low TTL #1,min",
    "Liberate_IP_LowTTLRSTb*max*": "RST w/ Low TTL #2,max",
    "Liberate_IP_LowTTLRSTb*min*": "RST w/ Low TTL #2,min",
    "Liberate_TCP_ACKNotSet*max*": "Data Packet wo/ ACK Flag,Max",
    "Liberate_TCP_ACKNotSet*min*": "Data Packet wo/ ACK Flag,Min",
    "Liberate_TCP_InvalidDataoff*max*": "Invalid Data-Offset,Max",
    "Liberate_TCP_InvalidDataoff*min*": "Invalid Data-Offset,Min",
    "Liberate_TCP_InvalidFlagComb*max*": "Invalid Flags,Max",
    "Liberate_TCP_InvalidFlagComb*min*": "Invalid Flags,Min",
    "Liberate_TCP_WrongChksum*max*": "Bad TCP Checksum,Max",
    "Liberate_TCP_WrongChksum*min*": "Bad TCP Checksum,Min",
    "Liberate_TCP_WrongSEQ*max*": "Bad SEQ,Max",
    "Liberate_TCP_WrongSEQ*min*": "Bad SEQ,Min",
    "SymTCP_Zeek_SYNWithData": "SYN,w/ Payload,Zeek",
    "SymTCP_GFW_OutOfWindowSYNData": "SYN,w/ Payload & Bad SEQ,GFW #1",
    "SymTCP_GFW_RetransmittedSYNData": "SYN,w/ Payload & Bad SEQ,GFW #2",
    "SymTCP_Zeek_MultipleSYN": "SYN,Multiple (SYN),Zeek",
    "SymTCP_Snort_MultipleSYN": "SYN,Multiple (SYN),Snort",
    "SymTCP_GFW_FINWithData": "Injected FIN,w/ Payload,GFW",
    "SymTCP_Zeek_PureFIN": "Injected FIN,w/ Payload,Zeek",
    "SymTCP_Zeek_PureFIN": "Injected FIN,Pure,Zeek",
    "SymTCP_Snort_InWindowFIN": "Injected FIN,Pure,Snort",
    "SymTCP_Snort_RSTMD5": "Injected RST,Bad TCP MD5-Option,Snort",
    "SymTCP_Snort_RSTBadTimestamp": "Injected RST,Bad Timestamp,Snort",
    "SymTCP_GFW_RSTBadTimestamp": "Injected RST,Bad Timestamp,GFW",
    "SymTCP_Snort_PartialInWindowRST": "Injected RST,Partial In-Window,Snort",
    "SymTCP_GFW_BadRST": "Injected RST,Bad TCP-Checksum/MD5-Option,GFW",
    "SymTCP_Snort_InWindowRST": "Injected RST,Pure,Snort",
    "SymTCP_Zeek_BadRSTFIN": "Injected RST/FIN-ACK,Bad SEQ,Zeek",
    "SymTCP_Snort_FINACKBadACK": "Injected FIN-ACK,Bad ACK Num,Snort",
    "SymTCP_GFW_FINACKDataBadACK": "Injected FIN-ACK,Bad ACK Num,GFW",
    "SymTCP_Snort_FINACKMD5": "Injected FIN-ACK,Bad TCP MD5-Option,Snort",
    "SymTCP_GFW_BadFINACKData": "Injected FIN-ACK,Bad TCP-Checksum/MD5-Option,GFW",
    "SymTCP_GFW_RSTACKBadACKNum": "Injected RST-ACK,Bad ACK Num,GFW",
    "SymTCP_Snort_RSTACKBadACKNum": "Injected RST-ACK,Bad ACK Num,Snort",
    "SymTCP_Zeek_SEQJump": "Data Packet (ACK),Bad SEQ,Zeek",
    "SymTCP_Zeek_UnderflowSEQ": "Data Packet (ACK),Underflow SEQ,Zeek",
    "SymTCP_GFW_UnderflowSEQ": "Data Packet (ACK),Underflow SEQ,GFW",
    "SymTCP_Zeek_DataBadACK": "Data Packet (ACK),Bad ACK Num,Zeek",
    "SymTCP_Zeek_DataOverlapping": "Data Packet (ACK),Overlapping,Zeek",
    "SymTCP_Zeek_DataWithoutACK": "Data Packet (ACK),wo/ ACK Flag,Zeek",
    "SymTCP_GFW_DataWithoutACK": "Data Packet (ACK),wo/ ACK Flag,GFW",
    "SymTCP_Snort_UrgentData": "Data Packet (ACK),w/ Urgent Pointer,Snort",
    "SymTCP_GFW_BadData": "Data Packet (ACK),Bad TCP-Checksum/MD5-Option,GFW",
    "SymTCP_Snort_TimeGap": "Data Packet (ACK),Bad Timestamp,Snort",
}


def read_and_merge_res(our_app_res_fpath, dump_fpath):
    def read_data(fpath, opt=None):
        with open(fpath, 'r') as fin:
            d = {}
            names_by_work = {"SymTCP": [], "Liberate": [], "Geneva": []}
            data = fin.readlines()
            del data[0]
            for row in data:
                if row.startswith('#'):
                    continue
                row = row.rstrip('\n')
                if opt == 'tool_log_format':
                    _, name, auc_roc_score, tpr001, tpr005, eer_score, top1_hit_acc, top3_hit_acc, top5_hit_acc = row.split(
                        ',')
                    data_rec = ','.join(
                        [auc_roc_score, tpr001, tpr005, eer_score, top1_hit_acc, top3_hit_acc, top5_hit_acc])
                if opt == 'kitsune_log_format':
                    name, auc_roc_score, tpr001, tpr005, eer_score = row.split(
                        ',')
                    if name.endswith("_max"):
                        name = name.replace('_max', '*max*')
                    if name.endswith("_min"):
                        name = name.replace('_min', '*min*')
                    data_rec = ','.join(
                        [auc_roc_score, tpr001, tpr005, eer_score])
                if "SymTCP" in name:
                    names_by_work["SymTCP"].append(name)
                if "Liberate" in name:
                    names_by_work["Liberate"].append(name)
                if "Geneva" in name:
                    names_by_work["Geneva"].append(name)
                d[name] = data_rec
        return d, names_by_work

    our_app_d, names_by_work = read_data(
        our_app_res_fpath, opt='tool_log_format')

    dump = []

    dump.append("#SymTCP")
    for ori_name in names_by_work["SymTCP"]:
        if ori_name not in NAME_MAP:
            continue
        name = NAME_MAP[ori_name]
        dump.append(
            ','.join([name, our_app_d[ori_name]]))

    dump.append("#Liberate")
    for ori_name in names_by_work["Liberate"]:
        if ori_name not in NAME_MAP:
            continue
        name = NAME_MAP[ori_name]
        dump.append(
            ','.join([name, our_app_d[ori_name]]))

    dump.append("#Geneva")
    for ori_name in names_by_work["Geneva"]:
        if ori_name not in NAME_MAP:
            continue
        name = NAME_MAP[ori_name]
        dump.append(
            ','.join([name, our_app_d[ori_name]]))

    with open(dump_fpath, 'w') as fout:
        for line in dump:
            fout.write('%s\n' % line)


def read_data(fpath):
    with open(fpath, 'r') as fin:
        data = fin.readlines()

    data_dict = {}
    curr_tag = ""
    for row in data:
        row = row.rstrip('\n')
        if len(row) == 0:
            continue
        if row.startswith('#'):
            curr_tag = row[1:]
            data_dict[curr_tag] = {}
        else:
            if curr_tag == 'SymTCP':
                primary_type, secondary_type, variant, \
                    cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc = row.split(',')
                cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc = float(cxt_res), float(cxt_tpr001), \
                    float(cxt_tpr005), float(cxt_eer_score), float(cxt_top1_hit_acc), float(cxt_top3_hit_acc), float(cxt_top5_hit_acc)
                if primary_type not in data_dict[curr_tag]:
                    data_dict[curr_tag][primary_type] = {}
                if secondary_type not in data_dict[curr_tag][primary_type]:
                    data_dict[curr_tag][primary_type][secondary_type] = {}
                data_dict[curr_tag][primary_type][secondary_type][variant] = (
                    cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc)
            if curr_tag in {'Liberate', 'Geneva'}:
                primary_type, secondary_type, \
                    cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc = row.split(
                        ',')
                cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc = float(cxt_res), float(cxt_tpr001), \
                    float(cxt_tpr005), float(cxt_eer_score), float(cxt_top1_hit_acc), float(cxt_top3_hit_acc), float(cxt_top5_hit_acc)
                if primary_type not in data_dict[curr_tag]:
                    data_dict[curr_tag][primary_type] = {}
                data_dict[curr_tag][primary_type][secondary_type] = (cxt_res, cxt_tpr001, cxt_tpr005, cxt_eer_score, cxt_top1_hit_acc, cxt_top3_hit_acc, cxt_top5_hit_acc)
    return data_dict


def draw(data_dict, type='detection'):
    def draw_a_subplot(ax, y, title, remove_yticks=False, plot_type='detection'):
        if plot_type == 'detection':
            x = [i for i in range(2)]
            idx_lst = [0, 3]
            scores = [y[i] for i in idx_lst]
            bars = ax.bar(x, scores, color=('#F96E46', '#FFE3E3'))

            hatch_lst = ('/', '/')
        if plot_type == 'localization':
            x = [i for i in range(1)]
            idx_lst = [6]
            scores = [y[i] for i in idx_lst]
            bars = ax.bar(x, scores, color=('#F96E46'))
            hatch_lst = ('+')
        ax.set_xticklabels([])
        if remove_yticks:
            ax.set_yticklabels([])
        ax.set_ylim([0.0, 1.0])
        ax.set_title(title, fontweight='bold')

        idx = 0
        for bar in bars:
            yval = '%.3f' % bar.get_height()
            ax.text(bar.get_x() + 0.4, 0.1,
                    yval, rotation='vertical', color='black', fontsize='x-large', ha='center')
            if hatch_lst is not None:
                bar.set_hatch(hatch_lst[idx])
            idx += 1
        return

    # for SymTCP
    data = data_dict["SymTCP"]
    subplot_cnt = 0
    for _, secondary in data.items():
        for _, var in secondary.items():
            for _, _ in var.items():
                subplot_cnt += 1
    if type == 'detection':
        ncol = 10
    if type == 'localization':
        ncol = 10
    nrow = ceil(subplot_cnt / ncol)
    fig, axes = plt.subplots(nrow, ncol)
    row, col = 0, 0
    cnt = 0
    for primary, secondary in data.items():
        for secondary_type, variant in secondary.items():
            if len(variant) == 1:  # meaning this is 'All' case
                row, col = cnt // ncol, cnt % ncol
                if col != 0:
                    draw_a_subplot(axes[row, col], list(variant.values())[0], '%s: %s\n%s' %
                                   (list(variant.keys())[0], primary, secondary_type), remove_yticks=True, plot_type=type)
                else:
                    draw_a_subplot(axes[row, col], list(variant.values())[0], '%s: %s\n%s' %
                                   (list(variant.keys())[0], primary, secondary_type), plot_type=type)
                cnt += 1
            else:
                for variant_name, res in variant.items():
                    row, col = cnt // ncol, cnt % ncol
                    if col != 0:
                        draw_a_subplot(axes[row, col], res, '%s: %s\n%s' %
                                       (variant_name, primary, secondary_type), remove_yticks=True, plot_type=type)
                    else:
                        draw_a_subplot(axes[row, col], res, '%s: %s\n%s' %
                                       (variant_name, primary, secondary_type), plot_type=type)
                    cnt += 1

    for i in range(nrow*ncol-subplot_cnt):
        fig.delaxes(axes[-1][-(i+1)])
    plt.subplots_adjust(hspace=.3)
    plt.show()

    # for Liberate
    data = data_dict['Liberate']
    subplot_cnt = 0
    for _, strategy in data.items():
        for _, _ in strategy.items():
            subplot_cnt += 1
    if type == 'detection':
        ncol = 10
    if type == 'localization':
        ncol = 10
    nrow = ceil(subplot_cnt / ncol)
    fig, axes = plt.subplots(nrow, ncol)
    row, col = 0, 0
    cnt = 0
    for primary, strategy in data.items():
        for strategy, res in strategy.items():
            row, col = cnt // ncol, cnt % ncol
            if col != 0:
                draw_a_subplot(axes[row, col], res, '%s\n%s' %
                               (primary, strategy), remove_yticks=True, plot_type=type)
            else:
                draw_a_subplot(axes[row, col], res, '%s\n%s' %
                               (primary, strategy), plot_type=type)
            cnt += 1

    for i in range(nrow*ncol-subplot_cnt):
        fig.delaxes(axes[-1][-(i+1)])
    plt.subplots_adjust(hspace=.3)
    plt.show()

    # for Geneva
    data = data_dict['Geneva']
    subplot_cnt = 0
    for _, secondary in data.items():
        for _, _ in secondary.items():
            subplot_cnt += 1
    if type == 'detection':
        ncol = 10
    if type == 'localization':
        ncol = 10
    nrow = ceil(subplot_cnt / ncol)
    fig, axes = plt.subplots(nrow, ncol)
    row, col = 0, 0
    cnt = 0
    for primary, secondary in data.items():
        for secondary, res in secondary.items():
            row, col = cnt // ncol, cnt % ncol
            if col != 0:
                draw_a_subplot(axes[row, col], res, '%s\n%s' %
                               (primary, secondary), remove_yticks=True, plot_type=type)
            else:
                draw_a_subplot(axes[row, col], res, '%s\n%s' %
                               (primary, secondary), plot_type=type)
            cnt += 1

    for i in range(nrow*ncol-subplot_cnt):
        fig.delaxes(axes[-1][-(i+1)])
    plt.subplots_adjust(hspace=.3)
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='This script generates figure for showing detection results.')
    parser.add_argument('--fin-our', type=str)
    parser.add_argument('--merged-res', type=str)
    args = parser.parse_args()

    read_and_merge_res(args.fin_our, args.merged_res)

    data_dict = read_data(args.merged_res)
    draw(data_dict)
    draw(data_dict, type='localization')
