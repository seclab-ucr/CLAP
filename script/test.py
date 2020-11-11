from utils import nf_conntrack_states
from utils import get_losslist
from utils import read_dataset, generate_ngram_seq, generate_contextual_profile_dataset, generate_contextual_profile_dataset_fused
from utils import AEModel, GRUModel, GRUCell
import argparse
import torch
from torch import nn, optim
from torch.autograd import Variable
import torch.nn.functional as F
import numpy as np
import pandas
import random
import time
import pickle
from os import path

import matplotlib.pyplot as plt
import matplotlib

font = {'family': 'normal',
        'weight': 'bold',
        'size': 16}

matplotlib.rc('font', **font)


ERR_TOO_SHORT_SEQ = -1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='GRU for learning benign contextual profiles')
    parser.add_argument('--attack-dataset', type=str,
                        help='path to positive dataset file')
    parser.add_argument('--benign-dataset', type=str,
                        help='path to negative dataset file')
    parser.add_argument('--dataset-stats', type=str, help='path to stats file')
    parser.add_argument('--loss-list-fpath', type=str,
                        help='path to dump loss list')
    parser.add_argument('--rnn-model', type=str, help='path to RNN model file')
    parser.add_argument('--vae-model', type=str, help='path to VAE model file')
    parser.add_argument('--rnn-hidden-size', type=int,
                        help='hidden state size')
    parser.add_argument('--input-size', type=int, help='size of RNN input')
    parser.add_argument('--device', type=str, help='device for training')
    parser.add_argument('--seed', type=int, default=1,
                        metavar='S', help='random seed (default: 1)')
    parser.add_argument('--batch-size', type=int, default=1,
                        help='batch size for training and testing')
    parser.add_argument('--cutoff', type=int, default=-1,
                        help='cutoff for rnn training (default: -1)')
    parser.add_argument('--error-thres', type=float,
                        help='threshold of reconstruction error')
    parser.add_argument('--n-gram', type=int, default=3,
                        help='n-gram for training/testing the autoencoder (default: 3)')
    parser.add_argument('--debug', action="store_true",
                        help='enables debugging information')
    parser.add_argument('--context-mode', type=str,
                        default='use_gates', help='type of profile')
    parser.add_argument('--partition-mode', type=str,
                        default='none', help='type of partitioning')
    parser.add_argument('--rnn-model-type', type=str,
                        default='gru', help='type of partitioning')
    parser.add_argument('--extra-features', type=str,
                        help='whether to include post-mortem features.')
    parser.add_argument('--conn-dir', type=str,
                        help='direction of connection to play with.')
    parser.add_argument('--use-conn-id', action='store_true', default=True,
                        help='use connection ids to track adv pkts.')
    parser.add_argument('--paint-trend', action='store_true', default=False)
    args = parser.parse_args()

    if args.seed:
        torch.manual_seed(args.seed)
        random.seed(int(args.seed))

    device = torch.device(args.device if args.device else "cpu")

    with open(args.dataset_stats, 'rb') as fin:
        stats_info = pickle.load(fin)

    print("[INFO] Stats used for dataset:")
    print(stats_info)
    stats = stats_info['stats']
    label_map = stats_info['label_map']
    reversed_label_map = {}
    for label, label_id in label_map.items():
        reversed_label_map[label_id] = label

    attack_test_loader, _, _, cnt_map = read_dataset(
        args.attack_dataset, batch_size=args.batch_size, preprocess=True, cutoff=args.cutoff, split_train_test=False, stats=stats, debug=True)
    benign_test_loader, _, _, _ = read_dataset(
        args.benign_dataset, batch_size=args.batch_size, preprocess=True, cutoff=args.cutoff, split_train_test=False, stats=stats, debug=True)

    start_timestamp = time.time()
    print("[INFO] Stating timing: %f" % start_timestamp)

    if args.extra_features == 'all_addi':
        addi_attack_test_loader, _, _, _ = read_dataset(
            args.attack_dataset, batch_size=args.batch_size, preprocess=True, cutoff=args.cutoff, split_train_test=False, stats=stats, debug=True, add_additional_features=True, use_conn_id=args.use_conn_id)
        addi_benign_test_loader, _, _, _ = read_dataset(
            args.benign_dataset, batch_size=args.batch_size, preprocess=True, cutoff=args.cutoff, split_train_test=False, stats=stats, debug=True, add_additional_features=True, use_conn_id=args.use_conn_id)

    input_size = args.input_size
    hidden_size = args.rnn_hidden_size
    batch_size = 1
    if 'bi_' in args.rnn_model_type:
        rnn_bidirectional = True
    else:
        rnn_bidirectional = False

    rnn_model = torch.load(args.rnn_model)
    rnn_model.eval()  # Setting to eval model since this is testing phase...

    if args.conn_dir == 'only_outbound':
        only_outbound = True
    else:
        only_outbound = False

    if args.extra_features == 'all_addi':
        start_feature_ext_ts = time.time()
        attack_contextual_dataset = generate_contextual_profile_dataset_fused(
            attack_test_loader, device, rnn_model, context_mode=args.context_mode, partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=reversed_label_map, addi_data_loader=addi_attack_test_loader)
        finish_feature_ext_ts = time.time()
        benign_contextual_dataset = generate_contextual_profile_dataset_fused(
            benign_test_loader, device, rnn_model, context_mode=args.context_mode, partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=reversed_label_map, addi_data_loader=addi_benign_test_loader)
        num_addi_features = 15
    else:
        attack_contextual_dataset = generate_contextual_profile_dataset(
            attack_test_loader, device, rnn_model, context_mode=args.context_mode, partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=reversed_label_map)
        benign_contextual_dataset = generate_contextual_profile_dataset(
            benign_test_loader, device, rnn_model, context_mode=args.context_mode, partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=reversed_label_map)
        num_addi_features = 0

    if args.context_mode == "baseline":
        vae_input_size = (input_size + num_addi_features) * args.n_gram
    elif args.context_mode == "use_hn":
        vae_input_size = (input_size + hidden_size) * args.n_gram
    elif args.context_mode == "use_all":
        vae_input_size = (input_size + hidden_size * 5) * args.n_gram
    elif args.context_mode == "only_gates":
        vae_input_size = (hidden_size * 2) * args.n_gram
    elif args.context_mode == "only_hn":
        vae_input_size = hidden_size * args.n_gram
    elif args.context_mode == "use_all_gates":
        vae_input_size = (input_size + hidden_size * 4) * args.n_gram
    elif args.context_mode == "use_gates":
        vae_input_size = (input_size + num_addi_features +
                          hidden_size * 2) * args.n_gram
    elif args.context_mode == "use_gates_label":
        vae_input_size = (input_size + num_addi_features + hidden_size *
                          2 + len(nf_conntrack_states) + 1) * args.n_gram

    if args.partition_mode == 'none':
        vae_model = torch.load(args.vae_model)
    else:
        vae_model = {}
        new_label_map = {}
        for label, label_id in label_map.items():
            model_fpath = "%s.%s" % (
                args.vae_model, str(reversed_label_map[label_id]))
            if path.isfile(model_fpath):
                vae_model[label] = torch.load(model_fpath)
                new_label_map[label_id] = label
            else:
                print("[ERROR] Model file %s not found" % model_fpath)
        label_map = new_label_map

    if args.partition_mode == "none":
        attack_profile_loader = torch.utils.data.DataLoader(
            attack_contextual_dataset, batch_size=batch_size, shuffle=False)
        benign_profile_loader = torch.utils.data.DataLoader(
            benign_contextual_dataset, batch_size=batch_size, shuffle=False)
    else:
        attack_profile_loader, benign_profile_loader = {}, {}
        for label_id, label in label_map.items():
            if label_id in attack_contextual_dataset:
                attack_profile_loader[label] = torch.utils.data.DataLoader(
                    attack_contextual_dataset[label_id], batch_size=batch_size, shuffle=False)
            if label_id in benign_contextual_dataset:
                benign_profile_loader[label] = torch.utils.data.DataLoader(
                    benign_contextual_dataset[label_id], batch_size=batch_size, shuffle=False)

    if args.partition_mode == "none":
        start_loss_ts = time.time()
        attack_cnt, attack_seq_cnt, attack_test_loss, attack_seq_test_loss, attack_loss_list, attack_seq_loss_list, attack_x, attack_y = get_losslist(
            attack_profile_loader, vae_model, vae_input_size, args.n_gram, debug=args.debug, only_outbound=only_outbound, use_conn_id=args.use_conn_id)
        finish_loss_ts = time.time()
        benign_cnt, benign_seq_cnt, benign_test_loss, benign_seq_test_loss, benign_loss_list, benign_seq_loss_list, benign_x, benign_y = get_losslist(
            benign_profile_loader, vae_model, vae_input_size, args.n_gram, debug=args.debug, only_outbound=only_outbound, use_conn_id=args.use_conn_id)
        if args.paint_trend:
            for conn_id in attack_x.keys() & benign_x.keys():
                attk_x, attk_y = attack_x[conn_id], attack_y[conn_id]
                begn_x, begn_y = benign_x[conn_id], benign_y[conn_id]
                plt.plot(attk_x, attk_y, color='red', linewidth=3,
                         label='Adversarial')
                plt.plot(begn_x, begn_y, color='green',
                         linewidth=3, label='Benign')
                plt.ylim((0.0, 0.06))
                plt.xlim((0, 60))
                plt.xlabel("Index # of Context Profile",
                           fontsize=20, fontweight='bold')
                plt.ylabel("Recounstruction Error",
                           fontsize=20, fontweight='bold')
                plt.legend(loc='upper right')
                plt.tight_layout()
                plt.show()
    else:
        attack_cnt, attack_test_loss, attack_loss_list = get_losslist(
            attack_profile_loader, vae_model, vae_input_size, args.n_gram, debug=args.debug, only_outbound=only_outbound)
        benign_cnt, benign_test_loss, benign_loss_list = get_losslist(
            benign_profile_loader, vae_model, vae_input_size, args.n_gram, debug=args.debug, only_outbound=only_outbound)

    end_timestamp = time.time()
    print("[INFO] Ending timing: %f" % end_timestamp)
    duration = end_timestamp - start_timestamp
    feature_ext_duration = finish_feature_ext_ts - start_feature_ext_ts
    loss_duration = finish_loss_ts - start_loss_ts
    pkt_cnt = sum(list(cnt_map.values()))
    conn_cnt = len(attack_test_loader)

    print("[INFO] Total # of connections: %d; # of packets: %d; total elapsed time: %f; time for feature extraction: %f; time for computing loss: %f" % (
        conn_cnt, pkt_cnt, duration, feature_ext_duration, loss_duration))
    print("[INFO] Averge processing time per packet: %f" %
          ((feature_ext_duration + loss_duration) / pkt_cnt))
    print("[INFO] Averge processing time per connection: %f" %
          ((feature_ext_duration + loss_duration) / conn_cnt))

    if args.partition_mode == "none":
        with open(args.loss_list_fpath + '.UNILABEL', 'w') as fin:
            for (loss, idx, conn_id, leng) in attack_loss_list:
                fin.write(
                    '\t'.join([str(loss), str(idx), str(conn_id), str(leng), '1']) + '\n')
            for (loss, idx, _, leng) in benign_loss_list:
                fin.write(
                    '\t'.join([str(loss), str(idx), str(leng), '0']) + '\n')
    else:
        losslist_files = {}
        for _, label in label_map.items():
            losslist_files[label] = open(
                '%s.%s' % (args.loss_list_fpath, label), 'w')

        for label, loss_list in attack_loss_list.items():
            for (loss, idx) in loss_list:
                losslist_files[label].write("%f,%s,%s\n" % (loss, idx, '1'))
        for label, loss_list in benign_loss_list.items():
            for (loss, idx) in loss_list:
                losslist_files[label].write("%f,%s,%s\n" % (loss, idx, '0'))

        for label, f in losslist_files.items():
            f.close()

    if args.partition_mode == "none":
        print("Number of connections: %d | %d" % (attack_cnt, benign_cnt))
        print("Number of sequences: %d | %d" %
              (attack_seq_cnt, benign_seq_cnt))
        print('Per-connection average loss: {:.4f} | {:.4f}'.format(
            attack_test_loss/attack_cnt, benign_test_loss/benign_cnt))
        print('Per-seq average loss: {:.4f} | {:.4f}'.format(
            attack_seq_test_loss/attack_seq_cnt, benign_seq_test_loss/benign_seq_cnt))
    else:
        for label, _ in attack_loss_list.items():
            print("----- Label %s -----" % label)
            print("Number of connections: %d | %d" %
                  (attack_cnt[label], benign_cnt[label]))
            print('Per-connection average loss: {:.4f} | {:.4f}'.format(
                attack_test_loss[label]/attack_cnt[label], benign_test_loss[label]/benign_cnt[label]))
