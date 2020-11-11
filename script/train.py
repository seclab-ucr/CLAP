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
from collections import Counter

from utils import GRUModel, LSTMModel, rnn_loss_function, AEModel, ae_loss_function
from utils import read_dataset, generate_ngram_seq, generate_contextual_profile_dataset, \
    generate_contextual_profile_dataset_fused, generate_ngram_seq_dataset, calculate_acc, print_per_label_accu
from preprocess_dataset import nf_conntrack_states

ERR_TOO_SHORT_SEQ = -1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='GRU for learning benign contextual profiles')
    parser.add_argument('--train-dataset', type=str,
                        help='path to dataset file')
    parser.add_argument('--loss-list-fpath', type=str,
                        help='path to dump loss list')
    parser.add_argument('--device', type=str, help='device for training')
    parser.add_argument('--seed', type=int, default=1,
                        metavar='S', help='random seed (default: 1)')
    parser.add_argument('--rnn-num-epochs', type=int, default=5,
                        help='number of epochs for RNN training (default: 5)')
    parser.add_argument('--vae-num-epochs', type=int, default=5,
                        help='number of epochs for vae training (default: 5)')
    parser.add_argument('--cutoff', type=int, default=-1,
                        help='cutoff for rnn training (default: -1)')
    parser.add_argument('--ae-batch-size', type=int, default=128,
                        help='AE batch size for AE training (default: 128)')
    parser.add_argument('--input-size', type=int,
                        help='Raw input size (no default)')
    # NOTE: Not sure how to make the batch size for training RNN larger than 1
    parser.add_argument('--rnn-batch-size', type=int, default=1,
                        help='batch size for RNN training (default: 1)')
    parser.add_argument('--rnn-hidden-size', type=int, default=5,
                        help='hidden state size for RNN (default: 5)')
    parser.add_argument('--ae-bottleneck-size', type=int, default=5,
                        help='bottleneck size for AE (default: 5)')
    parser.add_argument('--n-gram', type=int, default=3,
                        help='n-gram for training/testing the autoencoder (default: 3)')
    parser.add_argument('--train-seq-cutoff', type=int, default=-1,
                        help='seq cutoff for training phase (default: -1)')
    parser.add_argument('--rnn-train-checkpoint', type=int, default=100000,
                        help='how many samples to perform a testing (default: 5000)')
    parser.add_argument('--ae-train-checkpoint', type=int, default=10000,
                        help='how many samples to perform a testing (default: 5000)')
    parser.add_argument('--error-thres', type=float,
                        help='reconstruction error for autoencoder')
    parser.add_argument('--debug', action="store_true",
                        help='enables debugging information')
    parser.add_argument('--train-ae-model', action="store_true",
                        help='whether to train AE model')
    parser.add_argument('--save-model', action="store_true",
                        help='persists the models for future use')
    parser.add_argument('--loss-weighting', type=str, default="none",
                        help='weights the loss w.r.t. different labels')
    parser.add_argument('--context-mode', type=str, default="use_gates",
                        help='type of contextual profile to use')
    parser.add_argument('--ae-model-type', type=str,
                        default="mid", help='type of AE model to use')
    parser.add_argument('--partition-mode', type=str,
                        default="none", help='type of partitioning to use')
    parser.add_argument('--rnn-model', type=str, help='loads AE model')
    parser.add_argument('--save-model-suffix', type=str,
                        help='for marking saved models')
    parser.add_argument('--test-dataset', type=str,
                        help='path to dataset file')
    parser.add_argument('--rnn-num-layers', type=int, default=1,
                        help='number of GRU stacked layers (default=3)')
    parser.add_argument('--rnn-model-type', type=str,
                        default="gru", help='which RNN model to use.')
    parser.add_argument('--extra-features', type=str,
                        help='whwther to include post-mortem features.')
    parser.add_argument('--conn-dir', type=str,
                        help='which direction to build contextual profile.')
    args = parser.parse_args()

    print("[INFO][Train] All arguments:")
    print(str(args))

    torch.manual_seed(args.seed)

    device = torch.device(args.device if args.device else "cpu")

    if args.loss_weighting == 'weighted':
        use_loss_weights = True
    else:
        use_loss_weights = False

    train_loader, train_state_map, stats, label_count = read_dataset(
        args.train_dataset, batch_size=args.rnn_batch_size, preprocess=True, cutoff=args.cutoff, seq_cutoff=args.train_seq_cutoff, split_train_test=False)
    if args.test_dataset:
        test_loader, test_state_map, _, test_label_count = read_dataset(
            args.test_dataset, batch_size=1, preprocess=True, cutoff=args.cutoff, seq_cutoff=args.train_seq_cutoff, split_train_test=False, stats=stats)

    if len(train_state_map) < len(test_state_map):
        print("[ERROR] Different numbers of classes:")
        print(str(train_state_map))
        print(str(label_count))
        print(str(test_state_map))
        print(str(test_label_count))
        exit()

    loss_weights = [0.0] * (int(max(list(label_count.keys()))) + 1)
    for label_id, count in label_count.items():
        loss_weights[int(label_id)] = 1.0 / count
    stats_dump = {"label_map": train_state_map,
                  "stats": stats, "loss_weights": loss_weights}
    loss_weights = torch.FloatTensor(loss_weights).to(device)
    reversed_train_state_map = {}
    for label, label_id in train_state_map.items():
        reversed_train_state_map[label_id] = label
    train_state_map = reversed_train_state_map
    print("[INFO] Stats used for the dataset")
    print(stats_dump)
    with open(args.train_dataset + '.stats', 'wb') as fout:
        pickle.dump(stats_dump, fout)

    input_size = args.input_size
    hidden_size = args.rnn_hidden_size
    num_class = len(train_state_map)
    output_size = num_class
    batch_size = 1
    num_layers = args.rnn_num_layers
    if 'bi_' in args.rnn_model_type:
        rnn_bidirectional = True
    else:
        rnn_bidirectional = False

    if not args.rnn_model:
        if args.rnn_model_type == 'test_lstm':
            rnn_model = BiLSTMTestModel(
                input_size, hidden_size, num_layers, num_class, device).to(device)
        elif 'gru' in args.rnn_model_type:
            rnn_model = GRUModel(input_size, hidden_size, output_size,
                                 num_layers, device, rnn_bidirectional).to(device)
        elif 'lstm' in args.rnn_model_type:
            rnn_model = LSTMModel(input_size, hidden_size, output_size,
                                  num_layers, device, rnn_bidirectional).to(device)
        rnn_learning_rate = 1e-4
        rnn_optimizer = torch.optim.Adam(
            rnn_model.parameters(), lr=rnn_learning_rate)

        for epoch in range(args.rnn_num_epochs):
            print("[INFO][Train] ============ Epoch: %d ============" % epoch)
            train_average_loss = 0.0
            for batch_idx, [x, labels] in enumerate(train_loader):
                x = x.to(device, dtype=torch.float)
                labels = labels.to(
                    device, dtype=torch.long).view(labels.size(1))

                rnn_optimizer.zero_grad()

                if args.rnn_model_type == 'test_lstm':
                    outputs = rnn_model(x)
                elif 'gru' in args.rnn_model_type:
                    outputs, _, _ = rnn_model(x)
                elif 'lstm' in args.rnn_model_type:
                    outputs, _, _ = rnn_model(x)
                outputs = outputs.view(x.size(1), num_class)
                if use_loss_weights:
                    loss = rnn_loss_function(
                        outputs, labels, weight=loss_weights)
                else:
                    loss = rnn_loss_function(outputs, labels)
                train_average_loss += loss.item()

                loss.backward()
                rnn_optimizer.step()

                if (batch_idx > 0 and batch_idx % args.rnn_train_checkpoint == 0) or batch_idx == len(train_loader) - 1:
                    print("[INFO][Train] Sample idx: %d; Training loss: %f" %
                          (batch_idx, train_average_loss / (batch_idx + 1)))

                    if not args.test_dataset:
                        continue

                    rnn_model.eval()  # Setting model to eval model to disable Dropout layers
                    correct, total = 0, 0
                    test_average_loss = 0.0
                    correct_labels, incorrect_labels = [], []
                    for test_idx, [test_x, test_labels] in enumerate(test_loader):
                        test_x = test_x.to(device, dtype=torch.float)
                        test_labels = test_labels.to(
                            device, dtype=torch.long).view(test_labels.size(1))
                        test_x_size = test_labels.size(0)

                        if args.rnn_model_type == 'test_lstm':
                            test_outputs = rnn_model(test_x)
                        elif 'gru' in args.rnn_model_type:
                            test_outputs, _, _ = rnn_model(test_x)
                        elif 'lstm' in args.rnn_model_type:
                            test_outputs, _, _ = rnn_model(test_x)
                        test_outputs = test_outputs.view(
                            test_x.size(1), num_class)
                        if use_loss_weights:
                            test_loss = rnn_loss_function(
                                test_outputs, test_labels, weight=loss_weights)
                        else:
                            test_loss = rnn_loss_function(
                                test_outputs, test_labels)
                        test_average_loss += test_loss.item()

                        curr_correct, curr_total, corr_labels, incorr_labels = calculate_acc(
                            test_outputs, test_labels)
                        correct_labels.extend(corr_labels.tolist())
                        incorrect_labels.extend(incorr_labels.tolist())
                        total += curr_total
                        correct += curr_correct

                    _ = print_per_label_accu(Counter(correct_labels), Counter(
                        incorrect_labels), test_state_map)
                    test_average_loss /= len(test_loader)
                    accuracy = float(correct) / total

                    print('[INFO][Test] Testing loss: {}. Overall testing accuracy: {}'.format(
                        test_average_loss, accuracy))
                    rnn_model.train()  # Now returning to train model
    else:
        rnn_model = torch.load(args.rnn_model).to(device)

    if args.save_model and not args.rnn_model:
        if args.save_model_suffix:
            torch.save(rnn_model, "../model/rnn_model.pt.%s" %
                       args.save_model_suffix)
        else:
            torch.save(rnn_model, "../model/rnn_model.pt.%s" %
                       str(int(time.time())))

    if not args.train_ae_model:
        exit()

    # Reload the training set if we need to include additional features
    if args.conn_dir == 'only_outbound':
        only_outbound = True
    else:
        only_outbound = False
    rnn_model.eval()  # switching to eval mode
    if args.extra_features == 'all_addi':
        addi_train_loader, _, _, _ = read_dataset(args.train_dataset, batch_size=args.rnn_batch_size, preprocess=True,
                                                  cutoff=args.cutoff, seq_cutoff=args.train_seq_cutoff, split_train_test=False, add_additional_features=True)
        contextual_dataset = generate_contextual_profile_dataset_fused(train_loader, device, rnn_model, context_mode=args.context_mode,
                                                                       partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=train_state_map, addi_data_loader=addi_train_loader)
        num_addi_features = 15
    else:
        # Now is the time to save final contextual profile
        contextual_dataset = generate_contextual_profile_dataset(
            train_loader, device, rnn_model, context_mode=args.context_mode, partition_mode=args.partition_mode, rnn_model_type=args.rnn_model_type, label_map=train_state_map)
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
    print("[INFO][Train] AE input size: %d" % vae_input_size)

    vae_learning_rate = 1e-3
    if args.partition_mode == 'none':
        vae_model = AEModel(
            vae_input_size, args.ae_bottleneck_size, args.ae_model_type).to(device)
        vae_optimizer = optim.Adam(
            vae_model.parameters(), lr=vae_learning_rate)
    else:
        vae_models = {}
        vae_optimizers = {}
        for label in list(contextual_dataset.keys()):
            vae_models[label] = AEModel(
                vae_input_size, args.ae_bottleneck_size, args.ae_model_type).to(device)
            vae_optimizers[label] = optim.Adam(
                vae_models[label].parameters(), lr=vae_learning_rate)

    if args.partition_mode == 'none':
        profile_loader = torch.utils.data.DataLoader(
            contextual_dataset, batch_size=args.rnn_batch_size, shuffle=True)
        seq_profile_loader = generate_ngram_seq_dataset(
            profile_loader, args.n_gram, batch_size=args.ae_batch_size, debug=False, only_outbound=only_outbound)
    else:
        profile_loaders = {}
        for label, dataset in contextual_dataset.items():
            profile_loaders[label] = torch.utils.data.DataLoader(
                contextual_dataset[label], batch_size=args.ae_batch_size, shuffle=True)

    for epoch in range(args.vae_num_epochs):
        if args.partition_mode == "none":  # Partitioning is off
            train_loss = 0.0
            seq_cnt = 0
            for batch_idx, ngram in enumerate(seq_profile_loader):
                ngram = ngram.view(-1, vae_input_size)
                vae_optimizer.zero_grad()
                recon_ngram = vae_model(ngram)
                loss = ae_loss_function(ngram, recon_ngram)
                loss.backward()
                train_loss += loss.item()
                vae_optimizer.step()
                if (batch_idx != 0 and batch_idx % args.ae_train_checkpoint == 0) or batch_idx == len(seq_profile_loader) - 1:
                    print("[INFO][Train] Training checkpoint: batch #%d" %
                          batch_idx)
                    print('[INFO] ====> Epoch: {}; Average loss: {:.4f}'.format(
                        epoch, train_loss/(batch_idx+1)))
        else:  # Partitioning is on
            train_loss = {}
            for label, label_profile_loader in profile_loaders.items():
                train_loss[label] = 0.0
                for batch_idx, profile in enumerate(label_profile_loader):
                    profile = profile.view(-1, vae_input_size)
                    vae_optimizers[label].zero_grad()
                    recon_profile = vae_models[label](profile)
                    loss = ae_loss_function(profile, recon_profile)
                    loss.backward()
                    train_loss[label] += loss.item()
                    vae_optimizers[label].step()
                    if (batch_idx != 0 and batch_idx % args.ae_train_checkpoint == 0) or batch_idx == len(profile_loaders[label]) - 1:
                        print(
                            "[INFO][Train] Training checkpoint: batch #%d" % batch_idx)
                        print('[INFO] ====> [Label: %s] Epoch: %d; Average loss: %f' % (
                            reversed_train_state_map[label], epoch, train_loss[label]/(batch_idx+1)))

    if args.save_model:
        if args.partition_mode == 'none':
            if args.save_model_suffix:
                torch.save(vae_model, "../model/vae_model.pt.%s" %
                           args.save_model_suffix)
            else:
                torch.save(vae_model, "../model/vae_model.pt.%s" %
                           str(int(time.time())))
        else:
            for label, vae_model in vae_models.items():
                if args.save_model_suffix:
                    torch.save(vae_model, "../model/vae_model.pt.%s.%s" %
                               (args.save_model_suffix, str(reversed_train_state_map[label])))
                else:
                    torch.save(vae_model, "../model/vae_model.pt.%s.%s" %
                               (str(int(time.time())), str(reversed_train_state_map[label])))
