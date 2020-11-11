from utils import *
from os import listdir
import argparse

from scipy.optimize import brentq
from scipy.interpolate import interp1d


def get_localization_acc(adv_pkt_idx_dict, top_loss_idx_dict, ngram=3):
    def ngram_idx_lst(lst, ngram):
        new_lst = []
        for top_loss_idx in lst:
            new_lst.append(top_loss_idx)
            for delta in range(1, ngram):
                new_lst.append(top_loss_idx + delta)
        return new_lst

    hit_dict = {}
    top_1_hit_cnt = 0
    top_3_hit_cnt = 0
    top_5_hit_cnt = 0

    for conn_id, adv_pkt_idx_lst in adv_pkt_idx_dict.items():
        if conn_id not in top_loss_idx_dict:
            continue

        top_loss_idx_lst = top_loss_idx_dict[conn_id]
        if len(top_loss_idx_lst) == 0:
            continue

        adv_pkt_idx_set = set(adv_pkt_idx_lst)

        top_1 = ngram_idx_lst([top_loss_idx_lst[0]], ngram)

        if len(top_loss_idx_lst) >= 5:
            top_5 = ngram_idx_lst(top_loss_idx_lst[:5], ngram)
        else:
            top_5 = ngram_idx_lst(top_loss_idx_lst, ngram)
        if len(top_loss_idx_lst) >= 3:
            top_3 = ngram_idx_lst(top_loss_idx_lst[:3], ngram)
        else:
            top_3 = ngram_idx_lst(top_loss_idx_lst, ngram)

        top_1_set = set(top_1)
        top_3_set = set(top_3)
        top_5_set = set(top_5)

        if len(top_1_set.intersection(adv_pkt_idx_set)) != 0:
            top_1_hit = True
        else:
            top_1_hit = False
        if len(top_3_set.intersection(adv_pkt_idx_set)) != 0:
            top_3_hit = True
        else:
            top_3_hit = False
        if len(top_5_set.intersection(adv_pkt_idx_set)) != 0:
            top_5_hit = True
        else:
            top_5_hit = False

        hit_dict[conn_id] = (top_1_hit, top_3_hit, top_5_hit)

    for conn_id, hits in hit_dict.items():
        if hits[0]:
            top_1_hit_cnt += 1
        if hits[1]:
            top_3_hit_cnt += 1
        if hits[2]:
            top_5_hit_cnt += 1

    top_1_hit_acc = top_1_hit_cnt / len(hit_dict)
    top_3_hit_acc = top_3_hit_cnt / len(hit_dict)
    top_5_hit_acc = top_5_hit_cnt / len(hit_dict)

    return top_1_hit_acc, top_3_hit_acc, top_5_hit_acc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Let us compute the ROC curve.')
    parser.add_argument('--loss-list-fname', type=str,
                        help='1st path to loss list')
    parser.add_argument('--n-gram', type=int)
    parser.add_argument('--attack-info-fpath', type=str,
                        help='to calculate the localization perf')
    parser.add_argument('--loss-list-dir', type=str,
                        help='1st path to loss list')
    parser.add_argument('--fig-fpath', type=str, help='path to save figure')
    parser.add_argument('--ds-title', type=str,
                        default='SymTCP', help='title in curve painting')
    parser.add_argument('--balance', action='store_true',
                        default=False, help='whether to balance by labels')
    args = parser.parse_args()

    all_losslist_files = listdir(args.loss_list_dir)
    losslist_files = {}
    for fname in all_losslist_files:
        if args.loss_list_fname in fname:
            label = fname.split('.')[-1]
            attack_type = fname.split('.')[-9]
            losslist_files[label] = (fname, attack_type)

    adv_pkt_idx_dict = {}
    with open(args.attack_info_fpath, 'r') as fin:
        data = fin.readlines()
    for row in data:
        row = row.rstrip('\n')
        conn_id, adv_pkt_info = row.split('\t')
        adv_pkt_info = eval(adv_pkt_info)
        adv_pkt_idx_dict[conn_id] = adv_pkt_info


    for label, (fname, attack_type) in losslist_files.items():
        lossfile_fname = '/'.join([args.loss_list_dir, fname])
        y, scores, top_loss_lst = read_loss_list(
            lossfile_fname, balance_by_label=args.balance)
        if len(y) == 0:
            print(">>>>>>>>> [Label %s; Attack type %s] Not found  <<<<<<<<<" % (
                label, attack_type))
            continue
        top_1_hit_acc, top_3_hit_acc, top_5_hit_acc = get_localization_acc(
            adv_pkt_idx_dict, top_loss_lst, ngram=args.n_gram)

        y = np.array(y)
        scores = np.array(scores)
        fpr, tpr, thresholds = metrics.roc_curve(y, scores, pos_label=1)
        tpr_lst = {}
        for fpr_th in [0.07, 0.09]:
            for i in range(1, len(fpr)):
                curr_fpr = fpr[i]
                prev_fpr = fpr[i-1]
                if prev_fpr <= fpr_th and fpr_th <= curr_fpr:
                    tpr_lst[fpr_th] = tpr[i-1]
        eer_score = brentq(lambda x: 1. - x - interp1d(fpr, tpr)(x), 0., 1.)
        score = metrics.roc_auc_score(y, scores)
        print(','.join([label, attack_type, str(score), str(
            tpr_lst[0.07]), str(tpr_lst[0.09]), str(eer_score), str(top_1_hit_acc), str(top_3_hit_acc), str(top_5_hit_acc)]))
