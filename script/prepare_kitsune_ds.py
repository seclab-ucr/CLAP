import argparse

def read_merged_kitsune_ds(fpath):
    with open(fpath, 'r') as fin:
        data = fin.readlines()
    
    ds_dict = {}
    curr_tag = 'dummy'
    for i in range(len(data)):
        row = data[i].rstrip('\n')
        if '==>' in row and '<==' in row:
            ds_category = row.split(" ")[1].split('/')[-1]
            if 'train' in ds_category:
                curr_tag = 'TRAIN_SET'
            else:
                curr_tag = '_'.join([ds_category.split('.')[-3], ds_category.split('.')[-2]])
            print("Encountering tag %s" % curr_tag)
            ds_dict[curr_tag] = []
        elif len(row) >= 2:
            ds_dict[curr_tag].append(row + '\n')
        else:
            continue
    return ds_dict

def dump_merged_kitsune_ds(fpath, ds_dict):
    with open(fpath, 'w') as fout1, open(fpath + '.info', 'w') as fout2:
        curr_line_num = 0
        fout1.write('\t'.join(['frame.time_epoch', 'frame.len', 'eth.src', 'eth.dst',
                               'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport',
                               'udp.dstport', 'icmp.type', 'icmp.code', 'arp.opcode',
                               'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac',
                               'arp.dst.proto_ipv4', 'ipv6.src', 'ipv6.dst\n']))
        curr_line_num += 1
        fout2.write("TRAIN_SET,%d,%d\n" % (curr_line_num, len(ds_dict['TRAIN_SET'])))
        fout1.writelines(ds_dict['TRAIN_SET'])
        curr_line_num += len(ds_dict['TRAIN_SET'])
        for tag, ds in ds_dict.items():
            if tag == 'TRAIN_SET':
                continue
            fout2.write("%s,%d,%d\n" % (tag, curr_line_num, curr_line_num+len(ds)))
            fout1.writelines(ds)
            curr_line_num += len(ds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Use this script to inject attacks.')
    parser.add_argument('--dataset', type=str, help='Path to dataset.')
    parser.add_argument('--out-dataset', type=str, help='Path to dataset.')
    args = parser.parse_args()

    k_ds = read_merged_kitsune_ds(args.dataset)
    dump_merged_kitsune_ds(args.out_dataset, k_ds)

