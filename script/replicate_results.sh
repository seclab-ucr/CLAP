# Note that this Shell script must be run with the the additional kernel instrumentatations,
# which should be done by executing `sudo sh setup_kernel_env.sh [PATH_TO_PCAP]`
# This script itself should be run using command `sudo sh replicate_results.sh [PATH_TO_PCAP]`

#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "[ERROR] This script must be run as root!"
   exit
fi

echo "[INFO] Step00: Install requirements (Linux and Python3)"
sudo apt install python3-pip
sudo pip3 install -r ../requirements.txt

echo "[INFO] Step1: Replay the specified pcap files"
echo "[INFO] (Note this step needs to happen after the instrumented kernel is installed [Step0B])"
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo python3 per_packet_replay_pcap.py --pcap-dir $1 --output ../data/replay_res/mawi_substate_ws_fixed.csv --interface lo
sudo iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[INFO] Step2: Combine dumped states and packet features to form the dataset"
if [ $2 == "large_ds" ]; then
    python3 analyze_packet_trace.py --pcap-dir $1 --dataset-fpath ../data/raw_dataset/mawi_ws_ds_sorted.csv.raw --kitsune-dataset-fpath ../data/raw_dataset/mawi_ws_ds_sorted.csv.raw.kitsune --dataset-type wami --sk-mapping-path ../data/replay_res/mawi_substate_ws_fixed.csv
else
    python3 analyze_packet_trace.py --pcap-dir $1 --dataset-fpath ../data/raw_dataset/mawi_ws_ds_sorted.csv.raw --kitsune-dataset-fpath ../data/raw_dataset/mawi_ws_ds_sorted.csv.raw.kitsune --dataset-type wami --sk-mapping-path ../data/replay_res/mawi_substate_ws_fixed.csv $2 --use-small-dataset
fi

echo "[INFO] Step3: Preprocess formed dataset to produce dataset that is consumable by the model"
sh prepare_dataset.sh mawi_ws_ds_sorted 6 none --incremental-seq-ack-strict --coarse-grained-label-overall --filter-capture-loss --dummy merge_kitsune

echo "[INFO] Step4: Run experiments and dump results"
sh run_experiment.sh 37 40 3 50 1000 cpu -1 -1 37 --train-rnn --train-ae --launch-attack mawi_ws_ds_sorted use_gates none gru large weighted all_addi only_outbound
