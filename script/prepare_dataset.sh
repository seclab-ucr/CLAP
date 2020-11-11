#!/bin/bash
echo "Dataset filename: $1"
echo "Ratio: $2"
echo "Additional arg: $3"
echo "Arg1 for distilling: $4"
echo "Arg2 for distilling: $5"
echo "Arg3 for distilling: $6"
echo "Arg4 for distilling: $7"
echo "Additional arg for merging: $8"

if [ "$2" != "no_distill" ]
then
	cp ../data/raw_dataset/mawi_ws_ds_sorted.csv.raw ../data/raw_dataset/$1.csv.raw
	python3 preprocess_dataset.py --dataset ../data/raw_dataset/$1.csv.raw --kitsune-dataset ../data/raw_dataset/$1.csv.raw.kitsune --distilled-dataset ../data/processed_dataset/$1.csv --ratio $2 --use-direction $4 $5 $6 $7
fi

if [ "$3" != "no_inject" ]
then
for attack_type in SymTCP_Zeek_SYNWithData SymTCP_Zeek_MultipleSYN SymTCP_Zeek_PureFIN SymTCP_Zeek_BadRSTFIN \
		   SymTCP_Zeek_DataOverlapping SymTCP_Zeek_DataWithoutACK SymTCP_Zeek_DataBadACK SymTCP_Zeek_SEQJump \
		   SymTCP_Zeek_UnderflowSEQ \
		   SymTCP_Snort_MultipleSYN SymTCP_Snort_InWindowFIN SymTCP_Snort_FINACKBadACK SymTCP_Snort_FINACKMD5 \
		   SymTCP_Snort_InWindowRST SymTCP_Snort_RSTBadTimestamp SymTCP_Snort_RSTMD5 SymTCP_Snort_RSTACKBadACKNum \
		   SymTCP_Snort_PartialInWindowRST SymTCP_Snort_UrgentData SymTCP_Snort_TimeGap \
		   SymTCP_GFW_BadRST SymTCP_GFW_BadData SymTCP_GFW_DataWithoutACK SymTCP_GFW_UnderflowSEQ \
		   SymTCP_GFW_SmallSegments SymTCP_GFW_FINWithData SymTCP_GFW_BadFINACKData SymTCP_GFW_FINACKDataBadACK \
		   SymTCP_GFW_OutOfWindowSYNData SymTCP_GFW_RetransmittedSYNData SymTCP_GFW_RSTBadTimestamp SymTCP_GFW_RSTACKBadACKNum
do
	echo "====== Generating perturbed samples for $attack_type... {one-sized}"
	python3 inject_attack.py --dataset ../data/processed_dataset/$1.csv.test --attack-type $attack_type --benign-dataset ../data/processed_dataset/$1.csv.test.$attack_type.benign --use-direction --attack-dataset ../data/processed_dataset/$1.csv.test.$attack_type.attack
done

for attack_type in Liberate_TCP_InvalidDataoff Liberate_TCP_InvalidFlagComb Liberate_IP_LowTTL \
		   Liberate_IP_InvalidVersion Liberate_IP_InvalidHeaderLen Liberate_IP_LongerLength \
		   Liberate_IP_ShorterLength Liberate_TCP_WrongSEQ Liberate_TCP_WrongChksum \
		   Liberate_TCP_ACKNotSet Liberate_IP_LowTTLRSTa Liberate_IP_LowTTLRSTb\
		   Geneva_Strategy_1 Geneva_Strategy_2 Geneva_Strategy_3 Geneva_Strategy_4 \
		   Geneva_Strategy_5 Geneva_Strategy_6 Geneva_Strategy_7 Geneva_Strategy_8 \
		   Geneva_Strategy_9 Geneva_Strategy_10 Geneva_Strategy_11 Geneva_Strategy_12 \
		   Geneva_Strategy_13 Geneva_Strategy_14 Geneva_Strategy_15 Geneva_Strategy_16 \
		   Geneva_Strategy_17 Geneva_Strategy_18 Geneva_Strategy_19 Geneva_Strategy_20 \
		   Geneva_Strategy_21 Geneva_Strategy_23 Geneva_Strategy_24 Geneva_Strategy_25
do
	echo "====== Generating perturbed samples for $attack_type... {min}"
	python3 inject_attack.py --dataset ../data/processed_dataset/$1.csv.test --attack-type $attack_type --benign-dataset ../data/processed_dataset/$1.csv.test.$attack_type\_min.benign --use-direction --attack-dataset ../data/processed_dataset/$1.csv.test.$attack_type\_min.attack
	echo "====== Generating perturbed samples for $attack_type... {max}"
	python3 inject_attack.py --dataset ../data/processed_dataset/$1.csv.test --attack-type $attack_type --benign-dataset ../data/processed_dataset/$1.csv.test.$attack_type\_max.benign --use-direction --attack-dataset ../data/processed_dataset/$1.csv.test.$attack_type\_max.attack --multipkt
done
fi

if [ "$8" = "merge_kitsune" ]
then
	tail -n +2 ../data/processed_dataset/mawi_ws_ds_sorted.csv.train.kitsune.tsv ../data/processed_dataset/$1.csv.test.*.kitsune > ../data/processed_dataset/$1.kitsune.merged
	python3 prepare_kitsune_ds.py --dataset ../data/processed_dataset/$1.kitsune.merged --out-dataset ../data/processed_dataset/$1.kitsune.merged.processed.tsv
	echo "Dumping merged Kitsune dataset to ../data/processed_dataset/$1.kitsune.merged.processed.tsv"
fi
