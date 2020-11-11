#!/bin/bash

echo "Size of RNN hidden state: $1"
echo "Size of AE bottleneck layer: $2"
echo "Length of sequence (n-gram): $3"
echo "RNN training epochs (no mini-batch): $4"
echo "AE training epochs (mini-batch): $5"
echo "Device name (gpu/cpu): $6"
echo "RNN training cutoff: $7"
echo "AE training cutoff: $8"
echo "Size of RNN input: $9"
echo "Train RNN model: $10"
echo "Train AE model: $11"
echo "Launch and test attacks: $12"
echo "Dataset filename: $13"
echo "Context mode: $14"
echo "Partition mode: $15"
echo "Model type: $16"
echo "AE model type: $17"
echo "Loss weighting: $18"
echo "Additional features: $19"
echo "Only outbound packets: $20"

if [ $10 = '--train-rnn' ]
then
	echo "Saved RNN model filename: $13.$1.$4.$7.$16.$18"
	python3 train.py --train-dataset ../data/processed_dataset/$13.csv.train --test-dataset ../data/processed_dataset/$13.csv.test --save-model --save-model-suffix $13.$1.$4.$7.$16.$18 --rnn-num-epochs $4 --rnn-hidden-size $1 --seed 222 --device $6 --cutoff $7 --input-size $9 --rnn-model-type $16 --loss-weighting $18 > ../log/train_rnn.$13.$1.$4.$7.$16.$18.log
fi

if [ $11 = '--train-ae' ]
then
	echo "Saved AE model filename: $13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20"
	python3 train.py --train-dataset ../data/processed_dataset/$13.csv.train --test-dataset ../data/processed_dataset/$13.csv.test --save-model --save-model-suffix $13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20 --train-ae-model --vae-num-epochs $5 --n-gram $3 --ae-bottleneck-size $2 --rnn-model ../model/rnn_model.pt.$13.$1.$4.$7.$16.$18 --rnn-hidden-size $1 --seed 222 --device $6 --cutoff $8 --input-size $9 --context-mode $14 --partition-mode $15 --rnn-model-type $16 --ae-model-type $17 --extra-features $19 --conn-dir $20 > ../log/train_ae.$13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20.log
fi

if [ $12 = '--launch-attack' ]
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
	echo "======= Generating results of $attack_type (one-sized) ======="
	python3 test.py --attack-dataset ../data/processed_dataset/$13.csv.test.$attack_type.attack --benign-dataset ../data/processed_dataset/$13.csv.test.$attack_type.benign --rnn-model ../model/rnn_model.pt.$13.$1.$4.$7.$16.$18 --vae-model ../model/vae_model.pt.$13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20 --loss-list-fpath ../data/losslist/$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20 --n-gram $3 --dataset-stats ../data/processed_dataset/$13.csv.train.stats --seed 222 --rnn-hidden-size $1 --input-size $9 --context-mode $14 --partition-mode $15 --rnn-model-type $16 --extra-features $19 --conn-dir $20 > ../log/test_loss.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.min
	python3 visualize.py --loss-list-fname $13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20 --loss-list-dir ../data/losslist --fig-fpath ../data/figs/roc_wami.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.min --ds-title $attack_type > ../log/roc_score.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20 --attack-info-fpath ../data/processed_dataset/$13.csv.test.$attack_type.attack.info --n-gram $3
done
for attack_type in Liberate_TCP_InvalidDataoff Liberate_TCP_InvalidFlagComb Liberate_IP_LowTTL \
                   Liberate_IP_InvalidVersion Liberate_IP_InvalidHeaderLen Liberate_IP_LongerLength \
                   Liberate_IP_ShorterLength Liberate_TCP_WrongSEQ Liberate_TCP_WrongChksum \
                   Liberate_TCP_ACKNotSet Liberate_IP_LowTTLRSTa Liberate_IP_LowTTLRSTb \
                   Geneva_Strategy_1 Geneva_Strategy_2 Geneva_Strategy_3 Geneva_Strategy_4 \
                   Geneva_Strategy_5 Geneva_Strategy_6 Geneva_Strategy_7 Geneva_Strategy_8 \
                   Geneva_Strategy_9 Geneva_Strategy_10 Geneva_Strategy_11 Geneva_Strategy_12 \
                   Geneva_Strategy_13 Geneva_Strategy_14 Geneva_Strategy_15 Geneva_Strategy_16 \
                   Geneva_Strategy_17 Geneva_Strategy_18 Geneva_Strategy_19 Geneva_Strategy_20 \
                   Geneva_Strategy_21 Geneva_Strategy_23 Geneva_Strategy_24 Geneva_Strategy_25

do
	echo "======= Generating results of $attack_type (minimum) ======="
	python3 test.py --attack-dataset ../data/processed_dataset/$13.csv.test.$attack_type\_min.attack --benign-dataset ../data/processed_dataset/$13.csv.test.$attack_type\_min.benign --rnn-model ../model/rnn_model.pt.$13.$1.$4.$7.$16.$18 --vae-model ../model/vae_model.pt.$13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20 --loss-list-fpath ../data/losslist/$13.$1.$2.$3.$4.$5.$7.$8.$attack_type*min*.$14.$15.$16.$17.$18.$19.$20 --n-gram $3 --dataset-stats ../data/processed_dataset/$13.csv.train.stats --seed 222 --rnn-hidden-size $1 --input-size $9 --context-mode $14 --partition-mode $15 --rnn-model-type $16 --extra-features $19 --conn-dir $20 > ../log/test_loss.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.min
	python3 visualize.py --loss-list-fname $13.$1.$2.$3.$4.$5.$7.$8.$attack_type*min*.$14.$15.$16.$17.$18.$19.$20 --loss-list-dir ../data/losslist --fig-fpath ../data/figs/roc_wami.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.min --ds-title $attack_type > ../log/roc_score.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.min --attack-info-fpath ../data/processed_dataset/$13.csv.test.$attack_type\_min.attack.info --n-gram $3
	echo "======= Generating results of $attack_type (maximum) ======="
	python3 test.py --attack-dataset ../data/processed_dataset/$13.csv.test.$attack_type\_max.attack --benign-dataset ../data/processed_dataset/$13.csv.test.$attack_type\_max.benign --rnn-model ../model/rnn_model.pt.$13.$1.$4.$7.$16.$18 --vae-model ../model/vae_model.pt.$13.$1.$2.$3.$5.$8.$14.$15.$16.$17.$18.$19.$20 --loss-list-fpath ../data/losslist/$13.$1.$2.$3.$4.$5.$7.$8.$attack_type*max*.$14.$15.$16.$17.$18.$19.$20 --n-gram $3 --dataset-stats ../data/processed_dataset/$13.csv.train.stats --seed 222 --rnn-hidden-size $1 --input-size $9 --context-mode $14 --partition-mode $15 --rnn-model-type $16 --extra-features $19 --conn-dir $20 > ../log/test_loss.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.max
	python3 visualize.py --loss-list-fname $13.$1.$2.$3.$4.$5.$7.$8.$attack_type*max*.$14.$15.$16.$17.$18.$19.$20 --loss-list-dir ../data/losslist --fig-fpath ../data/figs/roc_wami.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.max --ds-title $attack_type > ../log/roc_score.$13.$1.$2.$3.$4.$5.$7.$8.$attack_type.$14.$15.$16.$17.$18.$19.$20.max --attack-info-fpath ../data/processed_dataset/$13.csv.test.$attack_type\_max.attack.info --n-gram $3
done
cat ../log/test_loss.$13.$1.$2.$3.$4.$5.$7.$8.*.$14.$15.$16.$17.$18.$19.$20* > ../final_res/merged_test_loss.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log
cat ../log/roc_score.$13.$1.$2.$3.$4.$5.$7.$8.*.$14.$15.$16.$17.$18.$19.$20* > ../final_res/merged_roc_score.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log
rm ../log/test_loss.$13.$1.$2.$3.$4.$5.$7.$8.*.$14.$15.$16.$17.$18.$19.$20*
rm ../log/roc_score.$13.$1.$2.$3.$4.$5.$7.$8.*.$14.$15.$16.$17.$18.$19.$20*

echo "Adding header for producing the final resutls..."
echo "LABEL_OPT,ATTACK_TYPE,AUC_ROC_SCORE,TPR@FPR0.07,TPR@FPR009,EER_SCORE,TOP1_HIT_ACC,TOP3_HIT_ACC,TOP5_HIT_ACC" > ../final_res/header.txt
cat ../final_res/header.txt ../final_res/merged_roc_score.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log > ../final_res/merged_roc_score_w_header.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log
echo "Printing final results:"
cat ../final_res/merged_roc_score_w_header.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log
python3 paint_fig.py --fin-our ../final_res/merged_roc_score_w_header.$13.$1.$2.$3.$4.$5.$7.$8.$14.$15.$16.$17.$18.$19.$20.log --merged-res ../final_res/final_results_fig.csv
fi
