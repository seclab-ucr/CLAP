[ACM Artifact Badges](https://www.acm.org/publications/policies/artifact-review-and-badging-current) awarded: **Available** and **Functional**.

<img src="https://www.acm.org/binaries/content/gallery/acm/publications/artifact-review-v1_1-badges/artifacts_available_v1_1.png" width="150" height="150"> <img src="https://www.acm.org/binaries/content/gallery/acm/publications/artifact-review-v1_1-badges/artifacts_evaluated_functional_v1_1.png" width="150" height="150">

**System requirements**: our artifact was only tested on Ubuntu 18.04 64-bit; we recommand executing our artifact inside a VM sandbox, as it involves installing customized Linux kernel.

**Dependencies**: all necessary dependencies can be installed using the command: `sudo pip3 -r requirements.txt`, and this has been included in our script `replicate_results.sh`, so no action needs to be taken other than following the steps listed below.

**Result validation**: the steps below will eventually paint figures that are similar to Figure 7-12 in the paper. Note the ones generated by this artifact will only include results of CLAP, not the other two baselines. Thus, one can simply verify whether the results generated by this artifact match the results of CLAP shwon in Figure 7-12 in the paper for validation (or figures in `data/visualization` dir).

## Detailed steps to reproduce the main results (detection/localization accuracy metrics for CLAP)
Note that [PATH_TO_PCAP] refers to the path that you would like to specify to contain the downloaded PCAP files,
which needs to be an absolute path without the trailing "/". Also, you need to first enter the `script` folder in Shell/Bash in the artifact repository before executing the following commands.

If you want to load the full-scale MAWI dataset to replicate the main results in the paper:
1. Run `sudo sh setup_kernel_env.sh [PATH_TO_PCAP] full_test` -- this command will restart your OS, and activate the newly installed kernel;
2. Run `sudo sh replicate_results.sh [PATH_TO_PCAP] large_ds` -- this command will train/test the model and paint the figures that exhibit the results shwon in the paper.

If you only want to load the tiny demo PCAP dataset to validate that the artifact works as it claims:
1. Run `sudo sh setup_kernel_env.sh [PATH_TO_PCAP]` -- this command will restart your OS, and activate the newly installed kernel;
2. Run `sudo sh replicate_results.sh [PATH_TO_PCAP]` -- this command will train/test the model and paint the figures that exhibit the results shwon in the paper.

## Detailed explanations about all concrete operations in each step
### 1 Generating Dataset
#### 1.1 Download raw traffic capture
First, we need to download the MAWI raw network traffic capture. One can choose any date at his/her will, and here we pick the one used in the paper  (`http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2020/202004071400.pcap.gz`) for reproduction. We need to unzip the downloaded file and extract the aggregate pcap out of it, named `202004071400.pcap`. 
#### 1.2 Split the aggregate pcap file
Then we need to split the aggregate pcap file into different connections. We recommend the tool called PcapSpliter, a demo executable/application of the popular multi-platform C++ library PcapPlusPlus for capturing, parsing and crafting of network packets. Its version that is compatible with Ubuntu 18.04 is included in our uploaded artifact folder, named PcapSpliter. Assuming we are now again in the working directory /cwd, we can (1) create a folder `/splited_pcaps` and (2) use the command `./PcapSpliter 202004071400.pcap -m connections -out /splited_pcaps` to generate pcap files for each connection in the specified folder.
#### 1.3 Collect the states by replaying pcaps
As mentioned in the paper, CLAP needs internal states from instrumented TCP stack implementation against replayed TCP traffic to form the required dataset. In order to do so, we have instrumented Linux’s Netfilter module for printing out required internal states. Since the instructions live as a patch to the Linux Kernel, we now need to compile a customized kernel with our instrumentation patch and mount it. For convenience, we provide the compiled kernel images in the uploaded artifact folder under directory kernel_iamges. They can be easily mounted by issuing commands `dkpg -i *.deb` under the `kernel_iamges` folder to install all `.deb` files. After restarting the OS and selecting the newly installed kernel, it is loaded with additional instrumentations. Then we need to enable iptables rules that permit Netfilter to inspect replayed network traffic (MAWI capture) and output the internal states with respect to each TCP packet sent and received. We have compiled a Shell script named `per_packet_replay_pcap.py` that sets up the iptables, replays given pcap files and dumps internal states to a log file. 
#### 1.4 Combine dumped states and packet features
Now we need to finally generate the dataset in the format that is consumable by our model. In order to do so, we need to combine/link the internal states dumped from replaying the traffic and the packet features extracted from it. We have prepared the script named `analyze_packet_trace.py` for doing this. 
#### 1.5 Inject selected attacks into traffic
In this step, we (1) split the entire dataset into training and testing sets; and (2) synthesize the 73 DPI evasion attacks and inject them into the testing set of the traffic dataset as the “positive” samples. We compiled the Shell script named `prepare_dataset.sh` for accomplishing this.

### 2 Run experiments
#### 2.1 Train models
With generated datasets, we now invoke Shell script named `run_experiment.sh` that further calls Python script `train.py` for training the RNN and AE models. `run_experiment.sh` would also be in charge of testing the trained models on the testing set, and dump the loss and other results for analysis.
#### 2.2 Test models: See above.

### 3 Analyze results
#### 3.1 Generate final results
With loss and other results generated from the last step, we eventually call Python script `paint_fig.py` for replicating the performance metrics reported in the paper.
