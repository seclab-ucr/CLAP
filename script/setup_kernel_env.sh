# Run this script using `sudo sh setup_kernel_env.sh [PATH_TO_PCAP]`
# And the new kernel needs a restart to be activated

#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "[ERROR] This script must be run as root!"
   exit
fi

echo "[INFO] This script needs to run before executing `replicate_results.sh`."
echo "It (1) downloads traffic capture, "
echo "   (2) splits the giant pcap into smaller pcap files for different connections"
echo "   (3) install instrumented kernel and reboot the OS for activating the new kernel"
echo "Please choose the kernel named `Linux 5.6.3-customnetfilter` in the `Advanced options for Ubuntu` start menu"
echo "to enter the newly installed kernel."

echo "[INFO] Step0A: Download and split raw traffic captures"
mkdir $1
if [ $2 == "full_test" ]; then
    wget --directory-prefix $1/ http://mawi.nezu.wide.ad.jp/mawi/samplepoint-F/2020/202004071400.pcap.gz
    gzip -d $1/202004071400.pcap.gz
    ../bin/PcapSplitter -f $1/202004071400.pcap -m connection -o $1
    rm $1/202004071400.pcap.gz $1/202004071400.pcap
else
    wget --directory-prefix $1/ https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap
    ../bin/PcapSplitter -f $1/smallFlows.pcap -m connection -o $1
    rm $1/smallFlows.pcap
fi

echo "[INFO] Step0B: Install instrumented kernel"
sudo dpkg -i ../bin/*.deb
sudo reboot
