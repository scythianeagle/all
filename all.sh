#!/bin/bash

display_menu() {
    if [ $EUID -ne 0 ]; then
        _error "This script must be run as root"
    fi
    opsy=$(_os_full)
    arch=$(uname -m)
    lbit=$(getconf LONG_BIT)
    kern=$(uname -r)

    clear
    echo "---------- System Information ----------"
    echo " OS      : $opsy"
    echo " Arch    : $arch ($lbit Bit)"
    echo " Kernel  : $kern"
    echo "----------------------------------------"
    echo "Automatically enable TCP Hybla script"
    echo
    echo "Coded By: https://github.com/MrAminiDev/"
    echo "----------------------------------------"
    echo "Press any key to start...or Press Ctrl+C to cancel"
}


_os_full() {
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

# Function to check the system
check_sys() {
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
}

# Function to check the system version and bit
check_version() {
    if [[ -s /etc/redhat-release ]]; then
        version=$(grep -oE "[0-9.]+" /etc/redhat-release | cut -d . -f 1)
    else
        version=$(grep -oE "[0-9.]+" /etc/issue | cut -d . -f 1)
    fi
    bit=$(uname -m)
    if [[ ${bit} == "x86_64" ]]; then
        bit="x64"
    else
        bit="x32"
    fi
}


sysctl_config() {
		echo -e "#NetOptix optimize network traffic\n#Github: https://github.com/MrAminiDev//\n" > /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control = hybla" >> /etc/sysctl.conf
		echo "net.core.default_qdisc = fq_codel" >> /etc/sysctl.conf
		echo "net.core.optmem_max = 65535" >> /etc/sysctl.conf
		echo "net.ipv4.ip_no_pmtu_disc = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_ecn = 2" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_frto = 2" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_intvl = 30" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_probes = 3" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_keepalive_time = 300" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_low_latency = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_sack = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_timestamps = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_delack_min = 5" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_reordering = 3" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_early_retrans = 3" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_ssthresh = 32768" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_frto_response = 2" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_abort_on_overflow = 1" >> /etc/sysctl.conf
		echo "net.core.rmem_default = 4194304" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_orphans = 3276800" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_autocorking = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_tw_recycle = 1" >> /etc/sysctl.conf
		echo "fs.file-max = 1000000" >> /etc/sysctl.conf
		echo "fs.inotify.max_user_instances = 8192" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
		echo "net.ipv4.ip_local_port_range = 75 65535" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_rmem = 16384 262144 8388608" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_wmem = 32768 524288 16777216" >> /etc/sysctl.conf
		echo "net.core.somaxconn = 8192" >> /etc/sysctl.conf
		echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
		echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
		echo "net.core.wmem_default = 2097152" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_max_syn_backlog = 10240" >> /etc/sysctl.conf
		echo "net.core.netdev_max_backlog = 10240" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_notsent_lowat = 16384" >> /etc/sysctl.conf
		echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_fin_timeout = 25" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_mem = 65536 131072 262144" >> /etc/sysctl.conf
		echo "net.ipv4.tcp_retries2 = 8" >> /etc/sysctl.conf
		echo "net.ipv4.udp_mem = 65536 131072 262144" >> /etc/sysctl.conf
		echo "net.unix.max_dgram_qlen = 50" >> /etc/sysctl.conf
		echo "vm.min_free_kbytes = 65536" >> /etc/sysctl.conf
		echo "vm.swappiness = 10" >> /etc/sysctl.conf
		echo "vm.vfs_cache_pressure = 50" >> /etc/sysctl.conf
		echo "ulimit -SHn 1000000">>/etc/profile
		sudo sysctl -p
		sudo sysctl --system
}


save_config() {
    sudo sysctl -p
    sudo sysctl --system
}
endInstall() {
    clear
    echo "The script was successfully Install Hybla and all settings Updated."
	read -p "Press Enter to continue..."
}

cloner() {
		sed -i '/#NetOptix optimize network traffic/,/#Github: https:\/\/github.com\/MrAminiDev\//d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		sed -i '/net.core.optmem_max/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_no_pmtu_disc/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_frto/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_intvl/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_probes/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_low_latency/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_no_metrics_save/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_window_scaling/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_sack/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_delack_min/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_reordering/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_early_retrans/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_ssthresh/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_frto_response/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_abort_on_overflow/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_autocorking/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
		sed -i '/fs.file-max/d' /etc/sysctl.conf
		sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
		sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
		sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
		sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
		sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_notsent_lowat/d' /etc/sysctl.conf
		sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_mem/d' /etc/sysctl.conf
		sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
		sed -i '/net.ipv4.udp_mem/d' /etc/sysctl.conf
		sed -i '/net.unix.max_dgram_qlen/d' /etc/sysctl.conf
		sed -i '/vm.min_free_kbytes/d' /etc/sysctl.conf
		sed -i '/vm.swappiness/d' /etc/sysctl.conf
		sed -i '/vm.vfs_cache_pressure/d' /etc/sysctl.conf
		sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/' /etc/default/grub
		sudo update-grub
	}

#display_menu
#cloner
#run_drop_caches
#check_sys
#check_version
#sysctl_config
#save_config
#endInstall


install_and_configure_fail2ban() {
    if ! command -v fail2ban-server &> /dev/null; then
        echo "fail2ban not found, installing..."
        sudo apt update && sudo apt install -y fail2ban
    else
        echo "fail2ban is already installed."
    fi

    sudo bash -c 'cat > /etc/fail2ban/jail.local' <<EOL
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 86400
EOL

    sudo systemctl restart fail2ban
    sudo systemctl enable fail2ban
    clear
    echo "fail2ban has been successfully activated"
    sleep 5
}

disable_fail2ban() {
    sudo systemctl stop fail2ban
    sudo systemctl disable fail2ban
    clear
    echo "fail2ban has been successfully Disabled"
    sleep 5
}

clear_ban_list() {
    sudo fail2ban-client unban --all
    clear
    echo "The blocked list has been successfully emptied"
    sleep 5
}

while true; do
    clear
    echo "Please select an option:"
    echo "1 - Enable fail2ban"
    echo "2 - Disable fail2ban"
    echo "3 - Clean ban list"
    echo "4 - Exit"
    read -rp "Enter your choice: " choice

    case $choice in
        1)
            install_and_configure_fail2ban
            break
            ;;
        2)
            disable_fail2ban
            break
            ;;
        3)
            clear_ban_list
            break
            ;;
        4)
            exit 0
            ;;
        *)
            echo "Invalid option, please try again."
            sleep 1
            ;;
    esac
done





disable_ping() {
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    sudo netfilter-persistent save
    echo "Ping requests have been blocked and settings saved."
}

enable_ping() {
    sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP
    sudo netfilter-persistent save
    echo "Ping requests have been unblocked and settings saved."
}

while true; do
    clear
    echo "Please select an option:"
    echo "1) Disable Server Ping"
    echo "2) Enable Server Ping"
    echo "3) Exit"
    echo
    read -p "Enter your choice [1-3]: " choice

    case $choice in
        1)
            disable_ping
            ;;
        2)
            enable_ping
            ;;
        3)
            echo "Exiting script."
            exit 0
            ;;
        *)
            echo "Invalid option! Please enter a number between 1 and 3."
            ;;
    esac

    read -p "Press any key to continue..." -n1 -s
done




check_requirements() {
    local requirements=("ping" "ping6" "ip" "netplan" "net-tools")
    echo "Checking required packages..."

    for req in "${requirements[@]}"; do
        if ! command -v "$req" &> /dev/null; then
            echo "$req is not installed. Installing..."
            sudo apt-get update
            sudo apt-get install -y "$req"
        fi
    done
    echo "All required packages are installed."
}

show_menu() {
    echo "Select IP type:"
    echo "1- IPv4"
    echo "2- IPv6"
    read -p "Enter choice [1-2]: " ip_type

    if [[ $ip_type -ne 1 && $ip_type -ne 2 ]]; then
        echo "Invalid choice. Exiting."
        exit 1
    fi

    read -p "Enter destination IP: " dest_ip

    if [[ -z $dest_ip ]]; then
        echo "No IP entered. Exiting."
        exit 1
    fi

    read -p "Is the default network interface eth0? (In Hezner datacenter, the default is eth0) [Y/N]: " default_iface

    if [[ $default_iface == "Y" || $default_iface == "y" ]]; then
        interface="eth0"
    elif [[ $default_iface == "N" || $default_iface == "n" ]]; then
        read -p "Enter network interface (e.g., eth0): " interface
        if [[ -z $interface ]]; then
            echo "No interface entered. Exiting."
            exit 1
        fi
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi

    while true; do
        read -p "Enter incremental step (1-10): " step_size
        if [[ $step_size -ge 1 && $step_size -le 10 ]]; then
            break
        else
            echo "Invalid step size. Please enter a number between 1 and 10."
        fi
    done
}

save_mtu_setting() {
    local interface=$1
    local mtu=$2

    if [[ -f "/etc/netplan/01-netcfg.yaml" || -f "/etc/netplan/50-cloud-init.yaml" ]]; then
        local netplan_file=$(ls /etc/netplan/*.yaml | head -n 1)
        echo "Updating $netplan_file for permanent MTU setting..."
        sudo sed -i "/^ *ethernets:/,/^ *vlans:/ s/^ *$interface:/&\n      mtu: $mtu/" "$netplan_file"
        sudo netplan apply
    elif [[ -f "/etc/network/interfaces" ]]; then
        echo "Updating /etc/network/interfaces for permanent MTU setting..."
        sudo sed -i "/iface $interface inet/ a \    mtu $mtu" /etc/network/interfaces
        sudo ifdown "$interface" && sudo ifup "$interface"
    else
        echo "Could not detect Netplan or ifupdown. Please update manually."
        exit 1
    fi
}

find_max_mtu() {
    local ip=$1
    local proto=$2
    local interface=$3
    local step_size=$4
    local min_mtu=1000
    local max_mtu=1500
    local last_successful_mtu=$max_mtu

    echo "Starting MTU discovery for $proto on $ip..."

    echo "Setting MTU to $max_mtu on interface $interface..."
    sudo ip link set dev "$interface" mtu $max_mtu

    if [[ $? -ne 0 ]]; then
        echo "Failed to set initial MTU on $interface. Exiting."
        exit 1
    fi

    local current_mtu=$min_mtu

    while [[ $current_mtu -le $max_mtu ]]; do
        echo -n "Testing MTU: $current_mtu... "
        if [[ $proto == "IPv4" ]]; then
            ping -M do -c 1 -s $((current_mtu - 28)) "$ip" -W 1 &> /dev/null
        else
            ping6 -M do -c 1 -s $((current_mtu - 48)) "$ip" -W 1 &> /dev/null
        fi

        if [[ $? -eq 0 ]]; then
            echo "Success"
            last_successful_mtu=$current_mtu
        else
            echo "Failed"
            echo "Re-testing MTU: $current_mtu... "
            if [[ $proto == "IPv4" ]]; then
                ping -M do -c 1 -s $((current_mtu - 28)) "$ip" -W 1 &> /dev/null
            else
                ping6 -M do -c 1 -s $((current_mtu - 48)) "$ip" -W 1 &> /dev/null
            fi

            if [[ $? -ne 0 ]]; then
                break
            else
                last_successful_mtu=$current_mtu
            fi
        fi

        ((current_mtu+=step_size))
        sleep 1
    done

    local final_mtu=$((last_successful_mtu - 2))

    echo "The maximum MTU for $proto on $ip is: $last_successful_mtu"
    echo "Setting MTU to $final_mtu on interface $interface..."
    sudo ip link set dev "$interface" mtu $final_mtu

    if [[ $? -eq 0 ]]; then
        echo "MTU successfully set to $final_mtu on $interface."
        save_mtu_setting "$interface" $final_mtu
    else
        echo "Failed to set MTU on $interface."
    fi
}

main() {
    check_requirements

    show_menu

    if [[ $ip_type -eq 1 ]]; then
        find_max_mtu "$dest_ip" "IPv4" "$interface" "$step_size"
    else
        find_max_mtu "$dest_ip" "IPv6" "$interface" "$step_size"
    fi
}

main





