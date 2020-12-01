#!/usr/bin/env bash

save() {
    # Args:
    # $1 : Denotes the number of the chosen hci device.
    # $2, $3 ... : Array elements of alternating hci device name and corresponding bluetooth address.
    choice=$1
    shift
    ref=("$@")

    for ((i=0; i<${#ref[*]}; i++));
    do
        if [ ${ref[i]} = "hci$choice" ]
        then
            baddr=${ref[(($i + 1))]}
            break
        fi
    done

    echo "server_uuid=94f39d29-7d6d-437d-973b-fba39e49d4ee" > settings.cfg
    echo "baddr=$baddr" >> settings.cfg
    echo "device=hci$choice" >> settings.cfg

    echo "monitoring=0" >> settings.cfg
    echo "monitoring_ip=127.0.0.1" >> settings.cfg
    echo "monitoring_port=7000" >> settings.cfg
}

config_file_1="/etc/systemd/system/dbus-org.bluez.service"
config_file_2="/etc/systemd/system/bluetooth.target.wants/bluetooth.service"
echo -e "Applying bluetooth fix...\n"
sudo sed -i 's/ExecStart=\/usr\/lib\/bluetooth\/bluetoothd.*/ExecStart=\/usr\/lib\/bluetooth\/bluetoothd -C/g' $config_file_1
sudo sed -i 's/ExecStart=\/usr\/lib\/bluetooth\/bluetoothd.*/ExecStart=\/usr\/lib\/bluetooth\/bluetoothd -C/g' $config_file_2
sudo systemctl daemon-reload
sudo service bluetooth restart
sudo sdptool add SP

echo -e "\nInstalling virtualenv\n"
sudo apt-get install virtualenv

echo -e "\nInstalling libbluetooth-dev\n"
sudo apt-get install bluetooth libbluetooth-dev

echo -e "\nSetting up virtual-env\n"
virtualenv --python=python3 venv

echo -e "\nChoosing bluetooth device\n"
hciconfig
targets=($(hciconfig | grep -E -o "hci([0-9])+|([0-9A-F]{2}[:-]){5}([0-9A-F]{2})"))
amount_devices=$((${#targets[@]} / 2))

if [[ $amount_devices = "1" ]]
then
        echo "Using the only device available."
        save 0 ${targets[@]}
        exit
fi

echo "You have $amount_devices hci devices, which one do you want to use?"
echo "Choose x for hci[x] where x in range 0 up to and including $(($amount_devices - 1))"
choice=""
read choice
while [[ ! $choice =~ ^[0-$(($amount_devices-1))]$ ]]; do
    echo "Input not in range 0 up to and including $(($amount_devices - 1)). Please try again."
    read number
done
save $choice ${targets[@]}
