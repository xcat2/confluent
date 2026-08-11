#!/bin/bash

# Resealing to allow more practical use of, for example, PCR1, which frequently gets changed booting from install environment
# to local disk

get_requested_pcrs() {
    local encryptboot=$(grep ^encryptboot: /etc/confluent/confluent.deploycfg | awk '{print $2}')
    IFS=':' read -ra params <<< "$encryptboot"
    for param in  "${params[@]}"; do
        if [[ "$param" =~ ^pcrs= ]]; then
            echo "${param#pcrs=}"
            return 0
        fi
    done
}

wipe_slots() {
    local device="$1"
    
    if [[ -z "$device" ]]; then
        echo "Error: No device specified" >&2
        return 1
    fi
    
    # Check if device exists
    if [[ ! -e "$device" ]]; then
        echo "Error: Device $device not found" >&2
        return 1
    fi
    
    # Wipe existing TPM2 slots using clevis
    echo "Wiping TPM2 slots for $device"
    if [ -e /bin/systemd-cryptenroll ]; then
        systemd-cryptenroll --wipe-slot=tpm2 "$device"
    else
        clevis luks unbind -d "$device" tpm2 || true
    fi
    return 0
}

seal_tpm() {
    local device="$1"
    if [[ -z "$device" ]]; then
        echo "Error: No device specified" >&2
        return 1
    fi

    if [[ ! -e "$device" ]]; then
        echo "Error: Device $device not found" >&2
        return 1
    fi
    local pcrs=$(get_requested_pcrs)
    if [ -e /bin/systemd-cryptenroll ]; then
        PASSWORD=$(cat /etc/confluent/luks.key) systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="$pcrs" "$device"
    else
        if [ -n "$pcrs" ]; then
            clevispcrs=$(echo "$pcrs" | sed -e 's/,/, /g')
            clevis luks bind -f -d "$device" -k - tpm2 "{\"pcr_ids\":\"$clevispcrs\"}" < /etc/confluent/luks.key
        else
            clevis luks bind -f -d "$device" -k - tpm2 "{}" < /etc/confluent/luks.key
        fi
    fi
    
    if [[ $? -eq 0 ]]; then
        echo "Successfully enrolled TPM2 for $device"
        return 0
    else
        echo "Failed to enroll TPM2 for $device" >&2
        return 1
    fi
}

reseal_luks() {
    local device="$1"
    
    if [[ -z "$device" ]]; then
        echo "Error: No device specified" >&2
        return 1
    fi
    
    # Check if device exists
    if [[ ! -e "$device" ]]; then
        echo "Error: Device $device not found" >&2
        return 1
    fi
    
    # Wipe existing TPM2 slots
    echo "Wiping TPM2 slots for $device"
    wipe_slots "$device"
    
    # Enroll TPM2 key
    
    seal_tpm "$device"
    
}

while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$line" ]] && continue
    
   
    device=$(echo "$line" | awk '{print $2}')
    
    # If it's a UUID, convert to device name
    if [[ "$device" =~ ^UUID= ]]; then
        device=$(blkid -U "${device#UUID=}")
    fi

    if [ -e /bin/systemd-cryptenroll ]; then
        systemd-cryptenroll "$device" | grep -q "tpm2" || continue
    else
        clevis luks list -d "$device" | grep -q "tpm2" || continue
    fi
        
    # Process the device
    if [[ -n "$device" ]]; then
        reseal_luks "$device"
    else
        echo "Warning: Could not determine device for line: $line" >&2
    fi
done < /etc/crypttab


