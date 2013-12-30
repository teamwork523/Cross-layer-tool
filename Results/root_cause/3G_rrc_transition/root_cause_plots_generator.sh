#!/bin/bash

app_names=$@

# TODO: add RSCP and ECIO later
feature_array=("tcp_rtt" "transmission_delay" "normalized_transmission_delay" "ota_rtt" "rlc_retx_ratio" "rlc_retx_count")
feature_total=${#feature_array[*]}
feature_detail_array=('TCP RTT (s)' 'RLC Transmission Delay (ms)' 'Normalized Transmission Delay\n(ms)' 'RLC OTA RTT (ms)' \
                      'RLC Retransmission Ratio' 'RLC Retransmission Count')
direction_array=("uplink" "downlink")

for app_name in $app_names; do
    folder_path="raw/$app_name"
    input_filename="root_cause_rrc_transition_${app_name}"
    for (( i=0; i<=$(( ${feature_total} -1 )); i++ )); do
        echo "Starting ${app_name[@]^} ${feature_array[$i]} ..."
        input_path="${folder_path}/${input_filename}"

        # generate both uplink and downlink data
        for direction in "${direction_array[@]}"; do
            Tools/data/boxErrorBar.py 1 $((i+2)) y < "${input_path}_${direction}" > "${folder_path}/${feature_array[$i]}_${direction}"
        done
        
        # merge the two file
        Tools/common/mergeTwoFile.py "${folder_path}/${feature_array[$i]}_${direction_array[0]}" \
                                     "${folder_path}/${feature_array[$i]}_${direction_array[1]}" \
                                     3 4 5 > "${folder_path}/${app_name}_${feature_array[$i]}"
        
        # plot the graph (plus capitalize the application name)
        ./plotBoxErrorBar.sh "${folder_path}/${app_name}_${feature_array[$i]}" "${app_name[@]^}: ${feature_detail_array[$i]}"

        # convert eps to png
        convert -density 300 "${folder_path}/${app_name}_${feature_array[$i]}.eps" "${folder_path}/${app_name}_${feature_array[$i]}.png"

        # clean up the intermediate files
        for direction in "${direction_array[@]}"; do
            rm -rf "${folder_path}/${feature_array[$i]}_${direction}"
        done
    done
done
