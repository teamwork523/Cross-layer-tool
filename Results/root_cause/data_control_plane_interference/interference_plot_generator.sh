#!/bin/bash

app_names=$@

fileArray=("downlink_mobile" "downlink_none_mobile" \
           "uplink_mobile" "uplink_non_mobile")

for app_name in $app_names;do
    # clear previous eps and png plot
    rm "$app_name/*.eps" 2> /dev/null
    rm "$app_name/*.png" 2> /dev/null
    for file in "${fileArray[@]}"; do
        file_path="$app_name/${app_name}_${file}"
        # PRACH reset
        echo "Start plot $file for PRACH reset vs TCP RTT ..."
        ./plotBoxErrorBar.sh "$file_path" reset "${file_path}_prach_reset" 2
        echo "Start plot $file for PRACH reset vs RLC norm trans delay ..."
        ./plotBoxErrorBar.sh "$file_path" reset "${file_path}_prach_reset" 4
        # PRACH done
        echo "Start plot $file for PRACH done vs TCP RTT ..."
        ./plotBoxErrorBar.sh "$file_path" "done" "${file_path}_prach_done" 2
        echo "Start plot $file for PRACH done vs RLC norm trans delay ..."
        ./plotBoxErrorBar.sh "$file_path" "done" "${file_path}_prach_done" 4
    done
done
