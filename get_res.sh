sessions=(${SESSION_NAMES})
# hash_funcs=("crc" "jhash" "xxHash" "murmur3" "city_hash" "nmhash")
hash_funcs=("crc")
chunk_sizes=(16)
hash_table_sizes=(268435456)
hash_modules=(16777049 16777216)
config_file="autotest/units/001_one_port/dataplane.conf"


for session in "${sessions[@]}"
do
    mkdir -p ${session}_dir
    rm -rf ${session}_dir/*
    mkdir -p ${session}_dir/histograms/
done

replace_value_in_conf() {
    local expr=$1
    local config_file="autotest/units/001_one_port/dataplane.conf"
    echo $expr
    jq "$expr" $config_file > output.json
    mv ./output.json $config_file
}

for session in "${sessions[@]}"
do
    replace_value_in_conf ".sessionName = \"$session\""
    for ht_size in "${hash_table_sizes[@]}"
    do
        replace_value_in_conf ".configValues.balancer_state_ht_size = $ht_size"
        for chunk_size in "${chunk_sizes[@]}"
        do
            replace_value_in_conf ".chunkSize = $chunk_size"
            for module in "${hash_modules[@]}" 
            do
                replace_value_in_conf ".hashModule = $module"
                for hash in "${hash_funcs[@]}"
                do
                    replace_value_in_conf ".hashFuncName = \"$hash\""
                    jq $config_file
                    sudo docker run --rm -it -v /run/yanet:/run/yanet -v ${PWD}:/project yanetplatform/builder ./build_autotest/dataplane/yanet-dataplane -c autotest/units/001_one_port/dataplane.conf
                done
            done
        done
    done
done

python3 ./vizualize.py