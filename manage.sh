#!/bin/bash

# Global variables
script_dir=$(dirname "$0")

function usage() {

    declare -A commands=(
        ["clean"]="        Clean certs, generated code & build directories"
        ["help"]="        Display command usage")

    echo "manage.sh - Script to manage source code repository actions"
    echo "Arguments:"

    for key in "${!commands[@]}"; do
        printf "\t%s\t%s\n" "${key}" "${commands[$key]}"
    done
}


function build_qobject_meta_cpp() {
    for file in $1/*.h; do
        dirname=$(dirname $file)
        filename=$(basename -- "$file")
        filename="${filename%.*}"
        $(which moc) "$file" -nw -o "$2/$filename.meta.cpp"
    done
}

function clean_qobject_meta_cpp() {
    rm -rf $1/*.meta.cc
}


if [ "$1" = "clean" ]; then
    echo "TODO"
elif [ "$1" == "build-qt" ]; then
    echo " - Building QT components..."
    build_qobject_meta_cpp $script_dir/code/apps/sec-chat/client-ui/include $script_dir/code/apps/sec-chat/client-ui/src
    build_qobject_meta_cpp $script_dir/code/apps/sec-fdisk/include $script_dir/code/apps/sec-fdisk/src
elif [ "$1" == "clean-qt" ]; then
    echo " - Cleaning QT generated directories..."
    clean_qobject_meta_cpp $script_dir/code/apps/sec-chat/client-ui/src
    clean_qobject_meta_cpp $script_dir/code/apps/sec-fdisk/src
elif [ "$1" == "help" ]; then
    usage
else
    if [ -z "$1" ]; then
        usage
    else
        echo "Unrecognised argument: $1"
    fi;
fi;