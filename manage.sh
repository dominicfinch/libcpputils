#!/bin/bash

# Global variables
script_dir=$(dirname "$0")


# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out certs/cert.pem \
#    -sha512 -days 3650 -nodes -subj "/C=XX/ST=Cambs/L=Cambridge/O=IAR/OU=SecureThingz/CN=IAR"

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
elif [ "$1" == "clean-qt" ]; then
    echo " - Cleaning QT generated directories..."
    clean_qobject_meta_cpp $script_dir/code/apps/sec-chat/client-ui/src
elif [ "$1" == "help" ]; then
    usage
else
    if [ -z "$1" ]; then
        usage
    else
        echo "Unrecognised argument: $1"
    fi;
fi;