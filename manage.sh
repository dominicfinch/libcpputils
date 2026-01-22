#!/bin/bash

# Global variables
script_dir=$(dirname "$0")
declare -a video_fds=("video0" "video4")

# openssl req -x509 -newkey rsa:4096 -keyout key.pem -out certs/cert.pem \
#    -sha512 -days 3650 -nodes -subj "/C=XX/ST=Cambs/L=Cambridge/O=IAR/OU=SecureThingz/CN=IAR"

function usage() {

    declare -A commands=(
        ["clean"]="                Clean certs, generated code & build directories"
        #["build-qt"]="      Build Qt elements"
        #["clean-qt"]="      Clean Qt elements"
        ["start-rtsp-server"]="Starts RTSP server"
        ["broadcast-cameras"]="Broadcast cameras currently available"
        ["display-cameras"]="        Display cameras currently available"
        ["build-grpc"]="        Builds GRPC classes"
        ["clean-grpc"]="        Cleans GRPC classes"
        ["help"]="                Display command usage")

    echo "manage.sh - Script to manage source code repository actions"
    echo "Arguments:"

    for key in "${!commands[@]}"; do
        printf "\t%s\t%s\n" "${key}" "${commands[$key]}"
    done
}

function clean_directory() {
    if [ -d "$1" ]; then
        rm -rf "$1"
    fi;

    if [ -z "$2" ]; then
        mkdir "$1"
    fi;
}

function build_grpc_cpp() {
    if [ ! -d "$2" ]; then
        mkdir "$2"
    fi;

    for file in $1/*.proto; do
        protoc -I $1 --grpc_out=$2 --cpp_out=$2     \
            --experimental_allow_proto3_optional    \
            --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` \
            "$file"
    done
}

# Note to maintainer: This code is handy for dealing with Qt QObject classes
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



# Main command selection
if [ "$1" = "clean" ]; then
    clean_directory $script_dir/build/
    ./manage.sh clean-grpc
elif [ "$1" == "build-grpc" ]; then
    echo " - Building GRPC components..."
    cpp_grpc_generated_dir="$script_dir/code/app/generated"

    if [ ! -d $cpp_grpc_generated_dir ]; then
        mkdir $cpp_grpc_generated_dir
    fi;
    build_grpc_cpp $script_dir/svc-definitions $cpp_grpc_generated_dir

    # TODO: Add support for python bindings

elif [ "$1" == "clean-grpc" ]; then
    echo " - Cleaning GRPC generated directories..."
    cpp_grpc_generated_dir="$script_dir/code/app/generated"
    if [ -d $cpp_grpc_generated_dir ]; then
        rm -rf $cpp_grpc_generated_dir
    fi;
elif [ "$1" == "start-rtsp-server" ]; then
    sudo docker run --rm -it -p 8554:8554 bluenviron/mediamtx
elif [ "$1" == "display-cameras" ]; then
    pids=()
    for fd in "${video_fds[@]}"; do
        gnome-terminal -- ffplay -f v4l2 \
            -input_format yuyv422 \
            -video_size 640x480 \
            -framerate 15 \
            -i "/dev/$fd" 2>&1 &
        pids+=($!)
    done
    echo "Started PIDs: ${pids[@]}"
elif [ "$1" == "broadcast-cameras" ]; then
    rtsp_server_host=localhost
    rtsp_server_port=8554
    pids=()
    for i in "${!video_fds[@]}"; do
        gnome-terminal -- ffmpeg -f v4l2 \
            -input_format yuyv422 \
            -video_size 640x480 \
            -framerate 15 \
            -i "/dev/${video_fds[$i]}" \
            -c:v libx264 \
            -preset veryfast \
            -tune zerolatency \
            -pix_fmt yuv420p \
            -f rtsp \
            -rtsp_transport tcp \
            rtsp://$rtsp_server_host:$rtsp_server_port/cam$i 2>&1 &
    done
    echo "Started PIDs: ${pids[@]}"
#elif [ "$1" == "build-qt" ]; then
#    echo " - Building QT components..."
#    #build_qobject_meta_cpp $script_dir/code/client/include/ui $script_dir/code/client/src/ui
#elif [ "$1" == "clean-qt" ]; then
#    echo " - Cleaning QT generated directories..."
#    #clean_qobject_meta_cpp $script_dir/code/client/src/ui
elif [ "$1" == "help" ]; then
    usage
else
    if [ -z "$1" ]; then
        usage
    else
        echo "Unrecognised argument: $1"
    fi;
fi;