#!/usr/bin/bash

# called by dracut
check() {
    return 0
}
install() {
        . $moddir/install-base
        #. $moddir/install-gui

        if [ -d /usr/lib64/python3.13/ ]; then
            . $moddir/install-python313
        elif [ -d /usr/lib64/python3.9/ ]; then
            . $moddir/install-python39

        fi
}

installkernel() {
        . $moddir/installkernel
}

