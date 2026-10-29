function _confluent_arg_count
    math (count (commandline -opc)) + 1
end

function _confluent_prior_args
    commandline -opc
end

function _confluent_nodegroups
    confetty show /nodegroups | string replace -r '/$' ''
end

function _confluent_range_prefix
    set -l token (commandline -ct)
    if not string match -q '*@*' -- $token; and not string match -q '*,*' -- $token
        return
    end
    set token (string replace -r ',[^,@-]*$' ',' -- $token)
    set token (string replace -r ',-[^,@]*$' ',-' -- $token)
    string replace -r '@[^,@]*$' '@' -- $token
end

function _confluent_path_complete
    __fish_complete_path (commandline -ct)
end

function _confluent_directory_complete
    __fish_complete_directories (commandline -ct)
end

function _confluent_nr_complete
    if test (_confluent_arg_count) -gt 2
        _confluent_path_complete
        return
    end
    set -l prefix (_confluent_range_prefix)
    for candidate in (_confluent_nodegroups) (nodelist)
        printf '%s%s\n' "$prefix" "$candidate"
    end
end

function _confluent_ng_complete
    if test (_confluent_arg_count) -gt 2
        _confluent_path_complete
        return
    end
    set -l prefix (_confluent_range_prefix)
    for candidate in (_confluent_nodegroups)
        printf '%s%s\n' "$prefix" "$candidate"
    end
end

function _confluent_unseen
    set -l prior (_confluent_prior_args)
    for group in (string split ' ' -- $argv[1])
        set -l options (string split ',' -- $group)
        set -l found 0
        for option in $options
            if contains -- $option $prior
                set found 1
                break
            end
        end
        if test $found -eq 0
            printf '%s\n' $options
        end
    end
end

function _confluent_node_options
    set -l count (_confluent_arg_count)
    if test $count -lt 3
        _confluent_nr_complete
    else if test $count -ge 3
        _confluent_unseen "$argv[1]"
    end
end

function _confluent_nodeattrib_complete
    if test (_confluent_arg_count) -lt 3
        _confluent_nr_complete
    else
        set -l prior (_confluent_prior_args)
        for attribute in (nodeattrib '~.>1' all | awk '{print $2}' | string replace -r ':$' '')
            if not contains -- $attribute $prior
                printf '%s\n' $attribute
            end
        end
    end
end

function _confluent_nodegroupattrib_complete
    if test (_confluent_arg_count) -lt 3
        _confluent_ng_complete
    else
        set -l prior (_confluent_prior_args)
        for attribute in (nodegroupattrib everything all | awk '{print $2}' | string replace -r ':$' '')
            if not contains -- $attribute $prior
                printf '%s\n' $attribute
            end
        end
    end
end

function _confluent_define_complete
    set -l prior (_confluent_prior_args)
    set -l attributes (nodegroupattrib everything all | awk '{print $2}' | string replace -r ':$' '')
    for attribute in $attributes
        if not contains -- $attribute $prior
            printf '%s\n' $attribute
        end
    end
end

function _confluent_nodeconsole_complete
    set -l prior (_confluent_prior_args)
    if test (count $prior) -gt 0; and contains -- $prior[-1] -a --automation
        _confluent_path_complete
        return
    end
    if string match -q -- '-*' (commandline -ct)
        printf '%s\n' -a --automation -e --headless -t --tile -l --log -T --Timestamp -s --screenshot -i --interval -v --video -w --windowed
    else
        _confluent_nn_complete
    end
end

function _confluent_nn_complete
    set -l prefix (_confluent_range_prefix)
    for candidate in (nodelist)
        printf '%s%s\n' "$prefix" "$candidate"
    end
end

function _confluent_nodemedia_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 4; and test (count $args) -ge 3; and test "$args[3]" = upload
        _confluent_path_complete
    else
        _confluent_node_options 'list,upload,attach,detachall -h'
    end
end

function _confluent_nodefirmware_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 3
        printf '%s\n' list update
    else if test $count -gt 3; and test (count $args) -ge 3; and test "$args[3]" = update
        _confluent_path_complete
    else if test $count -lt 3
        _confluent_nr_complete
    end
end

function _confluent_osdeploy_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 2
        printf '%s\n' initialize export import importcheck updateboot rebase fetch
    else if test (count $args) -ge 2
        switch $args[2]
            case initialize
                printf '%s\n' -h -a -g -u -s -k -t -p -i -l -r
            case import importcheck
                _confluent_path_complete
            case fetch
                if test $count -eq 3
                    osdeploy getfetchable
                else
                    _confluent_directory_complete
                end
            case updateboot rebase
                printf '%s\n' -n (confetty show /deployment/profiles | string replace -r '/' '')
            case export
                if test $count -eq 3
                    printf '%s\n' -n (confetty show /deployment/profiles | string replace -r '/' '')
                else
                    _confluent_directory_complete
                end
        end
    end
end

function _confluent_imgutil_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 2
        printf '%s\n' build exec unpack pack capture
    else if test (count $args) -ge 2
        switch $args[2]
            case build
                printf '%s\n' -s (ls /var/lib/confluent/distributions)
            case unpack
                if test $count -eq 3
                    printf '%s\n' -s (ls /var/lib/confluent/public/os)
                else
                    _confluent_directory_complete
                end
            case pack
                if test $count -eq 3
                    _confluent_directory_complete
                end
            case capture
                if test $count -eq 3
                    _confluent_nn_complete
                end
            case exec
                printf '%s\n' -v
                _confluent_directory_complete
        end
    end
end

function _confluent_nodedeploy_complete
    if test (_confluent_arg_count) -gt 2
        printf '%s\n' -n (confetty show /deployment/profiles | string replace -r '/' '')
    else
        _confluent_nr_complete
    end
end

function _confluent_nodeshell_complete
    set -l count (_confluent_arg_count)
    if test $count -eq 3
        __fish_complete_command
    else if test $count -lt 3
        _confluent_nr_complete
    else
        _confluent_path_complete
    end
end

function _confluent_nodelicense_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 3
        printf '%s\n' install list save delete
    else if test $count -lt 3
        _confluent_nr_complete
    else if test $count -eq 4; and test (count $args) -ge 3
        switch $args[3]
            case install
                _confluent_path_complete
            case save
                _confluent_directory_complete
        end
    end
end

function _confluent_nodesupport_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -eq 3
        printf '%s\n' servicedata
    else if test $count -lt 3
        _confluent_nr_complete
    else if test $count -eq 4; and test (count $args) -ge 3; and test "$args[3]" = servicedata
        _confluent_directory_complete
    end
end

function _confluent_nodecertutil_complete
    set -l args (_confluent_prior_args)
    set -l count (_confluent_arg_count)
    if test $count -lt 3
        _confluent_nr_complete
    else if test $count -eq 3
        printf '%s\n' installbmccacert removebmccacert listbmccacerts signbmccert
    else if test (count $args) -ge 3; and test "$args[3]" = signbmccert
        _confluent_unseen '--days --added-names'
    else if test (count $args) -ge 3; and test "$args[3]" = installbmccacert
        _confluent_path_complete
    end
end

function _confluent_nodediscover_complete
    if test (_confluent_arg_count) -eq 2
        printf '%s\n' list assign rescan clear subscribe unsubscribe register
    end
end

complete -c nodeidentify -f -a '(_confluent_node_options "on,off,blink -h")'
complete -c nodeboot -f -a '(_confluent_node_options "default,cd,network,setup,hd,floppy,usb -h -b -p")'
complete -c nodesetboot -f -a '(_confluent_node_options "default,cd,network,setup,hd,floppy,usb -h -b -p")'
complete -c nodepower -f -a '(_confluent_node_options "boot,off,on,status -h -p")'
complete -c nodeattrib -f -a '(_confluent_nodeattrib_complete)'
complete -c nodelist -f -a '(_confluent_nodeattrib_complete)'
complete -c nodegroupattrib -f -a '(_confluent_nodegroupattrib_complete)'
complete -c nodedefine -f -a '(_confluent_define_complete)'
complete -c nodegroupdefine -f -a '(_confluent_define_complete)'
complete -c nodebmcreset -f -a '(_confluent_nr_complete)'
complete -c nodeconfig -f -a '(_confluent_nr_complete)'
complete -c nodeeventlog -f -a '(_confluent_nr_complete)'
complete -c nodehealth -f -a '(_confluent_nr_complete)'
complete -c nodeinventory -f -a '(_confluent_nr_complete)'
complete -c noderemove -f -a '(_confluent_nr_complete)'
complete -c nodereseat -f -a '(_confluent_nr_complete)'
complete -c nodesensors -f -a '(_confluent_nr_complete)'
complete -c nodegroupremove -f -a '(_confluent_ng_complete)'
complete -c nodeconsole -f -a '(_confluent_nodeconsole_complete)'
complete -c nodemedia -f -a '(_confluent_nodemedia_complete)'
complete -c nodefirmware -f -a '(_confluent_nodefirmware_complete)'
complete -c osdeploy -f -a '(_confluent_osdeploy_complete)'
complete -c imgutil -f -a '(_confluent_imgutil_complete)'
complete -c nodedeploy -f -a '(_confluent_nodedeploy_complete)'
complete -c noderun -f -a '(_confluent_nodeshell_complete)'
complete -c nodeshell -f -a '(_confluent_nodeshell_complete)'
complete -c nodelicense -f -a '(_confluent_nodelicense_complete)'
complete -c nodesupport -f -a '(_confluent_nodesupport_complete)'
complete -c nodecertutil -f -a '(_confluent_nodecertutil_complete)'
complete -c nodediscover -f -a '(_confluent_nodediscover_complete)'
