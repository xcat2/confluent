PATH=/opt/confluent/bin:$PATH
export PATH
MANPATH=/opt/confluent/share/man:$MANPATH
export MANPATH
# The aliases below are to signify that file globbing is unwelcome at the shell
# this avoids a problem if a user does a noderange like 'n[21-33] and there is a file
# in the directory like 'n3' that causes the parameter to change and target a totally
# different node
# Unfortunately in bourne shell, we cannot reliably ensure a prepended set-f
# and an appended set +f are both run.  alias seems to be the only mechanism
# that can intervene before glob expansion, but it lacks power.
# putting it into a function to append is all well and good, *except*  that
# if doing something like 'nodepower compute|grep' causes set -f to execute
# in current shell, and the function to be in a subshell and leaves globbing
# disabled in the parent shell.  Instead, store the current command in a
# variable and use that to check for misglobbed noderanges, which was the goal
alias nodeattrib='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeattrib'
alias nodebmcreset='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodebmcreset'
alias nodeboot='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeboot'
alias nodeconfig='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeconfig'
alias nodeconsole='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeconsole'
alias nodedefine='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodedefine'
alias nodeeventlog='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeeventlog'
alias nodefirmware='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodefirmware'
alias nodegroupattrib='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodegroupattrib'
alias nodegroupdefine='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodegroupdefine'
alias nodegroupremove='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodegroupremove'
alias nodehealth='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodehealth'
alias nodeidentify='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeidentify'
alias nodeinventory='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeinventory'
alias nodelist='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodelist'
alias nodemedia='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodemedia'
alias nodepower='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodepower'
alias noderemove='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; noderemove'
alias nodereseat='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodereseat'
alias noderun='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; noderun'
alias nodesensors='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodesensors'
alias nodesetboot='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodesetboot'
alias nodeshell='CURRENT_CMDLINE=$(HISTTIMEFORMAT= builtin history 1); export CURRENT_CMDLINE; nodeshell'
