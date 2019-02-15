
#xcat version string
xcat_version=""

#xcat version number
xcat_verno=""

#xcat service running?
isxcatrunning=0

implicitEnvVars={'OBJNAME':{'description':"the object name to import"},
                 'GITROOT':{'description':"the root path of the git repo where the inventory file resides in"},
                 'GITBRANCH':{'description':"the current git branch name of the inventory file to import"},
                 'GITTAG':{'description':"the current git tag of the inventory file to import"},
                 'GITCOMMIT':{'description':"the current git commit number of the inventory file to import"}}

#verbose?
verbose=False
