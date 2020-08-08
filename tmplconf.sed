# This file is part of the tlsclient project
# 
# (C) 2020 Andreas Steinmetz, ast@domdv.de
# The contents of this file is licensed under the GPL version 2 or, at
# your choice, any later version of this license.
#
s/[ 	]*#.*//
t done
s/^[ 	]*$//
t done
s/^[ 	]\+//
s/[ 	]\+$//
s/.*/	"&\\n"/
p
:done
