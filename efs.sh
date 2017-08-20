#!/bin/bash

# Copyright (C) 2010, Johan Norberg
#
# This file is part of efs_util.sh
#
# efs_util.sh is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# efs_util.sh is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with efs_util.sh.  If not, see <http://www.gnu.org/licenses/>.
#

function dependency_check {

  # Assume that mkdir, rmdir, mount, umount, cd, if, echo exist (a system without that is not usable)

  # Check that dd is found
  dependency_path=`which dd 2> /dev/null`
  if [ ! -f $dependency_path ]; then
    echo "dd cannot be found. Check your PATH settings."
    return 1;
  fi

  # Check that mkfs.ext4 is found
  dependency_path=`which mkfs.ext4 2> /dev/null`
  if [ ! -f $dependency_path ]; then
    echo "mkfs.ext4 cannot be found. Check your PATH settings."
    return 1;
  fi

  # Check that openssl is found
  dependency_path=`which openssl 2> /dev/null`
  if [ ! -f $dependency_path ]; then
    echo "openssl cannot be found. Check your PATH settings."
    return 1;
  fi

  # Everything found, return OK.
  return 0;
}

function efs_cleanup {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  rm -vf fs.ext4 > /dev/null
}

function efs_create {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  if [ -z $1 ]; then
    echo "use syntax: efs_create [nr_of_megabytes]"
  else 
    size=$1
    dd if=/dev/zero bs=1000k count=$size of=fs.ext4 &> /dev/null && mkfs.ext4 -F fs.ext4 &> /dev/null
    echo "fs.ext4 created ($size MB)"
  fi
}

function efs_mount {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  mkdir -p mnt &&  mount -o loop -t ext4 fs.ext4 mnt && cd mnt
}

function efs_umount {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  current_path=`pwd`
  current_dir=`basename $current_path`
  if [ $current_dir =  "mnt" ]; then
    cd ..
  fi
   umount mnt && rmdir mnt
}

function efs_encrypt {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  openssl enc -aes-256-cbc -salt -in fs.ext4 -out fs.ext4.aes
  echo "fs.ext4.aes created."
}

function efs_decrypt {
  dependency_check
  if [ $? -eq 1 ]; then
    return 0
  fi

  openssl enc -d -aes-256-cbc -in fs.ext4.aes -out fs.ext4
  echo "fs.ext4 created."
}

