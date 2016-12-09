#!/bin/bash
##Credits to Eva2000 from centminmod.com for all his years of hardwork on centminmod which this script is based of.
##Install NGINX
##Install PHP-FPM7
##Install MariaDB
##Install NSD
##Install Pureftpd
##Install Postfix
##Install Adminer/Phpmyadmin
##Instal mysqladmin
##Install Wordpress
##Install WP-CLI
##Install CacheEnabler/wpsupercache
##Install Iptables/csf/lf
##Add remove Ip
##Add remove user(setup users)
##restart services
##Monitor system health
#######################################################
# centminmod.com cli installer
# To run installer.sh type: 
# curl -sL https://gist.github.com/centminmod/dbe765784e03bc4b0d40/raw/installer.sh | bash
#######################################################
export PATH="/usr/lib64/ccache:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"
DT=$(date +"%d%m%y-%H%M%S")
branchname=123.09beta01
DOWNLOAD="${branchname}.zip"
#LOCALCENTMINMOD_MIRROR='https://centminmod.com'

INSTALLDIR='/usr/local/src'
DIR_TMP='/svr-setup'
#####################################################
EMAIL=''          # Server notification email address enter only 1 address
PUSHOVER_EMAIL='' # Signup pushover.net push email notifications to mobile & tablets
ZONEINFO=Etc/UTC  # Set Timezone
NGINX_IPV='n'     # option deprecated from 1.11.5+ IPV6 support
USEEDITOR='nano' # choice between nano or vim text editors for cmd shortcuts

CUSTOMSERVERNAME='y'
CUSTOMSERVERSTRING='nginx'
PHPFPMCONFDIR='/usr/local/nginx/conf/phpfpmd'

UNATTENDED='y' # please leave at 'y' for best compatibility as at .07 release
CMVERSION_CHECK='n'
#####################################################
DT=$(date +"%d%m%y-%H%M%S")
# for github support
branchname='123.09beta01'
SCRIPT_MAJORVER='1.2.3'
SCRIPT_MINORVER='09'
SCRIPT_INCREMENTVER='001'
SCRIPT_VERSION="${SCRIPT_MAJORVER}-eva2000.${SCRIPT_MINORVER}.${SCRIPT_INCREMENTVER}"
SCRIPT_DATE='30/04/2016'
SCRIPT_AUTHOR='eva2000 (centminmod.com)'
SCRIPT_MODIFICATION_AUTHOR='eva2000 (centminmod.com)'
SCRIPT_URL='http://centminmod.com'
COPYRIGHT="Copyright 2011-2016 CentminMod.com"
DISCLAIMER='This software is provided "as is" in the hope that it will be useful, but WITHOUT ANY WARRANTY, to the extent permitted by law; without even the implied warranty of MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.'

###########################################################
#hostname
HN=$(uname -n)
#######
# Setup Colours
black='\E[30;40m'
red='\E[31;40m'
green='\E[32;40m'
yellow='\E[33;40m'
blue='\E[34;40m'
magenta='\E[35;40m'
cyan='\E[36;40m'
white='\E[37;40m'

boldblack='\E[1;30;40m'
boldred='\E[1;31;40m'
boldgreen='\E[1;32;40m'
boldyellow='\E[1;33;40m'
boldblue='\E[1;34;40m'
boldmagenta='\E[1;35;40m'
boldcyan='\E[1;36;40m'
boldwhite='\E[1;37;40m'

Reset="tput sgr0"      #  Reset text attributes to normal
                       #+ without clearing screen.

cecho ()                     # Coloured-echo.
                             # Argument $1 = message
                             # Argument $2 = color
{
message=$1
color=$2
echo -e "$color$message" ; $Reset
return
}
#######################
##disable selinux
if [ -f /etc/selinux/config ]; then
  sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config && setenforce 0
  sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config && setenforce 0
fi

############################################################
##Install Base
apt-get  --yes --force-yes update
apt-get  --yes --force-yes upgrade
apt-get  --yes --force-yes install bc
apt-get  --yes --force-yes install coreutils
apt-get  --yes --force-yes install dnsutils
apt-get  --yes --force-yes install wget
apt-get  --yes --force-yes install nano
apt-get  --yes --force-yes install unzip
apt-get  --yes --force-yes install bzip2
apt-get  --yes --force-yes install ntp
apt-get  --yes --force-yes install ntpdate
apt-get  --yes --force-yes install build-essential
apt-get  --yes --force-yes install libpcre3 libpcre3-dev
apt-get  --yes --force-yes install mariadb-server-10.0
apt-get  --yes --force-yes install postfix
apt-get  --yes --force-yes install pure-ftpd
apt-get  --yes --force-yes install imagemagick
## pcre python postgresql
############################################
##Setup ntp
if [ -f /proc/user_beancounters ]; then
    echo "OpenVZ system detected, NTP not installed"
else
  if [ ! -f /usr/sbin/ntpd ]; then
    echo "*************************************************"
    echo "* Installing NTP (and syncing time)"
    echo "*************************************************"
    echo "The date/time before was:"
    date
    echo
 #   yum -y install ntp
 #   chkconfig ntpd on
update-rc.d ntp defaults
update-rc.d ntp enable
/etc/init.d/ntp start
    if [ -f /etc/ntp.conf ]; then
    echo "current ntp servers"
    NTPSERVERS=$(awk '/server / {print $2}' /etc/ntp.conf | grep ntp.org | sort -r)
    for s in $NTPSERVERS; do
      if [ -f /usr/bin/nc ]; then
        echo -ne "\n$s test connectivity: "
        if [[ "$(echo | nc -u -w1 $s 53 >/dev/null 2>&1 ;echo $?)" = '0' ]]; then
        echo " ok"
        else
        echo " error"
        fi
      fi
        ntpdate -q $s | tail -1
    done
    /etc/init.d/ntp restart >/dev/null 2>&1
    fi
    echo "The date/time is now:"
    date
  fi
fi

#############################################################
###setup networking
#######################################################
# check if custom open file descriptor limits already exist
#??? 
    LIMITSCONFCHECK=`grep '* hard nofile 262144' /etc/security/limits.conf`
    if [[ -z $LIMITSCONFCHECK ]]; then
        # Set VPS hard/soft limits
        echo "* soft nofile 262144" >>/etc/security/limits.conf
        echo "* hard nofile 262144" >>/etc/security/limits.conf
        ulimit -n 262144
        echo "ulimit -n 262144" >> /etc/rc.local
    fi # check if custom open file descriptor limits already exist

##???/etc/security/limits.d/ for ubuntu?
        if [ -d /etc/sysctl.d ]; then
            # centos 7
            touch /etc/sysctl.d/101-sysctl.conf
            
            #??? raise hashsize for conntrack entries
            echo 65536 > /sys/module/nf_conntrack/parameters/hashsize
            
cat > "/etc/sysctl.d/101-sysctl.conf" <<EOF
# vpsmin added
fs.nr_open=12000000
fs.file-max=9000000
net.core.wmem_max=16777216
net.core.rmem_max=16777216
net.ipv4.tcp_rmem=8192 87380 16777216                                          
net.ipv4.tcp_wmem=8192 65536 16777216
net.core.netdev_max_backlog=8192
net.core.somaxconn=8151
net.core.optmem_max=8192
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_sack=1
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_max_tw_buckets = 1440000
vm.swappiness=10
vm.min_free_kbytes=65536
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_limit_output_bytes=65536
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.netfilter.nf_conntrack_helper=0
net.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.netfilter.nf_conntrack_generic_timeout = 60
net.ipv4.tcp_challenge_ack_limit = 999999999
EOF
        /sbin/sysctl --system

fi



###########################################################
#Check shit
##CPU/THREADS?
if [ -f /proc/user_beancounters ]; then
    # CPUS='1'
    # MAKETHREADS=" -j$CPUS"
    # speed up make
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo "$CPUS+2" | bc)
    else
        CPUS=$(echo "$CPUS+1" | bc)
    fi
    MAKETHREADS=" -j$CPUS"
else
    # speed up make
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo "$CPUS+2" | bc)
    else
        CPUS=$(echo "$CPUS+1" | bc)
    fi
    MAKETHREADS=" -j$CPUS"
fi
##Memory
#############################################################
TOTALMEM=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
ISLOWMEM='262144'
#############################################################
# Formulas
TOTALMEMMB=`echo "scale=0;$TOTALMEM/1024" | bc`
ISLOWMEMMB=`echo "scale=0;$ISLOWMEM/1024" | bc`
CHECKLOWMEM=`expr $TOTALMEM \< $ISLOWMEM`
##Arch
MACHINE_TYPE=$(uname -m) # Used to detect if OS is 64bit or not.

if [ "${ARCH_OVERRIDE}" != '' ]
then
    ARCH=${ARCH_OVERRIDE}
else
    if [ "${MACHINE_TYPE}" == 'x86_64' ];
    then
        ARCH='x86_64'
        MDB_ARCH='amd64'
    else
        ARCH='i386'
    fi
fi

if [[ -z "$(cat /etc/resolv.conf)" ]]; then
echo ""
echo "/etc/resolv.conf is empty. No nameserver resolvers detected !! "
echo "Please configure your /etc/resolv.conf correctly or you will not"
echo "be able to use the internet or download from your server."
echo "aborting script... please re-run centmin.sh"
echo ""
exit
fi

if [ ! -f /usr/bin/wget ]; then
echo "wget not found !! "
echo "aborting script... please re-run centmin.sh"
exit
fi

if [ ! -f /usr/bin/unzip ]; then
echo "unzip not found !! "
echo "aborting script... please re-run centmin.sh"
fi

if [ ! -f /usr/bin/bc ]; then
echo "bc not found !! "
echo "aborting script... please re-run centmin.sh"
exit
fi

if [ ! -f /usr/bin/tee ]; then
#echo "tee not found !! "
fi

if [ -f /var/cpanel/cpanel.config ]; then
echo "WHM/Cpanel detected.. centmin mod NOT compatible"
echo "aborting script..."
exit
fi

if [ -f /etc/psa/.psa.shadow ]; then
echo "Plesk detected.. centmin mod NOT compatible"
echo "aborting script..."
exit
fi

if [ -f /etc/init.d/directadmin ]; then
echo "DirectAdmin detected.. centmin mod NOT compatible"
echo "aborting script..."
exit
fi

###########################################################
##Setup Dirs
DIR_TMP='/svr-setup'
SCRIPT_DIR=$(readlink -f $(dirname ${BASH_SOURCE[0]}))
if [ ! -d "$DIR_TMP" ]; then
            mkdir -p "$DIR_TMP"
            chmod 0750 "$DIR_TMP"
        fi
fi
if [ -f /proc/user_beancounters ]; then
    # CPUS='1'
    # MAKETHREADS=" -j$CPUS"
    # speed up make
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo "$CPUS+2" | bc)
    else
        CPUS=$(echo "$CPUS+1" | bc)
    fi
    MAKETHREADS=" -j$CPUS"
else
    # speed up make
    CPUS=$(grep -c "processor" /proc/cpuinfo)
    if [[ "$CPUS" -gt '8' ]]; then
        CPUS=$(echo "$CPUS+2" | bc)
    else
        CPUS=$(echo "$CPUS+1" | bc)
    fi
    MAKETHREADS=" -j$CPUS"
fi

# configure .ini directory
CONFIGSCANBASE='/etc/vpsmin'
CONFIGSCANDIR="${CONFIGSCANBASE}/php.d"

if [ ! -d "$CONFIGSCANBASE" ]; then
	mkdir -p "$CONFIGSCANBASE"
fi

if [ ! -d "$CONFIGSCANDIR" ]; then
	mkdir -p "$CONFIGSCANDIR"
	if [ -d /root/vpsmin/php.d/ ]; then
    	cp -a /root/vpsmin/php.d/* "${CONFIGSCANDIR}/"
    fi
fi

# MySQL non-tmpfs based tmpdir for MySQL temp files
if [ ! -d "/home/mysqltmp" ]; then
	mkdir -p /home/mysqltmp
	chmod 1777 /home/mysqltmp
	CHOWNMYSQL=y
fi
CUR_DIR=$SCRIPT_DIR # Get current directory.
CM_INSTALLDIR=$CUR_DIR
# Set LIBDIR
if [ ${ARCH} == 'x86_64' ];
then
    LIBDIR='lib64'
else
    LIBDIR='lib'
fi
##########################################
##Setup tmp and secure tmp here
HOME_DFSIZE=$(df --output=avail /home | tail -1)
CURRENT_TMPSIZE=$(df -P /tmp | awk '/tmp/ {print $3}')

    # only mount /tmp on tmpfs if CentOS system
    # total memory size is greater than 8GB
    # will give /tmp a size equal to 1/2 total memory
    if [[ "$TOTALMEM" -ge '8100001' ]]; then
	   rm -rf /tmp
	   mkdir -p /tmp
	   mount -t tmpfs -o rw,noexec,nosuid tmpfs /tmp
	   chmod 1777 /tmp
	   echo "tmpfs /tmp tmpfs rw,noexec,nosuid 0 0" >> /etc/fstab
	   rm -rf /var/tmp
	   ln -s /tmp /var/tmp
    elif [[ "$TOTALMEM" -ge '2050061' || "$TOTALMEM" -lt '8100000' ]]; then
       # set on disk non-tmpfs /tmp to 4GB size
       # if total memory is between 2GB and <8GB
       rm -rf /tmp
       if [[ "$HOME_DFSIZE" -le '15750000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=1048576
       elif [[ "$HOME_DFSIZE" -gt '15750001' && "$HOME_DFSIZE" -le '20999000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=2097152
       else
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=4194304
       fi
       echo Y | mkfs.ext4 /home/usertmp_donotdelete
       mkdir -p /tmp
       mount -t ext4 -o loop,rw,noexec,nosuid /home/usertmp_donotdelete /tmp
       chmod 1777 /tmp
       echo "/home/usertmp_donotdelete /tmp ext4 loop,rw,noexec,nosuid 0 0" >> /etc/fstab
       rm -rf /var/tmp
       ln -s /tmp /var/tmp
    elif [[ "$TOTALMEM" -ge '1153434' || "$TOTALMEM" -lt '2050060' ]]; then
       # set on disk non-tmpfs /tmp to 2GB size
       # if total memory is between 1.1-2GB
       rm -rf /tmp
       if [[ "$HOME_DFSIZE" -le '15750000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=1048576
       elif [[ "$HOME_DFSIZE" -gt '15750001' && "$HOME_DFSIZE" -le '20999000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=2097152
       else
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=3000000
       fi
       echo Y | mkfs.ext4 /home/usertmp_donotdelete
       mkdir -p /tmp
       mount -t ext4 -o loop,rw,noexec,nosuid /home/usertmp_donotdelete /tmp
       chmod 1777 /tmp
       echo "/home/usertmp_donotdelete /tmp ext4 loop,rw,noexec,nosuid 0 0" >> /etc/fstab
       rm -rf /var/tmp
       ln -s /tmp /var/tmp
    elif [[ "$TOTALMEM" -le '1153433' ]]; then
       # set on disk non-tmpfs /tmp to 1GB size
       # if total memory is <1.1GB
       rm -rf /tmp
       if [[ "$HOME_DFSIZE" -le '15750000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=1048576
       elif [[ "$HOME_DFSIZE" -gt '15750001' && "$HOME_DFSIZE" -le '20999000' ]]; then
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=2097152
       else
        dd if=/dev/zero of=/home/usertmp_donotdelete bs=1024 count=3000000
       fi
       echo Y | mkfs.ext4 /home/usertmp_donotdelete
       mkdir -p /tmp
       mount -t ext4 -o loop,rw,noexec,nosuid /home/usertmp_donotdelete /tmp
       chmod 1777 /tmp
       echo "/home/usertmp_donotdelete /tmp ext4 loop,rw,noexec,nosuid 0 0" >> /etc/fstab
       rm -rf /var/tmp
       ln -s /tmp /var/tmp       
    fi
###########################################
##Config Variables
CLANG='y'                     # Nginx and LibreSSL
CLANG_PHP='n'                 # PHP
GCCINTEL_PHP='y'              # enable PHP-FPM GCC compiler with Intel cpu optimizations
#PHP_PGO='n'                   # Profile Guided Optimization https://software.intel.com/en-us/blogs/2015/10/09/pgo-let-it-go-php
NGINX_DEVTOOLSETGCC='n'       # Use devtoolset-4 GCC 5.2 even for CentOS 7 nginx compiles
GENERAL_DEVTOOLSETGCC='n'     # Use devtoolset-4 GCC 5.2 whereever possible/coded
INTELOPT='n'
# GCC optimization level choices: -O2 or -O3 or -Ofast (only for GCC via CLANG=n)
GCC_OPTLEVEL='-O3'

##Services
NSD_DISABLED='n'              # when set to =y, NSD disabled by default with chkconfig off
PHP_DISABLED='n'              # when set to =y,  PHP-FPM disabled by default with chkconfig off
MYSQLSERVICE_DISABLED='n'     # when set to =y,  MariaDB MySQL service disabled by default with chkconfig off
PUREFTPD_DISABLED='n'         # when set to =y, Pure-ftpd service disabled by default with chkconfig off
POSTFIX_INSTALL=y            # Install Postfix (and mailx) set to n and SENDMAIL_INSTALL=y for sendmail
#POSTGRESQL='n'               # set to =y to install PostgreSQL 9.6 server, devel packages and pdo-pgsql PHP extension
#PYTHON_VERSION='2.7.10'       # Use this version of Python

CURL_TIMEOUTS=' --max-time 5 --connect-timeout 5'
WGETOPT='-cnv --no-dns-cache -4'

#############################
##Nginx
# Nginx Dynamic Module Switches
NGINX_VERSION='1.11.6'       # Use this version of Nginx
NGINX_VHOSTSSL='y'           # enable centmin.sh menu 2 prompt to create self signed SSL vhost 2nd vhost conf
NGINXBACKUP='y'
NGINXDIR='/usr/local/nginx'
NGINXCONFDIR="${NGINXDIR}/conf"
NGINXBACKUPDIR='/usr/local/nginxbackup'


NGXDYNAMIC_NJS='n'
NGXDYNAMIC_XSLT='n'
NGXDYNAMIC_PERL='n'
NGXDYNAMIC_IMAGEFILTER='y'
NGXDYNAMIC_GEOIP='n'
NGXDYNAMIC_STREAM='y'
NGXDYNAMIC_STREAMGEOIP='n'  # nginx 1.11.3+ option http://hg.nginx.org/nginx/rev/558db057adaa
NGXDYNAMIC_STREAMREALIP='n' # nginx 1.11.4+ option http://hg.nginx.org/nginx/rev/9cac11efb205
NGXDYNAMIC_HEADERSMORE='n'
NGXDYNAMIC_SETMISC='n'
NGXDYNAMIC_ECHO='n'
NGXDYNAMIC_LUA='n'          # leave disabled due to bug https://github.com/openresty/lua-nginx-module/issues/715
NGXDYNAMIC_SRCCACHE='n'
NGXDYNAMIC_DEVELKIT='n'     # leave disabled as it requires lua nginx module as dynamic but it has a bug in lua nginx
NGXDYNAMIC_MEMC='n'
NGXDYNAMIC_REDISTWO='n'
NGXDYNAMIC_NGXPAGESPEED='n'
NGXDYNAMIC_BROTLI='y'
NGXDYNAMIC_FANCYINDEX='n'
NGXDYNAMIC_HIDELENGTH='y'

# set = y to put nginx, php and mariadb major version updates into 503 
# maintenance mode https://community.centminmod.com/posts/26485/
NGINX_UPDATEMAINTENANCE='n'
PHP_UPDATEMAINTENANCE='n'
MARIADB_UPDATEMAINTENANCE='n'

# General Configuration
NGINXUPGRADESLEEP='3'
NSD_INSTALL='n'              # Install NSD (DNS Server)
NSD_VERSION='3.2.18'         # NSD Version
NTP_INSTALL='y'              # Install Network time protocol daemon
NGINXPATCH='y'               # Set to y to allow NGINXPATCH_DELAY seconds time before Nginx configure and patching Nginx
NGINXPATCH_DELAY='1'         # Number of seconds to pause Nginx configure routine during Nginx upgrades
STRIPNGINX='y'               # set 'y' to strip nginx binary to reduce size
NGXMODULE_ALTORDER='y'       # nginx configure module ordering alternative order
NGINX_ZERODT='n'             # nginx zero downtime reloading on nginx upgrades
NGINX_INSTALL='y'            # Install Nginx (Webserver)
NGINX_DEBUG='n'              # Enable & reinstall Nginx debug log nginx.org/en/docs/debugging_log.html & wiki.nginx.org/Debugging
NGINX_HTTP2='y'              # Nginx http/2 patch https://community.centminmod.com/threads/4127/
NGINX_ZLIBNG='n'             # 64bit OS only for Nginx compiled against zlib-ng https://github.com/Dead2/zlib-ng
NGINX_MODSECURITY='n'          # modsecurity module support https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#Installation_for_NGINX
NGINX_RDNS='n'               # https://github.com/flant/nginx-http-rdns
NGINX_NJS='n'                # nginScript https://www.nginx.com/blog/launching-nginscript-and-looking-ahead/
NGINX_GEOIP='n'              # Nginx GEOIP module install
NGINX_GEOIPMEM='n'           # Nginx caches GEOIP databases in memory (default), setting 'n' caches to disk instead
NGINX_SPDY='n'               # Nginx SPDY support
NGINX_SPDYPATCHED='n'        # Cloudflare HTTP/2 + SPDY patch https://github.com/cloudflare/sslconfig/blob/master/patches/nginx__http2_spdy.patch
NGINX_STUBSTATUS='y'         # http://nginx.org/en/docs/http/ngx_http_stub_status_module.html required for nginx statistics
NGINX_SUB='y'                # http://nginx.org/en/docs/http/ngx_http_sub_module.html
NGINX_ADDITION='y'           # http://nginx.org/en/docs/http/ngx_http_addition_module.html
NGINX_IMAGEFILTER='n'        # http://nginx.org/en/docs/http/ngx_http_image_filter_module.html
NGINX_PERL='n'               # http://nginx.org/en/docs/http/ngx_http_perl_module.html
NGINX_XSLT='n'               # http://nginx.org/en/docs/http/ngx_http_xslt_module.html
NGINX_LENGTHHIDE='n'         # https://github.com/nulab/nginx-length-hiding-filter-module
NGINX_LENGTHHIDEGIT='y'      # triggers only if NGINX_LENGTHHIDE='y'
NGINX_CACHEPURGE='y'         # https://github.com/FRiCKLE/ngx_cache_purge/
NGINX_ACCESSKEY='n'          #
NGINX_HTTPCONCAT='n'         # https://github.com/alibaba/nginx-http-concat
NGINX_THREADS='y'            # https://www.nginx.com/blog/thread-pools-boost-performance-9x/
NGINX_STREAM='y'             # http://nginx.org/en/docs/stream/ngx_stream_core_module.html
NGINX_STREAMGEOIP='n'        # nginx 1.11.3+ option http://hg.nginx.org/nginx/rev/558db057adaa
NGINX_STREAMREALIP='y'       # nginx 1.11.4+ option http://hg.nginx.org/nginx/rev/9cac11efb205
NGINX_STREAMSSLPREREAD='y'   # nginx 1.11.5+ option https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html
NGINX_RTMP='n'               # Nginx RTMP Module support https://github.com/arut/nginx-rtmp-module
NGINX_FLV='n'                # http://nginx.org/en/docs/http/ngx_http_flv_module.html
NGINX_MP4='n'                # Nginx MP4 Module http://nginx.org/en/docs/http/ngx_http_mp4_module.html
NGINX_AUTHREQ='n'            # http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
NGINX_SECURELINK='y'         # http://nginx.org/en/docs/http/ngx_http_secure_link_module.html
NGINX_FANCYINDEX='n'         # https://github.com/aperezdc/ngx-fancyindex/releases
NGINX_FANCYINDEXVER='0.4.0'  # https://github.com/aperezdc/ngx-fancyindex/releases
NGINX_VHOSTSTATS='y'         # https://github.com/vozlt/nginx-module-vts
NGINX_LIBBROTLI='n'          # https://github.com/google/ngx_brotli
NGINX_LIBBROTLISTATIC='n'
NGINX_PAGESPEED='n'          # Install ngx_pagespeed
NGINX_PAGESPEEDGITMASTER='n' # Install ngx_pagespeed from official github master instead  
NGXPGSPEED_VER='1.11.33.4-beta'
NGINX_PAGESPEEDPSOL_VER='1.11.33.4'
NGINX_PASSENGER='n'          # Install Phusion Passenger requires installing addons/passenger.sh before hand
NGINX_WEBDAV='n'             # Nginx WebDAV and nginx-dav-ext-module
NGINX_EXTWEBDAVVER='0.0.3'   # nginx-dav-ext-module version
NGINX_LIBATOMIC='y'          # Nginx configured with libatomic support
NGINX_HTTPREDIS='n'          # Nginx redis http://wiki.nginx.org/HttpRedisModule
NGINX_HTTPREDISVER='0.3.7'   # Nginx redis version
NGINX_PCREJIT='y'            # Nginx configured with pcre & pcre-jit support
NGINX_PCREVER='8.39'         # Version of PCRE used for pcre-jit support in Nginx
NGINX_HEADERSMORE='0.32'
NGINX_CACHEPURGEVER='2.3'
NGINX_STICKY='n'             # nginx sticky module https://bitbucket.org/nginx-goodies/nginx-sticky-module-ng
NGINX_STICKYVER='master'
NGINX_UPSTREAMCHECK='n'      # nginx upstream check https://github.com/yaoweibin/nginx_upstream_check_module
NGINX_UPSTREAMCHECKVER='0.3.0'
NGINX_OPENRESTY='n'          # Agentzh's openresty Nginx modules
#############################
##PHP
STRIPPHP='y'                 # set 'y' to strip PHP binary to reduce size
PHP_INSTALL='y'              # Install PHP /w Fast Process Manager
PHP_CUSTOMSSL='n'            # compile php-fpm against openssl 1.0.2+ or libressl 2.3+ whichever nginx uses
PHPMAKETEST=n                # set to y to enable make test after PHP make for diagnostic purposes
AUTODETECPHP_OVERRIDE='n'    # when enabled, php updates will always reinstall all php extensions even if minor php version

PHPGEOIP_ALWAYS='n'          # GeoIP php extension is always reinstalled on php recompiles
PHPIMAGICK_ALWAYS='y'        # imagick php extension is always reinstalled on php recompiles
PHPDEBUGMODE='n'             # --enable-debug PHP compile flag
PHPFINFO='y'                 # Disable or Enable PHP File Info extension
PHPPCNTL='n'                 # Disable or Enable PHP Process Control extension
PHPINTL='y'                  # Disable or Enable PHP intl extension
PHPRECODE=n                  # Disable or Enable PHP Recode extension
PHPSNMP='n'                  # Disable or Enable PHP SNMP extension
PHPIMAGICK='y'               # Disable or Enable PHP ImagicK extension
PHPMAILPARSE='n'             # Disable or Enable PHP mailparse extension
PHPIONCUBE='n'               # Disable or Enable Ioncube Loader via addons/ioncube.sh
PHPMSSQL='n'                 # Disable or Enable MSSQL server PHP extension
PHPMSSQL_ALWAYS='n'          # mssql php extension always install on php recompiles
IMAGICKPHP_VER='3.4.3RC1'   # PHP extension for imagick

PHP_FTPEXT='y'              # ftp PHP extension
PHP_VERSION='7.0.13'        # Use this version of PHP '7.0.10 7.0.13
PHP_MIRRORURL='http://php.net'
PHPUPGRADE_MIRRORURL="$PHP_MIRRORURL"
ZOPCACHEDFT='y'
ZOPCACHECACHE_VERSION='7.0.5'   # for PHP <=5.4 http://pecl.php.net/package/ZendOpcache
ZOPCACHE_OVERRIDE='n'           # =y will override PHP 5.5, 5.6, 7.0 inbuilt Zend OpCache version

SHORTCUTS='y'                # shortcuts


########################################################
##SSL
# LibreSSL
LIBRESSL_SWITCH='y'        # if set to 'y' it overrides OpenSSL as the default static compiled option for Nginx server
LIBRESSL_VERSION='2.4.4'   # Use this version of LibreSSL http://www.libressl.org/
# BoringSSL
# not working yet just prep work
BORINGSSL_SWITCH='n'       # if set to 'y' it overrides OpenSSL as the default static compiled option for Nginx server

###############################################################
# Settings for centmin.sh menu option 2 and option 22 for
# 
# -subj "/C=US/ST=California/L=Los Angeles/O=${vhostname}/OU=${vhostname}/CN=${vhostname}"
# 
# You can only customise the first 5 variables for 
# C = Country 2 digit code
# ST = state 
# L = Location as in city 
# 0 = organisation
# OU = organisational unit
# 
# if left blank # defaults to same as vhostname that is your domain
# if set it overrides that
SELFSIGNEDSSL_C='US'
SELFSIGNEDSSL_ST='California'
SELFSIGNEDSSL_L='Los Angeles'
SELFSIGNEDSSL_O=''
SELFSIGNEDSSL_OU=''
###############################################################
# centmin.sh menu option 22 specific options
WPPLUGINS_ALL='n'           # do not install additional plugins
WPCLI_SUPERCACHEPLUGIN='n'  # https://community.centminmod.com/threads/5102/
###############################################################
# php configured --with-mysql-sock=${PHP_MYSQLSOCKPATH}/mysql.sock
PHP_MYSQLSOCKPATH='/var/lib/mysql'
###############################################################
# Letsencrypt integration via addons/acmetool.sh auto detection
LETSENCRYPT_DETECT='n'
###############################################################

###########################################################
## Base programs

##
