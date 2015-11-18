# == Class: profile::base::centos6
#
# CentOS base install. Configured according to CIS standards.
#
# === Author
#
# Joon Guillen
#

class profile::base::centos6 {

  ###################
  ## Hiera lookups ##
  ###################

  $org_name           = hiera('profile::base::org_name')
  $ntp_servers        = hiera('profile::base::ntp_servers')
  $timezone           = hiera('profile::base::timezone')
  $proxy_server       = hiera('profile::base::proxy_server', 'none')
  $proxy_port         = hiera('profile::base::proxy_port', 'none')
  $puppet_interval    = hiera('profile::base::puppet_interval', '30m' )
  $ntp_interfaces     = hiera('profile::base::centos6::ntp_interfaces')
  $selinux_mode       = hiera('profile::base::centos6::selinux_mode', 'enforcing')
  $sysctl_purge       = hiera('profile::base::centos6::sysctl_purge', true)
  $sysctl_ipv4forward = hiera('profile::base::centos6::sysctl_ipv4forward', '0')
  $sshd_manage        = hiera('profile::base::centos6::sshd_manage', true)
  $sshd_port          = hiera('profile::base::centos6::sshd_port', 22)
  $sshd_addressfamily = hiera('profile::base::centos6::sshd_addressfamily', 'any')
  $sshd_listenaddress = hiera('profile::base::centos6::sshd_listenaddress', [ '0.0.0.0' ])
  $sshd_pubkeyauth    = hiera('profile::base::centos6::sshd_pubkeyauth', 'yes')
  $sshd_passwordauth  = hiera('profile::base::centos6::sshd_passwordauth', 'yes')
  $sshd_usepam        = hiera('profile::base::centos6::sshd_usepam', 'yes')
  $sshd_tcpforwarding = hiera('profile::base::centos6::sshd_tcpforwarding', 'no')
  $sshd_usedns        = hiera('profile::base::centos6::sshd_usedns', 'yes')
  $sshd_allowgroups   = hiera('profile::base::centos6::sshd_allowgroups', 'wheel')
  $clamav_excludes    = hiera('profile::base::centos6::clamav_excludes', [])
  $clamav_mirrors     = hiera('profile::base::centos6::clamav_mirrors', [])
  $clamav_scanhour    = hiera('profile::base::centos6::clamav_scanhour', '5')
  $login_retry        = hiera('profile::base::centos6::login_retry', '5')
  $login_pw_minlen    = hiera('profile::base::centos6::login_pw_minlen', '13')
  $login_pw_minclass  = hiera('profile::base::centos6::login_pw_minclass', '3')
  $login_pw_remember  = hiera('profile::base::centos6::login_pw_remember', '24')
  $login_pw_maxdays   = hiera('profile::base::centos6::login_pw_maxdays', '90')
  $login_pw_mindays   = hiera('profile::base::centos6::login_pw_mindays', '1')
  $login_pw_warnage   = hiera('profile::base::centos6::login_pw_warnage', '14')
  $login_lo_attempts  = hiera('profile::base::centos6::login_lo_attempts', '5')
  $login_lo_unlocksec = hiera('profile::base::centos6::login_lo_unlocksec', '900')
  $postfix_relayhost  = hiera('profile::base::centos6::postfix_relayhost', [])
  $auth_activedir     = hiera('profile::base::centos6::auth_activedir', 'no')
  if $auth_activedir=='yes' {
    $auth_ad_domain     = hiera('profile::base::centos6::auth_ad_domain')
    $auth_ad_domain_nb  = hiera('profile::base::centos6::auth_ad_domain_nb')
    $auth_ad_servers    = hiera('profile::base::centos6::auth_ad_servers')
    $auth_ad_group_dn   = hiera('profile::base::centos6::auth_ad_group_dn')
    $auth_ad_cache_cr   = hiera('profile::base::centos6::auth_ad_cache_cr')
  }


  ##################################
  ## Declarations & Preprocessing ##
  ##################################

  # Local variables
  $puppet_scripts_dir = '/root/puppet_scripts'

  # AD integration:

  # 1. Extract Linux group name from Distinguished Name (DN)
  $auth_ad_group = downcase(regsubst($auth_ad_group_dn, '^CN=([^,]*),.*$', '\1', 'I'))

  # 2. Throw an error if group name contains whitespaces
  if $auth_ad_group =~ /\s+/ {
    fail("ERROR: AD Group Name '$auth_ad_group' contains whitespace characters!")
  }


  ####################
  ## Custom classes ##
  ####################


  class firstthingsfirst (
    $puppet_scripts_dir = $profile::base::centos6::puppet_scripts_dir,
    $tz                 = $profile::base::centos6::timezone,
    $proxy_server       = $profile::base::centos6::proxy_server,
    $proxy_port         = $profile::base::centos6::proxy_port,
    $selinux_mode       = $profile::base::centos6::selinux_mode
  ) {
    
    # Set timezone
    class { '::timezone': timezone => $tz }

    # Create puppet_scripts directory
    file { $puppet_scripts_dir:
      ensure => 'directory',
      owner  => 'root',
      group  => 'root',
      mode   => '0750'
    }

    # Sudoers
    file_line { 'sudo_wheel':
      path    => '/etc/sudoers',
      line    => '%wheel  ALL=(ALL)       ALL',
      match   => '#?\s?%wheel\s+ALL=\(ALL\)\s+ALL',
      replace => true
    }

    # Set global proxy server environment variable
    # Only apply if proxy is set
    if $proxy_server!=undef and $proxy_server!='none' {
      #yumrepo { 'main': proxy => "http://$proxy_server:$proxy_port" }
      file_line { 'http_proxy':
        path    => '/etc/environment',
        line    => "http_proxy=http://$proxy_server:$proxy_port",
        match   => 'http_proxy',
        replace => true
      }
      file_line { 'https_proxy':
        path    => '/etc/environment',
        line    => "https_proxy=http://$proxy_server:$proxy_port",
        match   => 'https_proxy',
        replace => true
      }
    } else {
      #exec { "/bin/sed -i '/^proxy=/d' /etc/yum.conf":
      #  onlyif   => '/bin/grep -E "^proxy\s*=" /etc/yum.conf',
      #  path     => ['/bin'],
      #  provider => 'shell'
      #}
      exec { "/bin/sed -i '/^http_proxy=/d' /etc/environment":
        onlyif   => '/bin/grep -E "^http_proxy\s*=" /etc/environment',
        path     => ['/bin'],
        provider => 'shell'
      }
      exec { "/bin/sed -i '/^https_proxy=/d' /etc/environment":
        onlyif   => '/bin/grep -E "^https_proxy\s*=" /etc/environment',
        path     => ['/bin'],
        provider => 'shell'
      }
    } 

    # Set global proxy server environment variable
    
    # Useful tools/utilities
    $packlist = [
      'epel-release','at', 'bash-completion', 'cronie-anacron','crontabs',
      'curl', 'ed','sed','screen', 'lsof', 'man', 'man-pages', 'nano','srm',
      'tcp_wrappers', 'telnet', 'tree','vim-enhanced', 'wget', 'sysstat',
      'strace', 'yum-utils', 'yum-plugin-remove-with-leaves', 'yum-plugin-security'
    ]
    package { $packlist: ensure => 'installed' }

    # SELinux
    class { '::selinux': mode => $selinux_mode }

  }


  class sysctld (
     $ipv4forward = $profile::base::centos6::sysctl_ipv4forward,
     $purge_conf  = $profile::base::centos6::sysctl_purge
  ) {

    file { '/etc/sysctl.conf': ensure => 'absent' }   # Remove sysctl.conf; we will use sysctl.d instead
    class { '::sysctl::base': purge => $purge_conf }  # Purge original contents of systcl.d (if any)

    sysctl { 'kernel.sysrq': value => '0' }
    sysctl { 'kernel.core_uses_pid': value => '1' }
    sysctl { 'kernel.msgmnb': value => '65536' }
    sysctl { 'kernel.msgmax': value => '65536' }
    sysctl { 'kernel.shmmax': value => '68719476736' }
    sysctl { 'kernel.shmall': value => '4294967296' }
    sysctl { 'kernel.exec-shield': value => '1' }
    sysctl { 'kernel.randomize_va_space': value => '2' }
    sysctl { 'fs.suid_dumpable': value => '0' }
  
    sysctl { 'net.ipv6.conf.all.disable_ipv6': value => '1' }
    sysctl { 'net.ipv6.conf.default.disable_ipv6': value => '1' }
    sysctl { 'net.ipv6.conf.all.accept_ra': value => '0' }
    sysctl { 'net.ipv6.conf.default.accept_ra': value => '0' }
    sysctl { 'net.ipv6.conf.all.accept_redirects': value => '0' }
    sysctl { 'net.ipv6.conf.default.accept_redirects': value => '0' }

    sysctl { 'net.ipv4.ip_forward': value => $ipv4forward }
    sysctl { 'net.ipv4.conf.default.rp_filter': value => '1' }
    sysctl { 'net.ipv4.conf.default.accept_source_route': value => '0' }
    sysctl { 'net.ipv4.conf.all.send_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.default.send_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.all.accept_source_route': value => '0' }
    sysctl { 'net.ipv4.conf.all.accept_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.default.accept_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.all.secure_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.default.secure_redirects': value => '0' }
    sysctl { 'net.ipv4.conf.all.log_martians': value => '1' }
    sysctl { 'net.ipv4.conf.default.log_martians': value => '1' }
    sysctl { 'net.ipv4.icmp_echo_ignore_broadcasts': value => '1' }
    sysctl { 'net.ipv4.icmp_ignore_bogus_error_responses': value => '1' }
    sysctl { 'net.ipv4.conf.all.rp_filter': value => '1' }
    sysctl { 'net.ipv4.tcp_syncookies': value => '1' }
    #sysctl { 'net.bridge.bridge-nf-call-ip6tables': value => '0' }
    #sysctl { 'net.bridge.bridge-nf-call-iptables': value => '0' }
    #sysctl { 'net.bridge.bridge-nf-call-arptables': value => '0' }

  }


  class sshd (
    $sshd_port          = $profile::base::centos6::sshd_port,
    $sshd_addressfamily = $profile::base::centos6::sshd_addressfamily,
    $sshd_listenaddress = $profile::base::centos6::sshd_listenaddress,
    $sshd_pubkeyauth    = $profile::base::centos6::sshd_pubkeyauth,
    $sshd_passwordauth  = $profile::base::centos6::sshd_passwordauth,
    $sshd_usepam        = $profile::base::centos6::sshd_usepam,
    $sshd_tcpforwarding = $profile::base::centos6::sshd_tcpforwarding,
    $sshd_usedns        = $profile::base::centos6::sshd_usedns,
    $sshd_allowgroups   = $profile::base::centos6::sshd_allowgroups,
    $activedir          = $profile::base::centos6::auth_activedir,
    $ad_group           = $profile::base::centos6::auth_ad_group
  ) {

    # Add AD group to AllowGroups
    if $activedir=='yes' {
      $sshd_allowgroups_parsed = "${sshd_allowgroups} ${ad_group}"
    } else {
      $sshd_allowgroups_parsed = "$sshd_allowgroups"
    }

    class { '::ssh::server':
      storeconfigs_enabled => false,
      options              => {
        'Port'                            => $sshd_port,
        'AddressFamily'                   => $sshd_addressfamily,
        'ListenAddress'                   => $sshd_listenaddress,
        'Protocol'                        => 2,
        'SyslogFacility'                  => 'AUTHPRIV',
        'LogLevel'                        => 'INFO',
        'LoginGraceTime'                  => '2m',
        'PermitRootLogin'                 => 'no',
        'StrictModes'                     => 'yes',
        'MaxAuthTries'                    => 5,
        'MaxSessions'                     => 10,
        'RSAAuthentication'               => 'yes',
        'PubkeyAuthentication'            => $sshd_pubkeyauth,
        'RhostsRSAAuthentication'         => 'no',
        'HostbasedAuthentication'         => 'no',
        'IgnoreRhosts'                    => 'yes',
        'PasswordAuthentication'          => $sshd_passwordauth,
        'PermitEmptyPasswords'            => 'no',
        'ChallengeResponseAuthentication' => 'no',
        'GSSAPIAuthentication'            => 'yes',
        'GSSAPICleanupCredentials'        => 'yes',
        'UsePAM'                          => $sshd_usepam,
        'AcceptEnv'                       => [
          'LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES',
          'LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT',
          'LC_IDENTIFICATION LC_ALL LANGUAGE',
          'XMODIFIERS'
        ],
        'AllowTcpForwarding'              => $sshd_tcpforwarding,
        'X11Forwarding'                   => 'no',
        'TCPKeepAlive'                    => 'yes',
        'UsePrivilegeSeparation'          => 'yes',
        'PermitUserEnvironment'           => 'no',
        'Compression'                     => 'delayed',
        'ClientAliveInterval'             => '900',
        'ClientAliveCountMax'             => '0',
        'ShowPatchLevel'                  => 'no',
        'UseDNS'                          => $sshd_usedns,
        'PermitTunnel'                    => 'no',
        'ChrootDirectory'                 => 'none',
        'Banner'                          => '/etc/issue.net',
        'Subsystem'                       => 'sftp /usr/libexec/openssh/sftp-server',
        'Ciphers'                         => 'aes192-ctr,aes256-ctr,aes128-ctr',
        'MACs'                            => 'hmac-sha2-256,hmac-sha2-512,hmac-sha1',
        'AllowGroups'                     => $sshd_allowgroups_parsed
      }
    }

  }


  class ntpd (
    $ntp_servers    = $profile::base::centos6::ntp_servers,
    $ntp_interfaces = $profile::base::centos6::ntp_interfaces
  ) {
    class { '::ntp':
      package_manage => true,
      package_ensure => 'installed',
      service_enable => true,
      service_ensure => 'running',
      servers        => $ntp_servers,
      interfaces     => $ntp_interfaces,
      iburst_enable  => true,
      restrict       => [
        'default kod nomodify notrap nopeer noquery',
        '127.0.0.1',
      ],
    }
  }


  class postfix (
    $inet_protocols = 'ipv4',
    $relayhost = $profile::base::centos6::postfix_relayhost
  ) {
    package { 'postfix': ensure => 'installed' }
    service { 'postfix':
      ensure  => 'running',
      enable  => true,
      require => Package['postfix']
    }
    file { '/etc/postfix/main.cf':
      notify  => Service['postfix'],
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      require => Package['postfix'],
      content => template('profile/centos6/etc/postfix/main.cf.erb')
    }
  }


  class auditd ($puppet_scripts_dir = $profile::base::centos6::puppet_scripts_dir) {
    package { 'audit': ensure => 'installed' }
    service { 'auditd':
      ensure  => 'running',
      enable  => true,
      require => Package['audit']
    }
    file { '/etc/audit/auditd.conf':
      notify  => Service['auditd'],
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      require => Package['audit'],
      content => file('profile/centos6/etc/audit/auditd.conf')
    }
    file_line { 'auditd_initd':
      path    => '/etc/sysconfig/auditd',
      line    => 'USE_AUGENRULES="yes"',
      match   => 'USE_AUGENRULES="no"',
      replace => true
    }
   # Initial rules.d entry
    file { '/etc/audit/rules.d/audit.rules':
      notify  => Service['auditd'],
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      require => Package['audit'],
      content => file('profile/centos6/etc/audit/rules.d/audit.rules')
    }
   # 2nd rules.d entry (cis01.rules)
    file { "$puppet_scripts_dir/audit_rules_custom.sh":
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/audit_rules_custom.sh')
    }
    exec { "$puppet_scripts_dir/audit_rules_custom.sh":
      creates => '/etc/audit/rules.d/cis01.rules',
      path    => ['/bin']
    }
   # 3rd and last rules.d entry (cis02.rules)
    file { '/etc/audit/rules.d/cis02.rules':
      notify  => Service['auditd'],
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      require => Package['audit'],
      content => file('profile/centos6/etc/audit/rules.d/cis02.rules')
    }
  }


  class file_permissions {
    
    file { '/etc/anacrontab':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/crontab':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.hourly':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.daily':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.weekly':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.monthly':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.d':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/cron.allow':
      ensure => 'present',
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
    file { '/etc/at.allow':
      ensure => 'present',
      owner  => 'root',
      group  => 'root',
      mode   => 'og-rwx',
    }
    file { '/etc/cron.deny': ensure => 'absent' }
    file { '/etc/at.deny':   ensure => 'absent' }
    file { '/etc/grub.conf':
      owner => 'root',
      group => 'root',
      mode  => 'og-rwx',
    }
    file { '/etc/passwd':
      owner => 'root',
      group => 'root',
      mode  => '0644',
    }
    file { '/etc/group':
      owner => 'root',
      group => 'root',
      mode  => '0644',
    }
    file { '/etc/shadow':
      owner => 'root',
      group => 'root',
      mode  => '0000',
    }
    file { '/etc/gshadow':
      owner => 'root',
      group => 'root',
      mode  => '0000',
    }
    file { '/etc/sysconfig/iptables':
      owner => 'root',
      group => 'root',
      mode  => '0600',
    }

  }


  class filesystems {

    mount { '/dev/shm':
      fstype  => 'tmpfs',
      options => 'defaults,nodev,nosuid,noexec',
    }
    mount { '/boot':
      fstype  => 'ext4',
      options => 'defaults,nodev,nosuid,noexec',
    }
    mount { '/tmp':
      fstype  => 'ext4',
      options => 'defaults,nodev,nosuid,noexec',
    }
    mount { '/home':
      fstype  => 'ext4',
      options => 'defaults,nodev,nosuid',
    }
    mount { '/var':
      fstype  => 'ext4',
      options => 'defaults,nosuid',
    }
    mount { '/var/tmp':
      ensure  => 'mounted',
      device  => '/tmp',
      fstype  => 'none',
      options => 'bind',
    }
    file { '/etc/modprobe.d/blacklist-filesystems.conf':
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/modprobe.d/blacklist-filesystems.conf')
    }

  }


  class iptables_init ($puppet_scripts_dir = $profile::base::centos6::puppet_scripts_dir) {

    # Initialize the iptables config file
    file { "$puppet_scripts_dir/iptables_init.sh":
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/iptables_init.sh')
    }
    exec { "$puppet_scripts_dir/iptables_init.sh":
      #onlyif   => '! /bin/grep "\-A INPUT \-j DROP" /etc/sysconfig/iptables',
      onlyif   => '! /bin/grep "Puppet\-Custom\-INPUT" /etc/sysconfig/iptables',
      path     => ['/bin', '/sbin'],
      provider => 'shell'
    }

    # Install the custom IPtables config script
    file { "$puppet_scripts_dir/puppet_custom_iptables.sh":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/puppet_custom_iptables.sh'),
    }

  }


  class networking ( $puppet_scripts_dir = $profile::base::centos6::puppet_scripts_dir ) {
  
    # Disable IPv6 on networking config 
    file_line { 'sysconfig_network1':
      path    => '/etc/sysconfig/network',
      line    => 'NETWORKING_IPV6=no',
      match   => '#*\s*NETWORKING_IPV6\s*=',
      replace => true
    }
    file_line { 'sysconfig_network2':
      path    => '/etc/sysconfig/network',
      line    => 'IPV6INIT=no',
      match   => '#*\s*IPV6INIT\s*=',
      replace => true
    }

    # Disable ip6tables
    service { 'ip6tables':
      ensure => 'stopped',
      enable => false
    }

    # Disable wireless modules
    file { "$puppet_scripts_dir/disable_wireless.sh":
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/disable_wireless.sh')
    }
    exec { "$puppet_scripts_dir/disable_wireless.sh":
      creates => '/etc/modprobe.d/blacklist-wireless.conf',
      path    => ['/bin']
    }

    # tcp_wrappers
    file_line { 'hosts.allow':
      path    => '/etc/hosts.allow',
      line    => 'sshd : ALL',
      match   => '#\s*sshd\s*:\s*ALL',
      replace => true
    }
    file_line { 'hosts.deny':
      path    => '/etc/hosts.deny',
      line    => 'ALL : ALL',
      match   => '#\s*ALL\s*:\s*ALL',
      replace => true
    }

  }

  class miscellaneous ( $org_name = $profile::base::centos6::org_name )  {

    $umask_file     = '/etc/profile.d/umask.sh'
    $securetty_file = '/etc/securetty'

    # Require authentication for single user mode
    file_line { 'sysconfig_init1':
      path    => '/etc/sysconfig/init',
      line    => 'SINGLE=/sbin/sulogin',
      match   => '#*\s*SINGLE\s*=',
      replace => true
    }

    # Disable interactive boot
    file_line { 'sysconfig_init2':
      path    => '/etc/sysconfig/init',
      line    => 'PROMPT=no',
      match   => '#*\s*PROMPT\s*=',
      replace => true
    }

    # Warning banner
    file { "/etc/issue":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('profile/centos6/etc/issue.erb')
    }
    file { "/etc/issue.net":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template('profile/centos6/etc/issue.erb')
    }

    # Restrict core dumps
    file { "/etc/security/limits.d/00-coredumps.conf":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/security/limits.d/00-coredumps.conf')
    }

    # Default .screenrc
    file { "/etc/skel/.screenrc":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/skel/.screenrc')
    }

    # Default .vimrc
    file { "/etc/skel/.vimrc":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/skel/.vimrc')
    }

    # /etc/profile.d/umask.sh
    file { $umask_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file("profile/centos6$umask_file")
    }

    # /etc/securetty
    file { $securetty_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => file("profile/centos6$securetty_file")
    }

   # Undo disabling of IPv6 module (relic of standard CentOS VM template)
   file { "/etc/modprobe.d/ipv6.conf": ensure => 'absent' }

  }


  class clamav (

    $exclude_paths = $profile::base::centos6::clamav_excludes,  # Only add non-default paths
    $db_mirrors    = $profile::base::centos6::clamav_mirrors,
    $proxy_server  = $profile::base::centos6::proxy_server,
    $proxy_port    = $profile::base::centos6::proxy_port,
    $scan_hour     = $profile::base::centos6::clamav_scanhour   # The hour of day clamdscan.sh runs

  ) {

    $clamdscan = '/var/lib/clamav/clamdscan.sh'

    # Ensure package / service
    package { 'clamav': ensure => 'installed' }
    package { 'clamd':  ensure => 'installed' }
    service { 'clamd':
      ensure  => 'running',
      enable  => 'true',
      require => Package['clamd']
    }

    # Config files from template
    file { '/etc/clamd.conf':
      notify  => Service['clamd'],
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      require => Package['clamd'],
      content => template('profile/centos6/etc/clamd.conf.erb')
    }
    file { '/etc/freshclam.conf':
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => template('profile/centos6/etc/freshclam.conf.erb')
    }
    
    # Custom selinux settings
    selboolean { 'antivirus_can_scan_system':
      persistent => true,
      value   => 'on'
    }
    selboolean { 'antivirus_use_jit':
      persistent => true,
      value   => 'on'
    }
    
    # Periodic system scan script
    file { $clamdscan:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => file("profile/centos6$clamdscan")
    }
    file { '/etc/logrotate.d/clamdscan':
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file("profile/centos6/etc/logrotate.d/clamdscan")
    }
    cron { 'clamdscan.sh':
      name    => "Daily antivirus scan",
      command => $clamdscan,
      user    => 'root',
      hour    => $scan_hour,
      minute  => fqdn_rand(60)
    }

  }


  class authentication (

    $scripts_dir   = $profile::base::centos6::puppet_scripts_dir,
    $login_retry   = $profile::base::centos6::login_retry,
    $pw_minlen     = $profile::base::centos6::login_pw_minlen,
    $pw_minclass   = $profile::base::centos6::login_pw_minclass,
    $pw_remember   = $profile::base::centos6::login_pw_remember,
    $pw_maxdays    = $profile::base::centos6::login_pw_maxdays,
    $pw_mindays    = $profile::base::centos6::login_pw_mindays,
    $pw_warnage    = $profile::base::centos6::login_pw_warnage,
    $lo_attempts   = $profile::base::centos6::login_lo_attempts,
    $lo_unlocktime = $profile::base::centos6::login_lo_unlocksec,
    $activedir     = $profile::base::centos6::auth_activedir,
    $ad_domain     = $profile::base::centos6::auth_ad_domain,
    $ad_domain_nb  = $profile::base::centos6::auth_ad_domain_nb,
    $ad_servers    = $profile::base::centos6::auth_ad_servers,
    $ad_group_dn   = $profile::base::centos6::auth_ad_group_dn,
    $ad_cache_cred = $profile::base::centos6::auth_ad_cache_cr,
    $ad_group      = $profile::base::centos6::auth_ad_group

  ) {

    $system_auth_local   = '/etc/pam.d/system-auth-local'  
    $password_auth_local = '/etc/pam.d/password-auth-local'  
    $system_auth_ac      = '/etc/pam.d/system-auth-ac'  
    $password_auth_ac    = '/etc/pam.d/password-auth-ac'  
    $su_file             = '/etc/pam.d/su'
    $logindefs_file      = '/etc/login.defs'
    $nsswitch_file       = '/etc/nsswitch.conf'
    $krb5_file           = '/etc/krb5.conf'
    $krb5_file_orig      = '/etc/.krb5.conf.orig'
    $smb_file            = '/etc/samba/smb.conf'
    $sssd_file           = '/etc/sssd/sssd.conf'
    $sssd_help           = '/etc/sssd/README'
    $mkhomedir_file      = '/etc/oddjobd.conf.d/oddjobd-mkhomedir.conf'
    $authconfig_file     = '/etc/sysconfig/authconfig'
    $deploy_marker       = '/etc/sssd/.deployed-by-puppet'

    $ad_domain_upcase   = upcase($ad_domain)

    # First install the custom SSSD control script
    file { "$scripts_dir/sssd-control.sh":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/sssd-control.sh'),
    }


    if $activedir=='yes' {

      ####################################
      ### Active Directory integration ###
      ####################################

      ## Install ##

	  $installpacks = [ 'sssd', 'krb5-workstation', 'samba-common',
                        'authconfig', 'oddjob-mkhomedir', 'openldap-clients' ]
      package { $installpacks: ensure => 'installed' }

      ## Configure ##

      # /etc/krb5.conf
      file { $krb5_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        require => Package['krb5-workstation'],
        content => template("profile/centos6$krb5_file.erb")
      }
      file { $krb5_file_orig:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        require => Package['krb5-workstation'],
        content => file("profile/centos6$krb5_file_orig")
      }

      # /etc/samba/smb.conf
      file { $smb_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        require => Package['samba-common'],
        content => template("profile/centos6$smb_file.erb")
      }

      # /etc/sssd/sssd.conf
      file { $sssd_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        require => Package['sssd'],
        notify  => Service['sssd'],
        content => template("profile/centos6$sssd_file.erb")
      }
      file { $sssd_help:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        require => Package['sssd'],
        content => file("profile/centos6$sssd_help")
      }
      file { $deploy_marker:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        require  => File[$sssd_file],
        content => file("profile/centos6$deploy_marker")
      }

      # /etc/oddjobd.conf.d/oddjobd-mkhomedir.conf
      file { $mkhomedir_file:
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0600',
        require => Package['oddjob-mkhomedir'],
        notify  => Service['oddjobd'],
        content => file("profile/centos6$mkhomedir_file")
      }

      ## Enable sssd via authconfig inside script ##

      exec { "$scripts_dir/sssd-control.sh enable":
        unless   => "grep 'USESSSD=yes' $authconfig_file",
        path     => ['/usr/sbin','/sbin','/bin'],
        provider => 'shell',
        require  => File[$sssd_file]
      }

      ## Sudoers ##

      file { '/etc/sudoers.d/sssd':
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0440',
        require => Package['sssd'],
        content => "%$ad_group  ALL=(ALL)       ALL"
      }

      ## Service ##

      service { 'messagebus':
        ensure  => 'running',
        enable  => true,
        require => Package['oddjob-mkhomedir']
      }
      service { 'oddjobd':
        ensure  => 'running',
        enable  => true,
        require => Service['messagebus']
      }
      service { 'sssd':
        ensure  => 'running',
        enable  => true,
        require => Package['sssd']
      }

    } else {

      ## Config reset ##

      # Disable sssd (Run only once and only after status change) 
      # Note: Script will also uninstall sssd, oddjob-mkhomedir,
      #       samba-common, sssd-common, oddjob, krb5-workstation,
      #       etc., and remove associated config files
      exec { "$scripts_dir/sssd-control.sh disable":
        onlyif  => "test -f $deploy_marker",
        path    => ['/usr/sbin','/usr/bin','/sbin','/bin'],
        provider => 'shell'
      }

      # Remove AD group from sudoers
      file { '/etc/sudoers.d/sssd': ensure  => 'absent' }

    }

    ###########################################
    ### Local Password and Account Policies ###
    ###########################################

    ## /etc/pam.d ##

    file { $system_auth_local:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$system_auth_local.erb")
    }
    file { $password_auth_local:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$password_auth_local.erb")
    }
    file { '/etc/pam.d/system-auth':
      ensure => 'link',
      target => $system_auth_local
    }
    file { '/etc/pam.d/password-auth':
      ensure => 'link',
      target => $password_auth_local
    }
    file_line { 'pam_su':
      path    => $su_file,
      line    => 'auth    required    pam_wheel.so use_uid',
      match   => '#*\s*auth\s*required\s*pam_wheel\.so\s*use_uid',
      replace => true
    }

    ## /etc/login.defs ##

    file { $logindefs_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$logindefs_file.erb")
    }

  }


  class puppet_agent (

    $puppetmaster = $::servername,
    $runinterval  = $profile::base::centos6::puppet_interval
  
  ) {
    
    # Only apply the template on agents, not on puppetmaster
    if $::fqdn != $::servername {
      file { '/etc/puppet/puppet.conf':
        ensure  => 'present',
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
        content => template("profile/centos6/etc/puppet/puppet.conf.erb")
      }
    } else {
      file_line { 'master_puppet.conf':
        path    => '/etc/puppet/puppet.conf',
        line    => "    runinterval       = $runinterval",
        match   => '\s*runinterval\s*=',
        replace => true
      }
    }
    service { 'puppet': enable  => true }

  }


  ###############################
  ## Custom class declarations ##
  ###############################
  include firstthingsfirst
  include ntpd
  include sysctld
  include networking
  include iptables_init
  include authentication
  include filesystems
  include file_permissions
  if $sshd_manage {
    include sshd
  }
  include clamav
  include postfix
  include miscellaneous
  include auditd
  include puppet_agent

}
