# == Class: profile::base::centos6
#
# CentOS base install. Configured according to CIS standards.
#
# === Parameters
#
# Document parameters here.
#
# [*sample_parameter*]
#   Explanation of what this parameter affects and what it defaults to.
#   e.g. "Specify one or more upstream ntp servers as an array."
#
# === Variables
#
# Here you should define a list of variables that this module would require.
#
# [*sample_variable*]
#   Explanation of how this variable affects the funtion of this class and if
#   it has a default. e.g. "The parameter enc_ntp_servers must be set by the
#   External Node Classifier as a comma separated list of hostnames." (Note,
#   global variables should be avoided in favor of class parameters as
#   of Puppet 2.6.)
#
# === Examples
#
#  class { 'profile':
#    servers => [ 'pool.ntp.org', 'ntp.local.company.com' ],
#  }
#
# === Authors
#
# Joon <joon@modulogeek.com>
#
# === Copyright
#
# Copyright 2015 Joon Guillen, unless otherwise noted.
#

class profile::base::centos6 {

  # Hiera lookups
  $ntp_servers        = hiera('profile::base::ntp_servers')
  $timezone           = hiera('profile::base::timezone')
  $proxy_server       = hiera('profile::base::proxy_server', '')
  $proxy_port         = hiera('profile::base::proxy_port', '')
  $ntp_interfaces     = hiera('profile::base::centos6::ntp_interfaces')
  $postfix_relayhost  = hiera('profile::base::centos6::postfix_relayhost', [])
  $sysctl_ipv4forward = hiera('profile::base::centos6::sysctl_ipv4forward', '0')
  $sshd_port          = hiera('profile::base::centos6:sshd_port', 22)
  $sshd_addressfamily = hiera('profile::base::centos6:sshd_addressfamily', 'any')
  $sshd_listenaddress = hiera('profile::base::centos6:sshd_listenaddress', [ '0.0.0.0' ])
  $sshd_pubkeyauth    = hiera('profile::base::centos6:sshd_pubkeyauth', 'yes')
  $sshd_passwordauth  = hiera('profile::base::centos6:sshd_passwordauth', 'yes')
  $sshd_usepam        = hiera('profile::base::centos6:sshd_usepam', 'yes')
  $sshd_tcpforwarding = hiera('profile::base::centos6:sshd_tcpforwarding', 'no')
  $sshd_allowgroups   = hiera('profile::base::centos6:sshd_allowgroups', 'wheel')
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
  $puppet_interval    = hiera('profile::base::puppet_interval', '30m' )


  # Local variables
  $puppet_scripts_dir = '/root/puppet_scripts'


  # Create puppet_scripts directory
  file { $puppet_scripts_dir:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => '0750'
  }


  # Some tools/utilities to install
  $packlist = [
    'epel-release','at','cronie-anacron','crontabs',
    'curl','ed','sed','screen','man','nano','srm',
    'tcp_wrappers','tree','vim-enhanced','wget','sysstat'
  ]
  package { $packlist: ensure => 'installed' }

  
  # Sysctl parameters
  file { '/etc/sysctl.conf': ensure => 'absent' }  # Remove sysctl.conf; we will use sysctl.d instead
  class { '::sysctl::base': purge => true }        # Purge original contents of systcl.d (if any)

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

  sysctl { 'net.ipv4.ip_forward': value => $sysctl_ipv4forward }
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


  # Sudoers
  file_line { 'sudo_wheel':
    path    => '/etc/sudoers',
    line    => '%wheel  ALL=(ALL)       ALL',
    match   => '#?\s?%wheel\s+ALL=\(ALL\)\s+ALL',
    replace => true
  }


  ######################
  ## Detailed configs ##
  ######################

  class { '::ntp':
    package_manage => true,
    package_ensure => 'latest',
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
      'AllowGroups'                     => $sshd_allowgroups
    }
    
  }

  class { '::selinux':
    mode => 'enforcing'
  }


  ####################
  ## Custom classes ##
  ####################


  class postfix (
    $inet_protocols = 'ipv4',
    $relayhost = $profile::base::centos6::postfix_relayhost
  ) {
    package { 'postfix': ensure => 'latest' }
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


  class auditd ($puppet_scripts_dir = '/root/puppet_scripts') {
    package { 'audit': ensure => 'latest' }
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


  class iptables_init ($puppet_scripts_dir = '/root/puppet_scripts') {

    file { "$puppet_scripts_dir/iptables_init.sh":
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/centos6/puppet_scripts/iptables_init.sh')
    }
    exec { "$puppet_scripts_dir/iptables_init.sh":
      onlyif   => "! /bin/grep '\-A INPUT \-j DROP' /etc/sysconfig/iptables",
      path     => ['/bin'],
      provider => 'shell'
    }

  }


  class networking ($puppet_scripts_dir = '/root/puppet_scripts') {
  
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
    service { 'ip6tables': ensure => 'stopped' }

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

  class miscellaneous (

    $tz = $profile::base::centos6::timezone

  ) {
    
    # Set timezone
    class { '::timezone': timezone => $tz }

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
      content => file('profile/centos6/etc/issue')
    }
    file { "/etc/issue.net":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/issue.net')
    }

    # Restrict core dumps
    file { "/etc/security/limits.d/00-coredumps.conf":
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file('profile/centos6/etc/security/limits.d/00-coredumps.conf')
    }

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
    selinux::boolean { 'antivirus_can_scan_system': ensure => 'on' }
    selinux::boolean { 'antivirus_use_jit': ensure => 'on' }
    
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

    $login_retry   = $profile::base::centos6::login_retry,
    $pw_minlen     = $profile::base::centos6::login_pw_minlen,
    $pw_minclass   = $profile::base::centos6::login_pw_minclass,
    $pw_remember   = $profile::base::centos6::login_pw_remember,
    $pw_maxdays    = $profile::base::centos6::login_pw_maxdays,
    $pw_mindays    = $profile::base::centos6::login_pw_mindays,
    $pw_warnage    = $profile::base::centos6::login_pw_warnage,
    $lo_attempts   = $profile::base::centos6::login_lo_attempts,
    $lo_unlocktime = $profile::base::centos6::login_lo_unlocksec

  ) {

    $system_auth_file   = '/etc/pam.d/system-auth-local'  
    $password_auth_file = '/etc/pam.d/password-auth-local'  
    $su_file            = '/etc/pam.d/su'
    $logindefs_file     = '/etc/login.defs'
    $securetty_file     = '/etc/securetty'
    $profile_file       = '/etc/profile'

    # /etc/pam.d
    file { $system_auth_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$system_auth_file.erb")
    }
    file { $password_auth_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$password_auth_file.erb")
    }
    file { '/etc/pam.d/system-auth':
      ensure => 'link',
      target => $system_auth_file
    }
    file { '/etc/pam.d/password-auth':
      ensure => 'link',
      target => $password_auth_file
    }
    file_line { 'pam_su':
      path    => $su_file,
      line    => 'auth    required    pam_wheel.so use_uid',
      match   => '#*\s*auth\s*required\s*pam_wheel\.so\s*use_uid',
      replace => true
    }

    # /etc/login.defs
    file { $logindefs_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$logindefs_file.erb")
    }

    # /etc/securetty
    file { $securetty_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => file("profile/centos6$securetty_file")
    }

    # /etc/profile
    file { $profile_file:
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => file("profile/centos6$profile_file")
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


  # Custom class includes
  include miscellaneous
  include networking
  include iptables_init
  include filesystems
  include authentication
  include file_permissions
  include postfix
  include clamav
  include auditd
  include puppet_agent

}
