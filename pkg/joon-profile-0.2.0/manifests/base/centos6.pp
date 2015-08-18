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
  $timezone           = hiera('profile::base::timezone', 'UTC')
  $ntp_servers        = hiera('profile::base::ntp_servers')
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

  # Local variables
  $puppet_scripts_dir = '/root/puppet_scripts'


  # Some tools/utilities to install
  $packlist = [ 'epel-release', 'at', 'cronie-anacron', 'crontabs', 'ed', 'sed', 'screen', 'man', 'nano', 'srm', 'tcp_wrappers', 'vim-enhanced', 'wget', 'sysstat' ]
  package { $packlist: ensure => 'installed' }


  # Create puppet_scripts directory
  file { $puppet_scripts_dir:
    ensure => 'directory',
    owner  => 'root',
    group  => 'root',
    mode   => 750
  }


  # Set timezone
  class { '::timezone': timezone => $timezone }

  
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
  sysctl { 'net.bridge.bridge-nf-call-ip6tables': value => '0' }
  sysctl { 'net.bridge.bridge-nf-call-iptables': value => '0' }
  sysctl { 'net.bridge.bridge-nf-call-arptables': value => '0' }


  # Enabled/Disabled services
  service { 'ip6tables': ensure => 'stopped' }

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
    options => {
      'Port' => $sshd_port,
      'AddressFamily' => $sshd_addressfamily,
      'ListenAddress' => $sshd_listenaddress,
      'Protocol' => 2,
      'SyslogFacility' => 'AUTHPRIV',
      'LogLevel' => 'INFO',
      'LoginGraceTime' => '2m',
      'PermitRootLogin' => 'no',
      'StrictModes' => 'yes',
      'MaxAuthTries' => 5,
      'MaxSessions' => 10,
      'RSAAuthentication' => 'yes',
      'PubkeyAuthentication' => $sshd_pubkeyauth,
      'RhostsRSAAuthentication' => 'no',
      'HostbasedAuthentication' => 'no',
      'IgnoreRhosts' => 'yes',
      'PasswordAuthentication' => $sshd_passwordauth,
      'PermitEmptyPasswords' => 'no',
      'ChallengeResponseAuthentication' => 'no',
      'GSSAPIAuthentication' => 'yes',
      'GSSAPICleanupCredentials' => 'yes',
      'UsePAM' => $sshd_usepam,
      'AcceptEnv' => [
        'LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES',
        'LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT',
        'LC_IDENTIFICATION LC_ALL LANGUAGE',
        'XMODIFIERS'
      ],
      'AllowTcpForwarding' => $sshd_tcpforwarding,
      'X11Forwarding' => 'no',
      'TCPKeepAlive' => 'yes',
      'UsePrivilegeSeparation' => 'yes',
      'PermitUserEnvironment' => 'no',
      'Compression' => 'delayed',
      'ClientAliveInterval' => '900',
      'ClientAliveCountMax' => '0',
      'ShowPatchLevel' => 'no',
      'UseDNS' => $sshd_usedns,
      'PermitTunnel' => 'no',
      'ChrootDirectory' => 'none',
      'Banner' => '/etc/issue.net',
      'Subsystem' => 'sftp /usr/libexec/openssh/sftp-server',
      'Ciphers' => 'aes192-ctr,aes256-ctr,aes128-ctr',
      'MACs' => 'hmac-sha2-256,hmac-sha2-512,hmac-sha1',
      'AllowGroups' => $sshd_allowgroups
    }
    
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
      content => template('profile/etc/postfix/main.cf.erb')
    }
  }

  class auditd {
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
      content => template('profile/etc/audit/auditd.conf.erb')
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
      content => template('profile/etc/audit/rules.d/audit.rules.erb')
    }
   # 2nd rules.d entry (cis01.rules)
    file { '/root/puppet_scripts/audit_rules_custom.sh':
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/puppet_scripts/audit_rules_custom.sh')
    }
    exec { '/root/puppet_scripts/audit_rules_custom.sh':
      cwd     => "/root",
      creates => "/etc/audit/rules.d/cis01.rules",
      path    => ["/bin"]
    }
   # 3rd and last rules.d entry (cis02.rules)
    file { '/etc/audit/rules.d/cis02.rules':
      notify  => Service['auditd'],
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      require => Package['audit'],
      content => template('profile/etc/audit/rules.d/cis02.rules.erb')
    }
  }

  class nowireless {
    file { '/root/puppet_scripts/disable_wireless.sh':
      owner   => 'root',
      group   => 'root',
      mode    => '0750',
      content => file('profile/puppet_scripts/disable_wireless.sh')
    }
    exec { '/root/puppet_scripts/disable_wireless.sh':
      cwd     => "/root",
      creates => "/etc/modprobe.d/blacklist-wireless.conf",
      path    => ["/bin"]
    }
  }

  class tcp_wrappers {
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

  # Custom class includes
  include tcp_wrappers
  include nowireless
  include postfix
  include auditd

}
