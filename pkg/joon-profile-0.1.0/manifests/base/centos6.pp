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

  # Hiera - required parameters
  $ntp_servers       = hiera('profile::base::ntp_servers')
  $ntp_interfaces    = hiera('profile::base::centos6::ntp_interfaces')
  $postfix_relayhost = hiera('profile::base::centos6::postfix_relayhost', [])

  # Hiera - optional parameters
  #profile::base::centos6::postfix_relayhost: (Array type)


  # Some tools/utilities to install
  $packlist = [ 'epel-release', 'at', 'cronie-anacron', 'crontabs', 'ed', 'sed', 'screen', 'man', 'nano', 'srm', 'tcp_wrappers', 'vim-enhanced', 'wget', 'sysstat' ]
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
  
  sysctl { 'net.ipv6.conf.all.disable_ipv6': value => '1' }
  sysctl { 'net.ipv6.conf.default.disable_ipv6': value => '1' }
  sysctl { 'net.ipv6.conf.all.accept_ra': value => '0' }
  sysctl { 'net.ipv6.conf.default.accept_ra': value => '0' }
  sysctl { 'net.ipv6.conf.all.accept_redirects': value => '0' }
  sysctl { 'net.ipv6.conf.default.accept_redirects': value => '0' }

  sysctl { 'net.ipv4.ip_forward': value => '0' }
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

  # Detailed configs
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

  class postfix (
    $inet_protocols = 'ipv4',
    $relayhost = $profile::base::centos6::postfix_relayhost
    #$relayhost = []
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
  include postfix


}
