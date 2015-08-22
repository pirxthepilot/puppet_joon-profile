# == Class: profile::agent::checkmk
#
#
class profile::agent::checkmk {

  # Hiera lookups
  $nagios_server = hiera('profile::agent::checkmk::nagios_server')

  # Other variables
  $bind_address  = $::ipaddress_eth0
  $puppet_scripts_dir = '/root/puppet_scripts'

  # Install
  package { [ 'check-mk-agent', 'xinetd' ]: ensure => 'latest' }

  # Configure
  file { '/etc/xinetd.d/check-mk-agent':
    notify  => Service['xinetd'],
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('profile/centos6/etc/xinetd.d/check-mk-agent.erb'),
    require => Package['check-mk-agent'],
  }

  file_line { 'checkmk-hostsallow':
    path    => '/etc/hosts.allow',
    line    => 'check_mk_agent : ALL',
    match   => '#\s*check_mk_agent\s*:\s*ALL',
    replace => true
  }

  # Service
  service { 'xinetd':
    ensure  => 'running',
    enable  => true,
    require => Package['xinetd']
  }

  # IPtables
  file { '/root/puppet_scripts/puppet_custom_iptables.sh':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0750',
    content => file('profile/centos6/puppet_scripts/puppet_custom_iptables.sh'),
  }
  exec { "$puppet_scripts_dir/puppet_custom_iptables.sh update $nagios_server tcp 6556":
    unless   => "/bin/grep \"\-s $nagios_server.*\-\-dport 6556 \-j ACCEPT\" /etc/sysconfig/iptables",
    path     => ['/bin', '/sbin'],
    provider => 'shell'
  }

}
