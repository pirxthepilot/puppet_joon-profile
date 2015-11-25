# == Class: profile::agent::checkmk
#
# Installs the check_mk agent and configures it
# to point to the correct Nagios server
#
class profile::agent::checkmk {

  # Hiera lookups
  $nagios_server = hiera('profile::agent::checkmk::nagios_server')
  $bind_ip       = hiera('profile::agent::checkmk::bind_ip', 0)

  # Other variables
  $puppet_scripts_dir = '/root/puppet_scripts'

  if $bind_ip==0 {
    $bind_address = $::ipaddress_eth0
  } else {
    $bind_address = $bind_ip
  }

  # Install
  package { [ 'check-mk-agent', 'xinetd' ]: ensure => 'installed' }

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
  exec { "$puppet_scripts_dir/puppet_custom_iptables.sh update $nagios_server tcp 6556":
    unless   => "/bin/grep -- \"-s $nagios_server/32.*--dport 6556 -j ACCEPT\" /etc/sysconfig/iptables",
    path     => ['/bin'],
    provider => 'shell'
  }

}
