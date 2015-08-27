# == Class: profile::agent::ossec
#
#
class profile::agent::ossec {

  # Hiera lookups
  $ossec_server   = hiera('profile::agent::ossec::ossec_server')
  $config_profile = hiera('profile::agent::ossec::config_profile', '')
  $ar_repeat      = hiera('profile::agent::ossec::ar_repeat', '')

  # Other variables
  $atomic_latest      = '1.0-19'
  $puppet_scripts_dir = '/root/puppet_scripts'


  # Install
  class install (

    $atomic_version = $profile::agent::ossec::atomic_latest

  ) { 

    package { 'atomic-release':
      source   => "http://www6.atomicorp.com/channels/atomic/centos/6/x86_64/RPMS/atomic-release-$atomic_version.el6.art.noarch.rpm",
      ensure   => 'installed',
      provider => 'rpm'
    }

    yumrepo { 'atomic':
      includepkgs => 'ossec*',
      ensure      => 'present',
      gpgcheck    => 1,
      require     => Package['atomic-release']
    }

    package { 'ossec-hids-client':
      ensure  => 'installed',
      require => Yumrepo['atomic']
    }

  }


  # Configure
  class configure (

    $ossec_server   = $profile::agent::ossec::ossec_server,
    $config_profile = $profile::agent::ossec::config_profile,
    $ar_repeat      = $profile::agent::ossec::ar_repeat

  ) {

    $ossec_config = '/var/ossec/etc/ossec-agent.conf'
    file { $ossec_config:
      notify  => Service['ossec-hids'],
      owner   => 'root',
      group   => 'root',
      mode    => '0644',
      content => template("profile/centos6$ossec_config.erb"),
      require => Package['ossec-hids-client'],
    }
    file { '/var/ossec/etc/ossec.conf':
      ensure => 'link',
      target => $ossec_config
    }

  }

  # Service
  class service {

    service { 'ossec-hids':
      ensure  => 'running',
      enable  => true,
      require => Package['ossec-hids-client']
    }

  }


  include install
  include configure
  include service

}
