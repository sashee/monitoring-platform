# The test network's time source.
#
# Every VM test needs one: the §9.4 boot gate refuses to start the service until the
# kernel's `maxerror` estimate drops below the threshold, and a machine with no time
# source sits at the kernel's 16 s unsynchronized ceiling forever. Rather than switch the
# gate off for testing — which would leave the production configuration unexercised — the
# harness gives the machine under test something real to synchronize against.
#
# Its own node because chrony, ntpd and openntpd all disable systemd-timesyncd: a real
# NTP daemon cannot sit next to the timesyncd client it is meant to serve.
#
# `nts` turns this into a real NTS server rather than a plain one. ./lib.nix passes it
# when the machine under test runs chrony with NTS, so that machine's own configuration —
# its real server names, over NTS-KE, validating a real certificate — runs unmodified
# against this node. Only name resolution and the trust anchor are swapped.
#
# The clock-gate case layers a module on top that holds chronyd down at boot, which is how
# it gets a genuine "no working NTP" state to assert against.
{
  hostName ? "ntp-server",
  # Taken as an argument rather than defaulted internally so it cannot drift from the
  # machine under test's; ./default.nix threads the consumer's through ./lib.nix.
  stateVersion ? null,
  # null, or { certFile, keyFile } from ./test-cert.nix.
  nts ? null,
  # Extra addresses to answer on, one per server name the machine under test dials. See
  # aliasAddressesFor in ./lib.nix for why one address for all of them does not work.
  extraAddresses ? [ ],
}:
{ config, lib, ... }:
{
  networking.hostName = hostName;

  # Aliases on this node's vlan interface, not extra nodes: chronyd already binds every
  # address and `allow all` below answers on all of them, so one daemon serves every name.
  # The framework's own address for the node merges with these rather than being replaced —
  # networking.interfaces is a plain definition and ipv4.addresses is a list.
  networking.interfaces.eth1.ipv4.addresses = map (address: {
    inherit address;
    prefixLength = 24;
  }) extraAddresses;

  # eth1 is the vlan-1 interface the test framework assigns at the default
  # `virtualisation.vlans = [ 1 ]`. If this node is ever put on other links the aliases
  # would land on the wrong one and every name would resolve to an address nothing answers
  # on, which surfaces as an opaque clock-gate timeout — so say so here instead.
  assertions = lib.optional (extraAddresses != [ ]) {
    assertion = config.virtualisation.vlans == [ 1 ] && config.virtualisation.interfaces == { };
    message =
      "monitoring-platform test harness: nix/tests/ntp-node.nix puts one alias address per "
      + "chrony server name on eth1, which is only the vlan-1 interface while this node "
      + "keeps the framework's default networking. It has vlans="
      + "${builtins.toJSON config.virtualisation.vlans} and interfaces="
      + "${builtins.toJSON (lib.attrNames config.virtualisation.interfaces)}. Point "
      + "extraAddresses at the right interface in nix/tests/ntp-node.nix.";
  };
  networking.firewall.allowedUDPPorts = [ 123 ];
  # NTS-KE. Only open when there is a certificate to serve — chronyd opens the port only
  # once ntsservercert/ntsserverkey are set.
  networking.firewall.allowedTCPPorts = lib.optional (nts != null) 4460;
  # Helper node, tiny workload: keeps the two-VM run affordable under aarch64 TCG.
  virtualisation.memorySize = 512;

  services.chrony = {
    enable = true;
    # An island: there is no upstream to reach.
    servers = [ ];
    # No server lines to decorate with `nts` — this is set purely because the nixpkgs
    # module derives `ntsdumpdir` from it, which chronyd wants for serving NTS.
    enableNTS = nts != null;
    extraConfig = ''
      # `local` is what makes chronyd offer its own clock as a valid reference, rather
      # than refusing to answer until it has synchronized with someone else.
      local stratum 10
      allow all
    ''
    + lib.optionalString (nts != null) ''
      ntsservercert ${nts.certFile}
      ntsserverkey ${nts.keyFile}
    '';
  };

  # Nothing on this node talks to the receiver, so it needs none of the harness's clients.
  system.stateVersion = if stateVersion == null then lib.trivial.release else stateVersion;
}
