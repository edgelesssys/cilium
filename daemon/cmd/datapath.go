// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	k8sLabels "k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	ippkg "github.com/cilium/cilium/pkg/ip"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/maps/strictmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/maps/worldcidrsmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// LocalConfig returns the local configuration of the daemon's nodediscovery.
func (d *Daemon) LocalConfig() *datapath.LocalNodeConfiguration {
	d.nodeDiscovery.WaitForLocalNodeInit()
	return &d.nodeDiscovery.LocalConfig
}

// listFilterIfs returns a map of interfaces based on the given filter.
// The filter should take a link and, if found, return the index of that
// interface, if not found return -1.
func listFilterIfs(filter func(netlink.Link) int) (map[int]netlink.Link, error) {
	ifs, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	vethLXCIdxs := map[int]netlink.Link{}
	for _, intf := range ifs {
		if idx := filter(intf); idx != -1 {
			vethLXCIdxs[idx] = intf
		}
	}
	return vethLXCIdxs, nil
}

// clearCiliumVeths checks all veths created by cilium and removes all that
// are considered a leftover from failed attempts to connect the container.
func clearCiliumVeths() error {
	log.Info("Removing stale endpoint interfaces")

	leftVeths, err := listFilterIfs(func(intf netlink.Link) int {
		// Filter by veth and return the index of the interface.
		if intf.Type() == "veth" {
			return intf.Attrs().Index
		}
		return -1
	})
	if err != nil {
		return fmt.Errorf("unable to retrieve host network interfaces: %w", err)
	}

	for _, v := range leftVeths {
		peerIndex := v.Attrs().ParentIndex
		parentVeth, found := leftVeths[peerIndex]

		// In addition to name matching, double check whether the parent of the
		// parent is the interface itself, to avoid removing the interface in
		// case we hit an index clash, and the actual parent of the interface is
		// in a different network namespace. Notably, this can happen in the
		// context of Kind nodes, as eth0 is a veth interface itself; if an
		// lxcxxxxxx interface ends up having the same ifindex of the eth0 parent
		// (which is actually located in the root network namespace), we would
		// otherwise end up deleting the eth0 interface, with the obvious
		// ill-fated consequences.
		if found && peerIndex != 0 && strings.HasPrefix(parentVeth.Attrs().Name, "lxc") &&
			parentVeth.Attrs().ParentIndex == v.Attrs().Index {
			scopedlog := log.WithFields(logrus.Fields{
				logfields.Device: v.Attrs().Name,
			})

			scopedlog.Debug("Deleting stale veth device")
			err := netlink.LinkDel(v)
			if err != nil {
				scopedlog.WithError(err).Warning("Unable to delete stale veth device")
			}
		}
	}
	return nil
}

// SetPrefilter sets the preftiler for the given daemon.
func (d *Daemon) SetPrefilter(preFilter datapath.PreFilter) {
	d.preFilter = preFilter
}

// EndpointMapManager is a wrapper around an endpointmanager as well as the
// filesystem for removing maps related to endpoints from the filesystem.
type EndpointMapManager struct {
	endpointmanager.EndpointManager
}

// RemoveDatapathMapping unlinks the endpointID from the global policy map, preventing
// packets that arrive on this node from being forwarded to the endpoint that
// used to exist with the specified ID.
func (e *EndpointMapManager) RemoveDatapathMapping(endpointID uint16) error {
	return policymap.RemoveGlobalMapping(uint32(endpointID), option.Config.EnableEnvoyConfig)
}

// RemoveMapPath removes the specified path from the filesystem.
func (e *EndpointMapManager) RemoveMapPath(path string) {
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).WithField(logfields.Path, path).Warn("Error while deleting stale map file")
	} else {
		log.WithField(logfields.Path, path).Info("Removed stale bpf map")
	}
}

// syncHostIPs adds local host entries to bpf lxcmap, as well as ipcache, if
// needed, and also notifies the daemon and network policy hosts cache if
// changes were made.
func (d *Daemon) syncHostIPs() error {
	if option.Config.DryMode {
		return nil
	}

	type ipIDLabel struct {
		identity.IPIdentityPair
		labels.Labels
	}
	specialIdentities := make([]ipIDLabel, 0, 2)

	if option.Config.EnableIPv4 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv4().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv4 addresses")
		}

		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities, ipIDLabel{
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					},
					labels.LabelHost,
				})
			}
		}

		ipv4Ident := identity.ReservedIdentityWorldIPv4
		ipv4Label := labels.LabelWorldIPv4
		if !option.Config.EnableIPv6 {
			ipv4Ident = identity.ReservedIdentityWorld
			ipv4Label = labels.LabelWorld
		}
		specialIdentities = append(specialIdentities, ipIDLabel{
			identity.IPIdentityPair{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, net.IPv4len*8),
				ID:   ipv4Ident,
			},
			ipv4Label,
		})
	}

	if option.Config.EnableIPv6 {
		addrs, err := d.datapath.LocalNodeAddressing().IPv6().LocalAddresses()
		if err != nil {
			log.WithError(err).Warning("Unable to list local IPv6 addresses")
		}

		addrs = append(addrs, node.GetIPv6Router())
		for _, ip := range addrs {
			if option.Config.IsExcludedLocalAddress(ip) {
				continue
			}

			if len(ip) > 0 {
				specialIdentities = append(specialIdentities, ipIDLabel{
					identity.IPIdentityPair{
						IP: ip,
						ID: identity.ReservedIdentityHost,
					},
					labels.LabelHost,
				})
			}
		}

		ipv6Ident := identity.ReservedIdentityWorldIPv6
		ipv6Label := labels.LabelWorldIPv6
		if !option.Config.EnableIPv4 {
			ipv6Ident = identity.ReservedIdentityWorld
			ipv6Label = labels.LabelWorld
		}
		specialIdentities = append(specialIdentities, ipIDLabel{
			identity.IPIdentityPair{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, net.IPv6len*8),
				ID:   ipv6Ident,
			},
			ipv6Label,
		})
	}

	existingEndpoints, err := lxcmap.DumpToMap()
	if err != nil {
		return err
	}

	daemonResourceID := ipcachetypes.NewResourceID(ipcachetypes.ResourceKindDaemon, "", "reserved")
	for _, ipIDLblsPair := range specialIdentities {
		isHost := ipIDLblsPair.ID == identity.ReservedIdentityHost
		if isHost {
			added, err := lxcmap.SyncHostEntry(ipIDLblsPair.IP)
			if err != nil {
				return fmt.Errorf("Unable to add host entry to endpoint map: %w", err)
			}
			if added {
				log.WithField(logfields.IPAddr, ipIDLblsPair.IP).Debugf("Added local ip to endpoint map")
			}
		}

		delete(existingEndpoints, ipIDLblsPair.IP.String())

		lbls := ipIDLblsPair.Labels
		if ipIDLblsPair.ID.IsWorld() {
			p := netip.PrefixFrom(ippkg.MustAddrFromIP(ipIDLblsPair.IP), 0)
			d.ipcache.OverrideIdentity(p, lbls, source.Local, daemonResourceID)
		} else {
			d.ipcache.UpsertLabels(ippkg.IPToNetPrefix(ipIDLblsPair.IP),
				lbls,
				source.Local, daemonResourceID,
			)
		}
	}

	// existingEndpoints is a map from endpoint IP to endpoint info. Referring
	// to the key as host IP here because we only care about the host endpoint.
	for hostIP, info := range existingEndpoints {
		if ip := net.ParseIP(hostIP); info.IsHost() && ip != nil {
			if err := lxcmap.DeleteEntry(ip); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr: hostIP,
				}).Warn("Unable to delete obsolete host IP from BPF map")
			} else {
				log.Debugf("Removed outdated host IP %s from endpoint map", hostIP)
			}

			d.ipcache.RemoveLabels(ippkg.IPToNetPrefix(ip), labels.LabelHost, daemonResourceID)
		}
	}

	// we have a reference to all ifindex values, so we update the related metric
	maxIfindex := uint32(0)
	for _, endpoint := range existingEndpoints {
		if endpoint.IfIndex > maxIfindex {
			maxIfindex = endpoint.IfIndex
		}
	}
	metrics.EndpointMaxIfindex.Set(float64(maxIfindex))

	if option.Config.EnableVTEP {
		err := setupVTEPMapping()
		if err != nil {
			return err
		}
		err = setupRouteToVtepCidr()
		if err != nil {
			return err
		}
	}

	return nil
}

// initMaps opens all BPF maps (and creates them if they do not exist). This
// must be done *before* any operations which read BPF maps, especially
// restoring endpoints and services.
func (d *Daemon) initMaps() error {
	if option.Config.DryMode {
		return nil
	}

	if err := lxcmap.LXCMap().OpenOrCreate(); err != nil {
		return fmt.Errorf("initializing lxc map: %w", err)
	}

	// The ipcache is shared between endpoints. Unpin the old ipcache map created
	// by any previous instances of the agent to prevent new endpoints from
	// picking up the old map pin. The old ipcache will continue to be used by
	// loaded bpf programs, it will just no longer be updated by the agent.
	//
	// This is to allow existing endpoints that have not been regenerated yet to
	// continue using the existing ipcache until the endpoint is regenerated for
	// the first time and its bpf programs have been replaced. Existing endpoints
	// are using a policy map which is potentially out of sync as local identities
	// are re-allocated on startup.
	if err := ipcachemap.IPCacheMap().Recreate(); err != nil {
		return fmt.Errorf("initializing ipcache map: %w", err)
	}

	if err := metricsmap.Metrics.OpenOrCreate(); err != nil {
		return fmt.Errorf("initializing metrics map: %w", err)
	}

	if option.Config.TunnelingEnabled() {
		if err := tunnel.TunnelMap().Recreate(); err != nil {
			return fmt.Errorf("initializing tunnel map: %w", err)
		}
	}

	if option.Config.EnableSRv6 {
		srv6map.CreateMaps()
	}

	if option.Config.EnableHighScaleIPcache {
		if err := worldcidrsmap.InitWorldCIDRsMap(); err != nil {
			return fmt.Errorf("initializing world CIDRs map: %w", err)
		}
	}

	if option.Config.EnableVTEP {
		if err := vtep.VtepMap().Recreate(); err != nil {
			return fmt.Errorf("initializing vtep map: %w", err)
		}
	}

	if err := d.svc.InitMaps(option.Config.EnableIPv6, option.Config.EnableIPv4,
		option.Config.EnableSocketLB, option.Config.RestoreState); err != nil {
		log.WithError(err).Fatal("Unable to initialize service maps")
	}

	if err := policymap.InitCallMaps(option.Config.EnableEnvoyConfig); err != nil {
		return fmt.Errorf("initializing policy map: %w", err)
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		ep.InitMap()
	}

	for _, ep := range d.endpointManager.GetEndpoints() {
		if !ep.ConntrackLocal() {
			continue
		}
		for _, m := range ctmap.LocalMaps(ep, option.Config.EnableIPv4,
			option.Config.EnableIPv6) {
			if err := m.Create(); err != nil {
				return fmt.Errorf("initializing conntrack map %s: %w", m.Name(), err)
			}
		}
	}
	for _, m := range ctmap.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6) {
		if err := m.Create(); err != nil {
			return fmt.Errorf("initializing conntrack map %s: %w", m.Name(), err)
		}
	}

	ipv4Nat, ipv6Nat := nat.GlobalMaps(option.Config.EnableIPv4,
		option.Config.EnableIPv6, option.Config.EnableNodePort)
	if ipv4Nat != nil {
		if err := ipv4Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv4nat map: %w", err)
		}
	}
	if ipv6Nat != nil {
		if err := ipv6Nat.Create(); err != nil {
			return fmt.Errorf("initializing ipv6nat map: %w", err)
		}
	}

	if option.Config.EnableNodePort {
		if err := neighborsmap.InitMaps(option.Config.EnableIPv4,
			option.Config.EnableIPv6); err != nil {
			return fmt.Errorf("initializing neighbors map: %w", err)
		}
	}

	if option.Config.EnableIPv4FragmentsTracking {
		if err := fragmap.InitMap(option.Config.FragmentsMapEntries); err != nil {
			return fmt.Errorf("initializing fragments map: %w", err)
		}
	}

	if option.Config.EnableIPMasqAgent {
		if option.Config.EnableIPv4Masquerade {
			if err := ipmasq.IPMasq4Map().OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing IPv4 masquerading map: %w", err)
			}
		}
		if option.Config.EnableIPv6Masquerade {
			if err := ipmasq.IPMasq6Map().OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing IPv6 masquerading map: %w", err)
			}
		}
	}

	if !option.Config.RestoreState {
		// If we are not restoring state, all endpoints can be
		// deleted. Entries will be re-populated.
		lxcmap.LXCMap().DeleteAll()
	}

	if option.Config.EnableSessionAffinity {
		if err := lbmap.AffinityMatchMap.OpenOrCreate(); err != nil {
			return fmt.Errorf("initializing affinity match map: %w", err)
		}
		if option.Config.EnableIPv4 {
			if err := lbmap.Affinity4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := lbmap.Affinity6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v6 map: %w", err)
			}
		}
	}

	if option.Config.EnableSVCSourceRangeCheck {
		if option.Config.EnableIPv4 {
			if err := lbmap.SourceRange4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := lbmap.SourceRange6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v6 map: %w", err)
			}
		}
	}

	if option.Config.NodePortAlg == option.NodePortAlgMaglev {
		if err := lbmap.InitMaglevMaps(option.Config.EnableIPv4, option.Config.EnableIPv6, uint32(option.Config.MaglevTableSize)); err != nil {
			return fmt.Errorf("initializing maglev maps: %w", err)
		}
	}

	return nil
}

func setupStrictModeMap(lns *node.LocalNodeStore) error {
	if err := strictmap.Create(); err != nil {
		return fmt.Errorf("initializing strict mode map: %w", err)
	}

	strictCIDRs := append(option.Config.EncryptionStrictModeNodeCIDRs, option.Config.EncryptionStrictModePodCIDRs...)
	for _, cidr := range strictCIDRs {

		ipv4Interface, ok := netip.AddrFromSlice(node.GetIPv4().To4())
		if !ok {
			return fmt.Errorf("unable to parse node IPv4 address %s", node.GetIPv4())
		}
		if cidr.Contains(ipv4Interface) && !option.Config.NodeEncryptionEnabled() {
			if !option.Config.EncryptionStrictModeAllowRemoteNodeIdentities {
				return fmt.Errorf(`encryption strict mode is enabled but the node's IPv4 address is within the strict CIDR range.
				This will cause the node to drop all traffic.
				Please either disable encryption or set --encryption-strict-mode-allow-dynamic-lookup=true`)
			}
		}

		if err := strictmap.UpdateContext(cidr, 0, 0, 0, 0); err != nil {
			return fmt.Errorf("updating strict mode map: %w", err)
		}
	}

	// Add the default match to the trie map.
	// If this prefix is matched, then the packet is allowed to pass unencrypted as indicated by the "1" as a value.
	if err := strictmap.UpdateContext(netip.MustParsePrefix("0.0.0.0/0"), 0, 1, 0, 0); err != nil {
		return fmt.Errorf("updating strict mode map: %w", err)
	}

	// Allow etcd ports only on control plane nodes
	sel, err := k8sLabels.Parse("node-role.kubernetes.io/control-plane")
	if err != nil {
		return fmt.Errorf("unable to parse control plane label selector: %w", err)
	}

	allowEtcd := func() {
		for i := 0; i < 10; i++ {
			localNode, err := lns.Get(context.Background())
			if err != nil {
				log.WithError(err).Error("unable to get local node")
			}
			log.Debugf("local node labels: %v", localNode.Labels)
			if sel.Matches(k8sLabels.Set(localNode.Labels)) {
				for _, nodeCIDR := range option.Config.EncryptionStrictModeNodeCIDRs {
					if err := strictmap.UpdateContext(nodeCIDR, 0, 0, 2379, 2380); err != nil {
						log.WithError(err).Fatal("updating strict mode map: %w", err)
					}
				}
				log.Infoln("Added etcd ports to strict mode map")
				return
			}
			time.Sleep(2 * time.Second)
		}
		log.Infoln("Didn't add etcd ports to strict mode map")
	}
	go allowEtcd()

	return nil
}

// This is a fix for the performance degradation when enabling WireGuard node
// encryption. See (2.) in https://github.com/cilium/cilium/issues/28413#issuecomment-1898943563
// Strictly speaking, we don't need to exectue this when WireGuard node encryption
// is not enabled. We stay on the safe side regarding the MSS value, since
// the RouteMTU also includes the tunneling overhead which does not affect
// node to node communication.
func setMSSForNodeCIDR(lns *node.LocalNodeStore, routeMTU int) {
	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(10 * time.Second)

			ln, err := lns.Get(context.Background())
			if err != nil {
				log.WithError(err).Error("unable to get local node")
				continue
			}
			if len(ln.GetNodeInternalIPv4().String()) == 0 {
				log.Infof("Waiting for node IP to be assigned: %s\n", ln.GetNodeInternalIPv4().String())
				continue
			}
			cmd := exec.CommandContext(context.Background(), "ip", "route", "show", "match", ln.GetNodeInternalIPv4().String())
			out, err := cmd.CombinedOutput()
			if err != nil {
				log.WithError(err).WithField("output", string(out)).Error("unable to find route")
				continue
			}
			lines := strings.Split(string(out), "\n")
			nonDefaultRoutes := []string{}
			defaultRoute := ""
			for _, line := range lines {
				if !strings.Contains(line, "default") && strings.Contains(line, "dev") {
					nonDefaultRoutes = append(nonDefaultRoutes, line)
				} else if strings.Contains(line, "default") && strings.Contains(line, "dev") {
					defaultRoute = line
				}
			}

			for _, route := range nonDefaultRoutes {
				args := []string{"route", "replace"}
				args = append(args, strings.Split(strings.TrimSpace(route), " ")...)
				args = append(args, "advmss", fmt.Sprintf("%d", routeMTU-40))
				cmd := exec.CommandContext(context.Background(), "ip", args...)
				if out, err := cmd.CombinedOutput(); err != nil {
					log.WithError(err).WithField("output", string(out)).Error("unable to add route")
					continue
				}
			}

			// GCP does not have any nodeCIDR specific route.
			// Since we don't want to override the default route, we create one
			// ourselves.
			if len(nonDefaultRoutes) == 0 {
				// "default via 192.168.178.1 ..."
				gatewayIP := strings.Split(defaultRoute, " ")[2]
				if _, err := netip.ParseAddr(gatewayIP); err != nil {
					log.WithError(err).Error("unable to parse gateway IP")
					continue
				}

				for _, nodeCIDR := range option.Config.EncryptionStrictModeNodeCIDRs {

					cmd := exec.CommandContext(context.Background(), "ip", "route", "replace", nodeCIDR.String(), "via", gatewayIP, "advmss", fmt.Sprintf("%d", routeMTU-40))
					if out, err := cmd.CombinedOutput(); err != nil {
						log.WithError(err).WithField("output", string(out)).Error("unable to add route")
						continue
					}
				}
			}

			return
		}
	}()
}

func setupVTEPMapping() error {
	for i, ep := range option.Config.VtepEndpoints {
		log.WithFields(logrus.Fields{
			logfields.IPAddr: ep,
		}).Debug("Updating vtep map entry for VTEP")

		err := vtep.UpdateVTEPMapping(option.Config.VtepCIDRs[i], ep, option.Config.VtepMACs[i])
		if err != nil {
			return fmt.Errorf("Unable to set up VTEP ipcache mappings: %w", err)
		}

	}
	return nil
}

func setupRouteToVtepCidr() error {
	routeCidrs := []*cidr.CIDR{}

	filter := &netlink.Route{
		Table: linux_defaults.RouteTableVtep,
	}

	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}
	for _, rt := range routes {
		rtCIDR, err := cidr.ParseCIDR(rt.Dst.String())
		if err != nil {
			return fmt.Errorf("Invalid VTEP Route CIDR: %w", err)
		}
		routeCidrs = append(routeCidrs, rtCIDR)
	}

	addedVtepRoutes, removedVtepRoutes := cidr.DiffCIDRLists(routeCidrs, option.Config.VtepCIDRs)
	vtepMTU := mtu.EthernetMTU - mtu.TunnelOverhead

	if option.Config.EnableL7Proxy {
		for _, prefix := range addedVtepRoutes {
			ip4 := prefix.IP.To4()
			if ip4 == nil {
				return fmt.Errorf("Invalid VTEP CIDR IPv4 address: %v", ip4)
			}
			r := route.Route{
				Device: defaults.HostDevice,
				Prefix: *prefix.IPNet,
				Scope:  netlink.SCOPE_LINK,
				MTU:    vtepMTU,
				Table:  linux_defaults.RouteTableVtep,
			}
			if err := route.Upsert(r); err != nil {
				return fmt.Errorf("Update VTEP CIDR route error: %w", err)
			}
			log.WithFields(logrus.Fields{
				logfields.IPAddr: r.Prefix.String(),
			}).Info("VTEP route added")

			rule := route.Rule{
				Priority: linux_defaults.RulePriorityVtep,
				To:       prefix.IPNet,
				Table:    linux_defaults.RouteTableVtep,
			}
			if err := route.ReplaceRule(rule); err != nil {
				return fmt.Errorf("Update VTEP CIDR rule error: %w", err)
			}
		}
	} else {
		removedVtepRoutes = routeCidrs
	}

	for _, prefix := range removedVtepRoutes {
		ip4 := prefix.IP.To4()
		if ip4 == nil {
			return fmt.Errorf("Invalid VTEP CIDR IPv4 address: %v", ip4)
		}
		r := route.Route{
			Device: defaults.HostDevice,
			Prefix: *prefix.IPNet,
			Scope:  netlink.SCOPE_LINK,
			MTU:    vtepMTU,
			Table:  linux_defaults.RouteTableVtep,
		}
		if err := route.Delete(r); err != nil {
			return fmt.Errorf("Delete VTEP CIDR route error: %w", err)
		}
		log.WithFields(logrus.Fields{
			logfields.IPAddr: r.Prefix.String(),
		}).Info("VTEP route removed")

		rule := route.Rule{
			Priority: linux_defaults.RulePriorityVtep,
			To:       prefix.IPNet,
			Table:    linux_defaults.RouteTableVtep,
		}
		if err := route.DeleteRule(netlink.FAMILY_V4, rule); err != nil {
			return fmt.Errorf("Delete VTEP CIDR rule error: %w", err)
		}
	}

	return nil
}

// Datapath returns a reference to the datapath implementation.
func (d *Daemon) Datapath() datapath.Datapath {
	return d.datapath
}
