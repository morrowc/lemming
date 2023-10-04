/*
Package lacp is a generated package which contains definitions
of structs which generate gNMI paths for a YANG schema.

This package was generated by ygnmi version: v0.8.7: (ygot: v0.29.11)
using the following YANG input files:
  - gnsi/yang/gnsi-telemetry.yang
  - public/release/models/acl/openconfig-acl.yang
  - public/release/models/acl/openconfig-packet-match.yang
  - public/release/models/aft/openconfig-aft.yang
  - public/release/models/bfd/openconfig-bfd.yang
  - public/release/models/bgp/openconfig-bgp-policy.yang
  - public/release/models/bgp/openconfig-bgp-types.yang
  - public/release/models/interfaces/openconfig-if-aggregate.yang
  - public/release/models/interfaces/openconfig-if-ethernet.yang
  - public/release/models/interfaces/openconfig-if-ip-ext.yang
  - public/release/models/interfaces/openconfig-if-ip.yang
  - public/release/models/interfaces/openconfig-interfaces.yang
  - public/release/models/isis/openconfig-isis.yang
  - public/release/models/lacp/openconfig-lacp.yang
  - public/release/models/lldp/openconfig-lldp-types.yang
  - public/release/models/lldp/openconfig-lldp.yang
  - public/release/models/local-routing/openconfig-local-routing.yang
  - public/release/models/mpls/openconfig-mpls-types.yang
  - public/release/models/multicast/openconfig-pim.yang
  - public/release/models/network-instance/openconfig-network-instance.yang
  - public/release/models/openconfig-extensions.yang
  - public/release/models/optical-transport/openconfig-transport-types.yang
  - public/release/models/ospf/openconfig-ospfv2.yang
  - public/release/models/platform/openconfig-platform-cpu.yang
  - public/release/models/platform/openconfig-platform-integrated-circuit.yang
  - public/release/models/platform/openconfig-platform-software.yang
  - public/release/models/platform/openconfig-platform-transceiver.yang
  - public/release/models/platform/openconfig-platform.yang
  - public/release/models/policy-forwarding/openconfig-policy-forwarding.yang
  - public/release/models/policy/openconfig-policy-types.yang
  - public/release/models/qos/openconfig-qos-elements.yang
  - public/release/models/qos/openconfig-qos-interfaces.yang
  - public/release/models/qos/openconfig-qos-types.yang
  - public/release/models/qos/openconfig-qos.yang
  - public/release/models/rib/openconfig-rib-bgp.yang
  - public/release/models/segment-routing/openconfig-segment-routing-types.yang
  - public/release/models/system/openconfig-system.yang
  - public/release/models/types/openconfig-inet-types.yang
  - public/release/models/types/openconfig-types.yang
  - public/release/models/types/openconfig-yang-types.yang
  - public/release/models/vlan/openconfig-vlan.yang
  - public/third_party/ietf/iana-if-type.yang
  - public/third_party/ietf/ietf-inet-types.yang
  - public/third_party/ietf/ietf-interfaces.yang
  - public/third_party/ietf/ietf-yang-types.yang
  - yang/openconfig-bgp-gue.yang

Imported modules were sourced from:
  - public/release/models/...
  - public/third_party/ietf/...
  - gnsi/...
*/
package lacp

import (
	"reflect"

	oc "github.com/openconfig/lemming/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
)

// Lacp_Interface_Member_SystemIdPath represents the /openconfig-lacp/lacp/interfaces/interface/members/member/state/system-id YANG schema element.
type Lacp_Interface_Member_SystemIdPath struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// Lacp_Interface_Member_SystemIdPathAny represents the wildcard version of the /openconfig-lacp/lacp/interfaces/interface/members/member/state/system-id YANG schema element.
type Lacp_Interface_Member_SystemIdPathAny struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/system-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/system-id"
func (n *Lacp_Interface_Member_SystemIdPath) State() ygnmi.SingletonQuery[string] {
	return ygnmi.NewSingletonQuery[string](
		"Lacp_Interface_Member",
		true,
		true,
		true,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"state", "system-id"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (string, bool) {
			ret := gs.(*oc.Lacp_Interface_Member).SystemId
			if ret == nil {
				var zero string
				return zero, false
			}
			return *ret, true
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		nil,
	)
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/system-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/system-id"
func (n *Lacp_Interface_Member_SystemIdPathAny) State() ygnmi.WildcardQuery[string] {
	return ygnmi.NewWildcardQuery[string](
		"Lacp_Interface_Member",
		true,
		true,
		true,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"state", "system-id"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (string, bool) {
			ret := gs.(*oc.Lacp_Interface_Member).SystemId
			if ret == nil {
				var zero string
				return zero, false
			}
			return *ret, true
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
	)
}

// Lacp_Interface_Member_TimeoutPath represents the /openconfig-lacp/lacp/interfaces/interface/members/member/state/timeout YANG schema element.
type Lacp_Interface_Member_TimeoutPath struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// Lacp_Interface_Member_TimeoutPathAny represents the wildcard version of the /openconfig-lacp/lacp/interfaces/interface/members/member/state/timeout YANG schema element.
type Lacp_Interface_Member_TimeoutPathAny struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/timeout"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/timeout"
func (n *Lacp_Interface_Member_TimeoutPath) State() ygnmi.SingletonQuery[oc.E_Lacp_LacpTimeoutType] {
	return ygnmi.NewSingletonQuery[oc.E_Lacp_LacpTimeoutType](
		"Lacp_Interface_Member",
		true,
		true,
		false,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"state", "timeout"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (oc.E_Lacp_LacpTimeoutType, bool) {
			ret := gs.(*oc.Lacp_Interface_Member).Timeout
			return ret, !reflect.ValueOf(ret).IsZero()
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		nil,
	)
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/timeout"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/timeout"
func (n *Lacp_Interface_Member_TimeoutPathAny) State() ygnmi.WildcardQuery[oc.E_Lacp_LacpTimeoutType] {
	return ygnmi.NewWildcardQuery[oc.E_Lacp_LacpTimeoutType](
		"Lacp_Interface_Member",
		true,
		true,
		false,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"state", "timeout"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (oc.E_Lacp_LacpTimeoutType, bool) {
			ret := gs.(*oc.Lacp_Interface_Member).Timeout
			return ret, !reflect.ValueOf(ret).IsZero()
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
	)
}

// Lacp_Interface_MemberPath represents the /openconfig-lacp/lacp/interfaces/interface/members/member YANG schema element.
type Lacp_Interface_MemberPath struct {
	*ygnmi.NodePath
}

// Lacp_Interface_MemberPathAny represents the wildcard version of the /openconfig-lacp/lacp/interfaces/interface/members/member YANG schema element.
type Lacp_Interface_MemberPathAny struct {
	*ygnmi.NodePath
}

// Lacp_Interface_MemberPathMap represents the /openconfig-lacp/lacp/interfaces/interface/members/member YANG schema element.
type Lacp_Interface_MemberPathMap struct {
	*ygnmi.NodePath
}

// Lacp_Interface_MemberPathMapAny represents the wildcard version of the /openconfig-lacp/lacp/interfaces/interface/members/member YANG schema element.
type Lacp_Interface_MemberPathMapAny struct {
	*ygnmi.NodePath
}

// Activity (leaf): Indicates participant is active or passive
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/activity"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/activity"
func (n *Lacp_Interface_MemberPath) Activity() *Lacp_Interface_Member_ActivityPath {
	ps := &Lacp_Interface_Member_ActivityPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "activity"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Activity (leaf): Indicates participant is active or passive
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/activity"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/activity"
func (n *Lacp_Interface_MemberPathAny) Activity() *Lacp_Interface_Member_ActivityPathAny {
	ps := &Lacp_Interface_Member_ActivityPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "activity"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Aggregatable (leaf): A true value indicates that the participant will allow
// the link to be used as part of the aggregate. A false
// value indicates the link should be used as an individual
// link
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/aggregatable"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/aggregatable"
func (n *Lacp_Interface_MemberPath) Aggregatable() *Lacp_Interface_Member_AggregatablePath {
	ps := &Lacp_Interface_Member_AggregatablePath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "aggregatable"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Aggregatable (leaf): A true value indicates that the participant will allow
// the link to be used as part of the aggregate. A false
// value indicates the link should be used as an individual
// link
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/aggregatable"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/aggregatable"
func (n *Lacp_Interface_MemberPathAny) Aggregatable() *Lacp_Interface_Member_AggregatablePathAny {
	ps := &Lacp_Interface_Member_AggregatablePathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "aggregatable"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Collecting (leaf): If true, the participant is collecting incoming frames
// on the link, otherwise false
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/collecting"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/collecting"
func (n *Lacp_Interface_MemberPath) Collecting() *Lacp_Interface_Member_CollectingPath {
	ps := &Lacp_Interface_Member_CollectingPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "collecting"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Collecting (leaf): If true, the participant is collecting incoming frames
// on the link, otherwise false
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/collecting"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/collecting"
func (n *Lacp_Interface_MemberPathAny) Collecting() *Lacp_Interface_Member_CollectingPathAny {
	ps := &Lacp_Interface_Member_CollectingPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "collecting"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Counters (container): LACP protocol counters
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/counters"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/counters"
func (n *Lacp_Interface_MemberPath) Counters() *Lacp_Interface_Member_CountersPath {
	ps := &Lacp_Interface_Member_CountersPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "counters"},
			map[string]interface{}{},
			n,
		),
	}
	return ps
}

// Counters (container): LACP protocol counters
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/counters"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/counters"
func (n *Lacp_Interface_MemberPathAny) Counters() *Lacp_Interface_Member_CountersPathAny {
	ps := &Lacp_Interface_Member_CountersPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "counters"},
			map[string]interface{}{},
			n,
		),
	}
	return ps
}

// Distributing (leaf): When true, the participant is distributing outgoing
// frames; when false, distribution is disabled
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/distributing"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/distributing"
func (n *Lacp_Interface_MemberPath) Distributing() *Lacp_Interface_Member_DistributingPath {
	ps := &Lacp_Interface_Member_DistributingPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "distributing"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Distributing (leaf): When true, the participant is distributing outgoing
// frames; when false, distribution is disabled
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/distributing"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/distributing"
func (n *Lacp_Interface_MemberPathAny) Distributing() *Lacp_Interface_Member_DistributingPathAny {
	ps := &Lacp_Interface_Member_DistributingPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "distributing"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Interface (leaf): Reference to interface member of the LACP aggregate
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "*/interface"
//	Path from root:       "/lacp/interfaces/interface/members/member/*/interface"
func (n *Lacp_Interface_MemberPath) Interface() *Lacp_Interface_Member_InterfacePath {
	ps := &Lacp_Interface_Member_InterfacePath{
		NodePath: ygnmi.NewNodePath(
			[]string{"*", "interface"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Interface (leaf): Reference to interface member of the LACP aggregate
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "*/interface"
//	Path from root:       "/lacp/interfaces/interface/members/member/*/interface"
func (n *Lacp_Interface_MemberPathAny) Interface() *Lacp_Interface_Member_InterfacePathAny {
	ps := &Lacp_Interface_Member_InterfacePathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"*", "interface"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// LastChange (leaf): The timestamp indicates the absolute time of the last state
// change of a LACP timeout. The last state change of the LACP
// timeout is defined as what is reported as the operating state
// to the system. The state change is both a timeout event and
// when the timeout event is no longer active. The value is the
// timestamp in nanoseconds relative to the Unix Epoch
// (Jan 1, 1970 00:00:00 UTC).
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/last-change"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/last-change"
func (n *Lacp_Interface_MemberPath) LastChange() *Lacp_Interface_Member_LastChangePath {
	ps := &Lacp_Interface_Member_LastChangePath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "last-change"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// LastChange (leaf): The timestamp indicates the absolute time of the last state
// change of a LACP timeout. The last state change of the LACP
// timeout is defined as what is reported as the operating state
// to the system. The state change is both a timeout event and
// when the timeout event is no longer active. The value is the
// timestamp in nanoseconds relative to the Unix Epoch
// (Jan 1, 1970 00:00:00 UTC).
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/last-change"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/last-change"
func (n *Lacp_Interface_MemberPathAny) LastChange() *Lacp_Interface_Member_LastChangePathAny {
	ps := &Lacp_Interface_Member_LastChangePathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "last-change"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// OperKey (leaf): Current operational value of the key for the aggregate
// interface
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/oper-key"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/oper-key"
func (n *Lacp_Interface_MemberPath) OperKey() *Lacp_Interface_Member_OperKeyPath {
	ps := &Lacp_Interface_Member_OperKeyPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "oper-key"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// OperKey (leaf): Current operational value of the key for the aggregate
// interface
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/oper-key"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/oper-key"
func (n *Lacp_Interface_MemberPathAny) OperKey() *Lacp_Interface_Member_OperKeyPathAny {
	ps := &Lacp_Interface_Member_OperKeyPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "oper-key"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerId (leaf): MAC address representing the protocol partner's interface
// system ID
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-id"
func (n *Lacp_Interface_MemberPath) PartnerId() *Lacp_Interface_Member_PartnerIdPath {
	ps := &Lacp_Interface_Member_PartnerIdPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-id"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerId (leaf): MAC address representing the protocol partner's interface
// system ID
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-id"
func (n *Lacp_Interface_MemberPathAny) PartnerId() *Lacp_Interface_Member_PartnerIdPathAny {
	ps := &Lacp_Interface_Member_PartnerIdPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-id"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerKey (leaf): Operational value of the protocol partner's key
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-key"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-key"
func (n *Lacp_Interface_MemberPath) PartnerKey() *Lacp_Interface_Member_PartnerKeyPath {
	ps := &Lacp_Interface_Member_PartnerKeyPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-key"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerKey (leaf): Operational value of the protocol partner's key
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-key"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-key"
func (n *Lacp_Interface_MemberPathAny) PartnerKey() *Lacp_Interface_Member_PartnerKeyPathAny {
	ps := &Lacp_Interface_Member_PartnerKeyPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-key"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerPortNum (leaf): Port number of the partner (remote) port for this member
// port
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-port-num"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-port-num"
func (n *Lacp_Interface_MemberPath) PartnerPortNum() *Lacp_Interface_Member_PartnerPortNumPath {
	ps := &Lacp_Interface_Member_PartnerPortNumPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-port-num"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PartnerPortNum (leaf): Port number of the partner (remote) port for this member
// port
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/partner-port-num"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/partner-port-num"
func (n *Lacp_Interface_MemberPathAny) PartnerPortNum() *Lacp_Interface_Member_PartnerPortNumPathAny {
	ps := &Lacp_Interface_Member_PartnerPortNumPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "partner-port-num"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PortNum (leaf): Port number of the local (actor) aggregation member
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/port-num"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/port-num"
func (n *Lacp_Interface_MemberPath) PortNum() *Lacp_Interface_Member_PortNumPath {
	ps := &Lacp_Interface_Member_PortNumPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "port-num"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// PortNum (leaf): Port number of the local (actor) aggregation member
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/port-num"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/port-num"
func (n *Lacp_Interface_MemberPathAny) PortNum() *Lacp_Interface_Member_PortNumPathAny {
	ps := &Lacp_Interface_Member_PortNumPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "port-num"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Synchronization (leaf): Indicates whether the participant is in-sync or
// out-of-sync
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/synchronization"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/synchronization"
func (n *Lacp_Interface_MemberPath) Synchronization() *Lacp_Interface_Member_SynchronizationPath {
	ps := &Lacp_Interface_Member_SynchronizationPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "synchronization"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Synchronization (leaf): Indicates whether the participant is in-sync or
// out-of-sync
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/synchronization"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/synchronization"
func (n *Lacp_Interface_MemberPathAny) Synchronization() *Lacp_Interface_Member_SynchronizationPathAny {
	ps := &Lacp_Interface_Member_SynchronizationPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "synchronization"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// SystemId (leaf): MAC address that defines the local system ID for the
// aggregate interface
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/system-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/system-id"
func (n *Lacp_Interface_MemberPath) SystemId() *Lacp_Interface_Member_SystemIdPath {
	ps := &Lacp_Interface_Member_SystemIdPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "system-id"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// SystemId (leaf): MAC address that defines the local system ID for the
// aggregate interface
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/system-id"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/system-id"
func (n *Lacp_Interface_MemberPathAny) SystemId() *Lacp_Interface_Member_SystemIdPathAny {
	ps := &Lacp_Interface_Member_SystemIdPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "system-id"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Timeout (leaf): The timeout type (short or long) used by the
// participant
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/timeout"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/timeout"
func (n *Lacp_Interface_MemberPath) Timeout() *Lacp_Interface_Member_TimeoutPath {
	ps := &Lacp_Interface_Member_TimeoutPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "timeout"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// Timeout (leaf): The timeout type (short or long) used by the
// participant
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "state/timeout"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/timeout"
func (n *Lacp_Interface_MemberPathAny) Timeout() *Lacp_Interface_Member_TimeoutPathAny {
	ps := &Lacp_Interface_Member_TimeoutPathAny{
		NodePath: ygnmi.NewNodePath(
			[]string{"state", "timeout"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

// State returns a Query that can be used in gNMI operations.
func (n *Lacp_Interface_MemberPath) State() ygnmi.SingletonQuery[*oc.Lacp_Interface_Member] {
	return ygnmi.NewSingletonQuery[*oc.Lacp_Interface_Member](
		"Lacp_Interface_Member",
		true,
		false,
		false,
		true,
		false,
		n,
		nil,
		nil,
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		nil,
	)
}

// State returns a Query that can be used in gNMI operations.
func (n *Lacp_Interface_MemberPathAny) State() ygnmi.WildcardQuery[*oc.Lacp_Interface_Member] {
	return ygnmi.NewWildcardQuery[*oc.Lacp_Interface_Member](
		"Lacp_Interface_Member",
		true,
		false,
		false,
		true,
		false,
		n,
		nil,
		nil,
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
	)
}

// State returns a Query that can be used in gNMI operations.
func (n *Lacp_Interface_MemberPathMap) State() ygnmi.SingletonQuery[map[string]*oc.Lacp_Interface_Member] {
	return ygnmi.NewSingletonQuery[map[string]*oc.Lacp_Interface_Member](
		"Lacp_Interface",
		true,
		false,
		false,
		true,
		true,
		n,
		func(gs ygot.ValidatedGoStruct) (map[string]*oc.Lacp_Interface_Member, bool) {
			ret := gs.(*oc.Lacp_Interface).Member
			return ret, ret != nil
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		&ygnmi.CompressionInfo{
			PreRelPath:  []string{"openconfig-lacp:members"},
			PostRelPath: []string{"openconfig-lacp:member"},
		},
	)
}

// State returns a Query that can be used in gNMI operations.
func (n *Lacp_Interface_MemberPathMapAny) State() ygnmi.WildcardQuery[map[string]*oc.Lacp_Interface_Member] {
	return ygnmi.NewWildcardQuery[map[string]*oc.Lacp_Interface_Member](
		"Lacp_Interface",
		true,
		false,
		false,
		true,
		true,
		n,
		func(gs ygot.ValidatedGoStruct) (map[string]*oc.Lacp_Interface_Member, bool) {
			ret := gs.(*oc.Lacp_Interface).Member
			return ret, ret != nil
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		&ygnmi.CompressionInfo{
			PreRelPath:  []string{"openconfig-lacp:members"},
			PostRelPath: []string{"openconfig-lacp:member"},
		},
	)
}

// Lacp_Interface_Member_Counters_LacpErrorsPath represents the /openconfig-lacp/lacp/interfaces/interface/members/member/state/counters/lacp-errors YANG schema element.
type Lacp_Interface_Member_Counters_LacpErrorsPath struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// Lacp_Interface_Member_Counters_LacpErrorsPathAny represents the wildcard version of the /openconfig-lacp/lacp/interfaces/interface/members/member/state/counters/lacp-errors YANG schema element.
type Lacp_Interface_Member_Counters_LacpErrorsPathAny struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "lacp-errors"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/counters/lacp-errors"
func (n *Lacp_Interface_Member_Counters_LacpErrorsPath) State() ygnmi.SingletonQuery[uint64] {
	return ygnmi.NewSingletonQuery[uint64](
		"Lacp_Interface_Member_Counters",
		true,
		true,
		true,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"lacp-errors"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (uint64, bool) {
			ret := gs.(*oc.Lacp_Interface_Member_Counters).LacpErrors
			if ret == nil {
				var zero uint64
				return zero, false
			}
			return *ret, true
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member_Counters) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		nil,
	)
}

// State returns a Query that can be used in gNMI operations.
//
//	Defining module:      "openconfig-lacp"
//	Instantiating module: "openconfig-lacp"
//	Path from parent:     "lacp-errors"
//	Path from root:       "/lacp/interfaces/interface/members/member/state/counters/lacp-errors"
func (n *Lacp_Interface_Member_Counters_LacpErrorsPathAny) State() ygnmi.WildcardQuery[uint64] {
	return ygnmi.NewWildcardQuery[uint64](
		"Lacp_Interface_Member_Counters",
		true,
		true,
		true,
		true,
		false,
		ygnmi.NewNodePath(
			[]string{"lacp-errors"},
			nil,
			n.parent,
		),
		func(gs ygot.ValidatedGoStruct) (uint64, bool) {
			ret := gs.(*oc.Lacp_Interface_Member_Counters).LacpErrors
			if ret == nil {
				var zero uint64
				return zero, false
			}
			return *ret, true
		},
		func() ygot.ValidatedGoStruct { return new(oc.Lacp_Interface_Member_Counters) },
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
	)
}