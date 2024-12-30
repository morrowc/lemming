# Lemming gNSI Server Requirements

## Background

The gNSI service for a system must provide at leaast:

* Internal storage of relevant data elements
  exchanged/managed.
  - TLS Artifacts (certificates, keys, trustbundles, CRLs, etc)
  - User data (credentials, keys)
  - Device identity information (keys)
  - Various authorization and authentication data for services
* Public services used to manage these data elements
* Private servics useful to other gRPC services on
  the system to synchronize data elements as necessary.

## Internal Data Storage

Storage of the data elements for each public service should
be provided in a manner which is resilient to system restarts.
The operating gNSI service should update the internal data store
and provide that updated data to the other gRPC services which
are operating on the system, through a set of private RPC services.

## Private Services

All gRPC public services which require updatable security/policy artifacts
may access that data through private services. There should be a single
RPC for each Public service to access, Update(), which will provide
to the appropriate updates upon request, an Update() may provide all
of the artifacts or only the updated set depending on the request detail.

An example of this interaction would be the gNMI service requesting
updates for the gnsi/certz data, once requested updated artifacts
are provided to the gNMI service for use.

## Public Services

The public services are those defined in at least:

* gnsi/acctz
* gnsi/authz
* gnsi/certz
* gnsi/credentialz
* gnsi/pathz

Each of these provides some management RPCs for the data
they manage as well as a Rotate() RPC to install/change
the data they manage. Documentation for these is available
at each endpoint's definition.

These services are necessarily made available by the system
to external (to the system) clients and servers.
